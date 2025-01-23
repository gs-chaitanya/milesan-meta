# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This module defines the initial basic block of the program.

from params.runparams import DO_ASSERT
from rv.csrids import CSR_IDS
from milesan.toleratebugs import is_forbid_vexriscv_csrs, is_tolerate_ras0, is_tolerate_ras1
from milesan.cfinstructionclasses import FloatLoadInstruction
from milesan.cfinstructionclasses_t0 import  ImmRdInstruction_t0, RegImmInstruction_t0, R12DInstruction_t0, IntLoadInstruction_t0, CSRRegInstruction_t0
from milesan.randomize.createcfinstr import create_instr
from milesan.randomize.pickisainstrclass import ISAInstrClass
from milesan.randomize.forbidden_random_value import is_forbidden_random_value
from milesan.util import get_range_bits_per_instrclass, BASIC_BLOCK_MIN_SPACE
from params.fuzzparams import RELOCATOR_REGISTER_ID, RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID_VIRT, FPU_ENDIS_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, MPP_TOP_ENDIS_REGISTER_ID, SPP_ENDIS_REGISTER_ID, REGDUMP_REGISTER_ID, USE_MMU, INIT_MIE
from params.runparams import INSERT_REGDUMPS
from rv.asmutil import li_into_reg
from common.spike import SPIKE_STARTADDR
from common.designcfgs import get_design_reg_stream_addr, get_design_cl_size
from milesan.mmu_utils import PHYSICAL_PAGE_SIZE, PAGE_ALIGNMENT_SHIFT, PAGE_ALIGNMENT_MASK, PAGE_ALIGNMENT_BITS
import numpy as np
import random

# The first basic block is responsible for the initial setup
def gen_initial_basic_block(fuzzerstate, offset_addr: int, csr_init_rounding_mode: int = 0):
    if DO_ASSERT:
        assert offset_addr >= 0
        assert offset_addr < 1 << 32
        # assert not fuzzerstate.instr_objs_seq
        assert csr_init_rounding_mode >= 0 and csr_init_rounding_mode <= 4
    
    # Interleave a cache line inbetween initial basic block and random register values if bug is disabled
    interleave_cl_bytes_until_random_reg_vals = get_design_cl_size(fuzzerstate.design_name) * int(not is_tolerate_ras0(fuzzerstate.design_name))
    # Set the relocator register to the correct value

    curr_addr = fuzzerstate.curr_bb_start_addr

    fuzzerstate.curr_pc = SPIKE_STARTADDR

    # prepare the relocator register
    lui_imm, addi_imm = li_into_reg(offset_addr, False)
    curr_addr += fuzzerstate.append_and_execute_instr(ImmRdInstruction_t0(fuzzerstate,"lui", RELOCATOR_REGISTER_ID, lui_imm, is_rd_nonpickable_ok=True), insert_regdump = False)
    curr_addr += fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"addi", RELOCATOR_REGISTER_ID, RELOCATOR_REGISTER_ID, addi_imm, is_rd_nonpickable_ok=True), insert_regdump = False)
    

    if INSERT_REGDUMPS:
        # prepare the register dump register
        try:
            regdump_addr = get_design_reg_stream_addr(fuzzerstate.design_name)
            assert regdump_addr < 0x80000000, f"For the destination address `{hex(regdump_addr)}`, we will need to manage sign extension, which is not yet implemented here."
        except:
            raise ValueError(f"Design `{fuzzerstate.design_name}` does not have the `regstreamaddr` attribute.")

        lui_imm, addi_imm = li_into_reg(regdump_addr, False)
        curr_addr += fuzzerstate.append_and_execute_instr(ImmRdInstruction_t0(fuzzerstate,"lui", REGDUMP_REGISTER_ID, lui_imm, is_rd_nonpickable_ok=True),insert_regdump = False)

        curr_addr += fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"addi", REGDUMP_REGISTER_ID, REGDUMP_REGISTER_ID, addi_imm, is_rd_nonpickable_ok=True),insert_regdump = False)
        
        if fuzzerstate.design_name == "kronos": # For kronos we need to add the spike offset, for e.g. rocket not.
            curr_addr += fuzzerstate.append_and_execute_instr(R12DInstruction_t0(fuzzerstate,"add", REGDUMP_REGISTER_ID, REGDUMP_REGISTER_ID, RELOCATOR_REGISTER_ID, is_rd_nonpickable_ok=True),insert_regdump = False)

    if fuzzerstate.is_design_64bit:
        # Clear the top 32 bits
        curr_addr += fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"slli", RELOCATOR_REGISTER_ID, RELOCATOR_REGISTER_ID, 32, is_rd_nonpickable_ok=True),insert_regdump = False)
        
        curr_addr += fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"srli", RELOCATOR_REGISTER_ID, RELOCATOR_REGISTER_ID, 32, is_rd_nonpickable_ok=True),insert_regdump = False)
        
    if DO_ASSERT:
        assert curr_addr == fuzzerstate.curr_bb_start_addr + len(fuzzerstate.instr_objs_seq[-1]) * 4 # NO_COMPRESSED

    if not ("vexriscv" in fuzzerstate.design_name and is_forbid_vexriscv_csrs()):
        # Write 0 to medeleg to uniformize across designs. This must be done in initialblock to facilitate the analysis.
        if fuzzerstate.design_has_supervisor_mode:
            curr_addr += fuzzerstate.append_and_execute_instr(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 0, CSR_IDS.MEDELEG), insert_regdump = False)
            

        # Write 0 to mtvec and stvec to uniformize across designs. This must be done in initialblock to facilitate the analysis.
        if fuzzerstate.design_name != 'picorv32':
            curr_addr += fuzzerstate.append_and_execute_instr(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 0, CSR_IDS.MTVEC), insert_regdump = False)
            
        if fuzzerstate.design_has_supervisor_mode:
            curr_addr += fuzzerstate.append_and_execute_instr(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 0, CSR_IDS.STVEC), insert_regdump = False)
            

    # We authorize all accesses through the PMP registers
    if not ("vexriscv" in fuzzerstate.design_name and is_forbid_vexriscv_csrs()):
        if fuzzerstate.design_has_pmp:
            # pmpcfg0
            curr_addr += fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"addi", 1, 0, 31),insert_regdump = False)
            
            curr_addr += fuzzerstate.append_and_execute_instr(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.PMPCFG0), insert_regdump = False)
            
            # pmpaddr0
            if fuzzerstate.is_design_64bit:
                curr_addr += fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"addi", 1, 0, 1),insert_regdump = False)
                
                curr_addr += fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"slli", 1, 0, 0x36),insert_regdump = False)
                
                curr_addr += fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"addi", 1, 1, -1),insert_regdump = False)
                
                curr_addr += fuzzerstate.append_and_execute_instr(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.PMPADDR0), insert_regdump = False)          
                
            else:
                curr_addr += fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"addi", 1, 0, -1),insert_regdump = False)
                
                curr_addr += fuzzerstate.append_and_execute_instr(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.PMPADDR0), insert_regdump = False)
                

    # Write random values into the performance monitor CSRs (zeros for now)
    if not ("vexriscv" in fuzzerstate.design_name and is_forbid_vexriscv_csrs()):
        if fuzzerstate.design_name != 'picorv32':
            curr_addr += fuzzerstate.append_and_execute_instr(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 0, CSR_IDS.MCYCLE), insert_regdump = False)
            
            curr_addr += fuzzerstate.append_and_execute_instr(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 0, CSR_IDS.MINSTRET), insert_regdump = False)
            
            curr_addr += fuzzerstate.append_and_execute_instr(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 0, CSR_IDS.MCAUSE), insert_regdump = False)
            
            curr_addr += fuzzerstate.append_and_execute_instr(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 0, CSR_IDS.MTVAL), insert_regdump = False)
            
            curr_addr += fuzzerstate.append_and_execute_instr(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 0, CSR_IDS.MSCRATCH), insert_regdump = False)
            
        if fuzzerstate.design_has_supervisor_mode:
            curr_addr += fuzzerstate.append_and_execute_instr(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 0, CSR_IDS.SCAUSE), insert_regdump = False)
            
            curr_addr += fuzzerstate.append_and_execute_instr(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 0, CSR_IDS.STVAL), insert_regdump = False)
            
            curr_addr += fuzzerstate.append_and_execute_instr(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 0, CSR_IDS.SSCRATCH), insert_regdump = False)
            

        if not fuzzerstate.is_design_64bit and fuzzerstate.design_name != 'picorv32':
            curr_addr += fuzzerstate.append_and_execute_instr(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 0, CSR_IDS.MCYCLEH), insert_regdump = False)
            
            curr_addr += fuzzerstate.append_and_execute_instr(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 0, CSR_IDS.MINSTRETH), insert_regdump = False)
            
    # Prepare FPU_ENDIS_REGISTER_ID, which will be used across the program's execution, also required to setup MPP
    curr_addr += fuzzerstate.append_and_execute_instr(ImmRdInstruction_t0(fuzzerstate,"lui", FPU_ENDIS_REGISTER_ID, 0b10, is_rd_nonpickable_ok=True),insert_regdump = False)

    # Start with enabled FPU, if the FPU exists.
    if fuzzerstate.design_has_fpu:
        raise NotImplementedError
        # FUTURE Create dependencies on FPU_ENDIS_REGISTER_ID        
        # Enable the FPU
        curr_addr += fuzzerstate.append_and_execute_instr(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, FPU_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS), insert_regdump = False)
        
        # Set the initial rounding mode to zero initially, arbitrarily. We arbitrarily use the register x1 as an intermediate register
        curr_addr += fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"addi", 1, 0, 0),insert_regdump = False)
        
        curr_addr += fuzzerstate.append_and_execute_instr(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.FCSR), insert_regdump = False)
        

    if fuzzerstate.design_has_supervisor_mode or fuzzerstate.design_has_user_mode:
        curr_addr += fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"srli", MPP_TOP_ENDIS_REGISTER_ID, FPU_ENDIS_REGISTER_ID, 1, is_rd_nonpickable_ok=True),insert_regdump = False)
        
        curr_addr += fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"srli", MPP_BOTH_ENDIS_REGISTER_ID, FPU_ENDIS_REGISTER_ID, 2, is_rd_nonpickable_ok=True),insert_regdump = False)
        
        curr_addr += fuzzerstate.append_and_execute_instr(R12DInstruction_t0(fuzzerstate,"or", MPP_BOTH_ENDIS_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, MPP_TOP_ENDIS_REGISTER_ID,is_rd_nonpickable_ok=True),insert_regdump = False)
        
        if INIT_MIE:
            curr_addr += fuzzerstate.append_and_execute_instr(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 0, CSR_IDS.MIE), insert_regdump = False)
        else: # Just for the alignment.
            curr_addr += fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"addi", 0, 0, 0),insert_regdump = False)

        # While it is not necesary to set the mpp initially, it is convenient to do so. If we don't, then we should adapt the initial values (typically to None) in privilegestate.py
        curr_addr += fuzzerstate.append_and_execute_instr(CSRRegInstruction_t0(fuzzerstate,"csrrs", 0, MPP_BOTH_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS), insert_regdump = False)
        
        curr_addr += fuzzerstate.append_and_execute_instr(CSRRegInstruction_t0(fuzzerstate,"csrrs", 0, MPP_TOP_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS), insert_regdump = False)
        

    if not ("vexriscv" in fuzzerstate.design_name and is_forbid_vexriscv_csrs()):
        if fuzzerstate.design_has_user_mode:
            curr_addr += fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"srli", SPP_ENDIS_REGISTER_ID, FPU_ENDIS_REGISTER_ID, 5, is_rd_nonpickable_ok=True),insert_regdump = False)
             # NO_COMPRESSED
            # While it is not necesary to set the mpp initially, it is convenient to do so. If we don't, then we should adapt the initial values (typically to None) in privilegestate.py
            curr_addr += fuzzerstate.append_and_execute_instr(CSRRegInstruction_t0(fuzzerstate,"csrrs", 0, SPP_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS), insert_regdump = False)
             # NO_COMPRESSED

    # Set the rdep mask to the correct value

    if fuzzerstate.is_design_64bit:
        curr_addr += fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"addi", RDEP_MASK_REGISTER_ID, 0, -1, is_rd_nonpickable_ok=True),insert_regdump = False)
        
        curr_addr += fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"slli", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, 32, is_rd_nonpickable_ok=True),insert_regdump = False)
        
        curr_addr += fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"xori", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, -1, is_rd_nonpickable_ok=True),insert_regdump = False)
        
        if DO_ASSERT:
            assert curr_addr == fuzzerstate.curr_bb_start_addr + len(fuzzerstate.instr_objs_seq[-1]) * 4 # NO_COMPRESSED

    # Set the pickable registers to random values. We use the last pickable register as an intermediate reg.
    # Relocate for the loads
    curr_addr += fuzzerstate.append_and_execute_instr(R12DInstruction_t0(fuzzerstate,"add", fuzzerstate.num_pickable_regs-1, 0, RELOCATOR_REGISTER_ID),insert_regdump = False)
    

    if USE_MMU:
        curr_addr += fuzzerstate.append_and_execute_instr(R12DInstruction_t0(fuzzerstate,"sub", RDEP_MASK_REGISTER_ID_VIRT, RDEP_MASK_REGISTER_ID, RELOCATOR_REGISTER_ID, is_rd_nonpickable_ok=True))
        curr_addr += fuzzerstate.append_and_execute_instr(CSRRegInstruction_t0(fuzzerstate, "csrrw", 0, 0, CSR_IDS.SATP)) # init satp to 0


    if fuzzerstate.design_has_fpu:
        expect_padding = bool((curr_addr + (4*(fuzzerstate.num_pickable_regs+fuzzerstate.num_pickable_floating_regs-1))) & 0x7 == 4) # Says whether there will be a padding required to align the random data
        bytes_until_random_vals = 8 + 4*(fuzzerstate.num_pickable_regs+fuzzerstate.num_pickable_floating_regs-1) + int(expect_padding) * 4 # NO_COMPRESSED
    else:
        expect_padding = bool((curr_addr + (4*(fuzzerstate.num_pickable_regs-1))) & 0x7 == 4) # Says whether there will be a padding required to align the random data
        bytes_until_random_vals = 8 + 4*(fuzzerstate.num_pickable_regs-1) + int(expect_padding) * 4 # NO_COMPRESSED


    bytes_until_random_vals += interleave_cl_bytes_until_random_reg_vals # just add extra cl_size bytes to ensure its a different cache line (if RAS bug ignored)

    bytes_until_random_vals_base_for_debug = curr_addr

    # We pre-allocate the space for the initial block before generating the next bb address.
    num_reginit_vals = fuzzerstate.num_pickable_regs-1
    if fuzzerstate.design_has_fpu:
        num_reginit_vals += fuzzerstate.num_pickable_floating_regs
    rng = np.random.RandomState(random.randrange(0,2**31))
    for _ in range(num_reginit_vals):
        rand_val = None
        while rand_val is None or is_forbidden_random_value(rand_val, 8) and not is_tolerate_ras1(fuzzerstate.design_name):
            rand_val = 0 if rng.randint(0,2) < fuzzerstate.proba_reg_starts_with_zero else int(rng.randint(0,2**63,dtype=np.int64))
        fuzzerstate.initial_reg_data_content.append(rand_val)

    # Initial values for pickable registers are determined, so load them s.t. in-situ ISA simulation executes on correct initial arch. state.
    fuzzerstate.memview.set_initial_register_values(fuzzerstate, SPIKE_STARTADDR +  curr_addr + bytes_until_random_vals)

    next_instr = RegImmInstruction_t0(fuzzerstate,"addi", fuzzerstate.num_pickable_regs-1, fuzzerstate.num_pickable_regs-1, bytes_until_random_vals + curr_addr)
    curr_addr += fuzzerstate.append_and_execute_instr(next_instr, insert_regdump = False)

    
    # Floating loads must be done before int loads, because the last pickable int register will be overwritten.
    if fuzzerstate.design_has_fpu:
        if DO_ASSERT:
            assert fuzzerstate.num_pickable_floating_regs <= fuzzerstate.num_pickable_regs, "For this param choice, we need to adapt slightly the initial block."
        for fp_reg_id in range(fuzzerstate.num_pickable_floating_regs):
            next_instr = FloatLoadInstruction(fuzzerstate,"fld" if fuzzerstate.is_design_64bit else "flw", fp_reg_id, fuzzerstate.num_pickable_regs-1, 8*(fp_reg_id+fuzzerstate.num_pickable_regs-1), -1)
            curr_addr += fuzzerstate.append_and_execute_instr(next_instr, insert_regdump = False)
            
    for reg_id in range(1, fuzzerstate.num_pickable_regs):
        next_instr = IntLoadInstruction_t0(fuzzerstate,"ld" if fuzzerstate.is_design_64bit else "lw", reg_id, fuzzerstate.num_pickable_regs-1, 8*(reg_id-1), -1)
        curr_addr += fuzzerstate.append_and_execute_instr(next_instr, insert_regdump = False)
        
    # fuzzerstate.intregpickstate.print()
    if DO_ASSERT:
        assert curr_addr == fuzzerstate.curr_bb_start_addr + len(fuzzerstate.instr_objs_seq[-1]) * 4, f"{curr_addr}, {fuzzerstate.curr_bb_start_addr + len(fuzzerstate.instr_objs_seq[-1]) * 4}" # NO_COMPRESSED

    # If there will be padding between the instructions and data, to ensure proper alignment of doubleword load and store ops for 64-bit CPUs 
    has_padding = bool((curr_addr+4) & 0x7) != 0
    if DO_ASSERT:
        assert expect_padding == has_padding, f"{expect_padding} != {has_padding}"
    # Allocate the initial block before choosing an address for the next bb.
    intended_initial_block_plus_reginit_size = len(fuzzerstate.instr_objs_seq[-1]) * 4 + 4 + len(fuzzerstate.initial_reg_data_content) * 8 + int(has_padding) * 4 + interleave_cl_bytes_until_random_reg_vals # NO_COMPRESSED
    # fuzzerstate.memview.alloc_mem_range(fuzzerstate.curr_bb_start_addr, fuzzerstate.curr_bb_start_addr+intended_initial_block_plus_reginit_size+4) # NO_COMPRESSED
    # fuzzerstate.memview.alloc_mem_range(fuzzerstate.curr_bb_start_addr&PAGE_ALIGNMENT_MASK, (fuzzerstate.curr_bb_start_addr&PAGE_ALIGNMENT_MASK)+PHYSICAL_PAGE_SIZE) # NO_COMPRESSED

    # Jump to the next basic block, say, with jal for simplicity
    # range_bits_each_direction = get_range_bits_per_instrclass(ISAInstrClass.JAL)
    # fuzzerstate.next_bb_addr = fuzzerstate.memview.gen_random_free_addr(4, BASIC_BLOCK_MIN_SPACE, curr_addr - (1 << range_bits_each_direction), curr_addr + (1 << range_bits_each_direction))
    from milesan.basicblock import gen_next_bb_addr
    gen_next_bb_addr(fuzzerstate, ISAInstrClass.JAL,curr_addr)
    if fuzzerstate.next_bb_addr == None:
        return False
    # JAL at end of initial block is the first to modify the architectural state of the pickable registers, so execute it.
    next_instr = create_instr("jal", fuzzerstate, curr_addr)
    # curr_addr += fuzzerstate.append_and_execute_instr(next_instr, insert_regdump = False) # first instruction that is considered for ISA milesan simulation crosscheck
    curr_addr += fuzzerstate.append_and_execute_instr(next_instr, insert_regdump = False)
     # NO_COMPRESSED

    # Add a potential nop to align the ld that load the random vals into the registers
    fuzzerstate.initial_reg_data_addr = curr_addr + interleave_cl_bytes_until_random_reg_vals
    if has_padding:
        fuzzerstate.initial_reg_data_addr += 4
        curr_addr += 4
        

    fuzzerstate.initial_block_data_start = curr_addr
    curr_addr += interleave_cl_bytes_until_random_reg_vals
    if DO_ASSERT:
        assert curr_addr == bytes_until_random_vals_base_for_debug + bytes_until_random_vals, f"curr_addr {hex(curr_addr)}, right-hand {hex(bytes_until_random_vals_base_for_debug + bytes_until_random_vals)} ({hex(bytes_until_random_vals_base_for_debug)} + {hex(bytes_until_random_vals)})"
        # Space taken by the random initial register values. We let some be zero.
    curr_addr += 8 * num_reginit_vals
    fuzzerstate.initial_block_data_end = curr_addr
    if DO_ASSERT:
        assert curr_addr == fuzzerstate.curr_bb_start_addr + intended_initial_block_plus_reginit_size, f"{curr_addr}, {fuzzerstate.curr_bb_start_addr + len(fuzzerstate.instr_objs_seq[-1]) * 4 + 4 + len(fuzzerstate.initial_reg_data_content) * 8 + int(has_padding) * 4}" # NO_COMPRESSED

    return True
