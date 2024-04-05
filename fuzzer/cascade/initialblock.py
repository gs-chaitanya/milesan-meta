# Copyright 2023 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This module defines the initial basic block of the program.

from params.runparams import DO_ASSERT
from rv.csrids import CSR_IDS
from cascade.toleratebugs import is_forbid_vexriscv_csrs
from cascade.cfinstructionclasses import CSRRegInstruction, FloatLoadInstruction
from cascade.cfinstructionclasses_t0 import  ImmRdInstruction_t0, RegImmInstruction_t0, R12DInstruction_t0, IntLoadInstruction_t0
from cascade.randomize.createcfinstr import create_instr
from cascade.randomize.pickisainstrclass import ISAInstrClass
from cascade.util import get_range_bits_per_instrclass, BASIC_BLOCK_MIN_SPACE
from params.fuzzparams import RELOCATOR_REGISTER_ID, RDEP_MASK_REGISTER_ID, FPU_ENDIS_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, MPP_TOP_ENDIS_REGISTER_ID, SPP_ENDIS_REGISTER_ID
from rv.asmutil import li_into_reg
from common.spike import SPIKE_STARTADDR

import random

# The first basic block is responsible for the initial setup
def gen_initial_basic_block(fuzzerstate, offset_addr: int, csr_init_rounding_mode: int = 0):
    if DO_ASSERT:
        assert offset_addr >= 0
        assert offset_addr < 1 << 32
        assert not fuzzerstate.instr_objs_seq
        assert csr_init_rounding_mode >= 0 and csr_init_rounding_mode <= 4

    fuzzerstate.init_new_bb() # Update fuzzer state to support a new basic block

    # Set the relocator register to the correct value

    curr_addr = fuzzerstate.curr_bb_start_addr

    lui_imm, addi_imm = li_into_reg(offset_addr, False)
    fuzzerstate.append_and_execute_instr(ImmRdInstruction_t0(fuzzerstate,"lui", RELOCATOR_REGISTER_ID, lui_imm), True)
    curr_addr += 4
    fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"addi", RELOCATOR_REGISTER_ID, RELOCATOR_REGISTER_ID, addi_imm, fuzzerstate.is_design_64bit), True)
    curr_addr += 4
    if fuzzerstate.is_design_64bit:
        # Clear the top 32 bits
        fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"slli", RELOCATOR_REGISTER_ID, RELOCATOR_REGISTER_ID, 32), True)
        curr_addr += 4
        fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"srli", RELOCATOR_REGISTER_ID, RELOCATOR_REGISTER_ID, 32), True)
        curr_addr += 4
    if DO_ASSERT:
        assert curr_addr == fuzzerstate.curr_bb_start_addr + len(fuzzerstate.instr_objs_seq[-1]) * 4 # NO_COMPRESSED

    if not ("vexriscv" in fuzzerstate.design_name and is_forbid_vexriscv_csrs()):
        # Write 0 to medeleg to uniformize across designs. This must be done in initialblock to facilitate the analysis.
        if fuzzerstate.design_has_supervisor_mode:
            fuzzerstate.append_and_execute_instr(CSRRegInstruction(fuzzerstate,"csrrw", 0, 0, CSR_IDS.MEDELEG))
            curr_addr += 4

        # Write 0 to mtvec and stvec to uniformize across designs. This must be done in initialblock to facilitate the analysis.
        if fuzzerstate.design_name != 'picorv32':
            fuzzerstate.append_and_execute_instr(CSRRegInstruction(fuzzerstate,"csrrw", 0, 0, CSR_IDS.MTVEC))
            curr_addr += 4
        if fuzzerstate.design_has_supervisor_mode:
            fuzzerstate.append_and_execute_instr(CSRRegInstruction(fuzzerstate,"csrrw", 0, 0, CSR_IDS.STVEC))
            curr_addr += 4

    # We authorize all accesses through the PMP registers
    if not ("vexriscv" in fuzzerstate.design_name and is_forbid_vexriscv_csrs()):
        if fuzzerstate.design_has_pmp:
            # pmpcfg0
            fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"addi", 1, 0, 31, fuzzerstate.is_design_64bit), True)
            curr_addr += 4
            fuzzerstate.append_and_execute_instr(CSRRegInstruction(fuzzerstate,"csrrw", 0, 1, CSR_IDS.PMPCFG0))
            curr_addr += 4
            # pmpaddr0
            if fuzzerstate.is_design_64bit:
                fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"addi", 1, 0, 1, fuzzerstate.is_design_64bit), True)
                curr_addr += 4
                fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"slli", 1, 0, 0x36, fuzzerstate.is_design_64bit), True)
                curr_addr += 4
                fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"addi", 1, 1, -1, fuzzerstate.is_design_64bit), True)
                curr_addr += 4
                fuzzerstate.append_and_execute_instr(CSRRegInstruction(fuzzerstate,"csrrw", 0, 1, CSR_IDS.PMPADDR0))          
                curr_addr += 4
            else:
                fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"addi", 1, 0, -1, fuzzerstate.is_design_64bit), True)
                curr_addr += 4
                fuzzerstate.append_and_execute_instr(CSRRegInstruction(fuzzerstate,"csrrw", 0, 1, CSR_IDS.PMPADDR0))
                curr_addr += 4

    # Write random values into the performance monitor CSRs (zeros for now)
    if not ("vexriscv" in fuzzerstate.design_name and is_forbid_vexriscv_csrs()):
        if fuzzerstate.design_name != 'picorv32':
            fuzzerstate.append_and_execute_instr(CSRRegInstruction(fuzzerstate,"csrrw", 0, 0, CSR_IDS.MCYCLE))
            curr_addr += 4
            fuzzerstate.append_and_execute_instr(CSRRegInstruction(fuzzerstate,"csrrw", 0, 0, CSR_IDS.MINSTRET))
            curr_addr += 4
            fuzzerstate.append_and_execute_instr(CSRRegInstruction(fuzzerstate,"csrrw", 0, 0, CSR_IDS.MCAUSE))
            curr_addr += 4
            fuzzerstate.append_and_execute_instr(CSRRegInstruction(fuzzerstate,"csrrw", 0, 0, CSR_IDS.MTVAL))
            curr_addr += 4
            fuzzerstate.append_and_execute_instr(CSRRegInstruction(fuzzerstate,"csrrw", 0, 0, CSR_IDS.MSCRATCH))
            curr_addr += 4
        if fuzzerstate.design_has_supervisor_mode:
            fuzzerstate.append_and_execute_instr(CSRRegInstruction(fuzzerstate,"csrrw", 0, 0, CSR_IDS.SCAUSE))
            curr_addr += 4
            fuzzerstate.append_and_execute_instr(CSRRegInstruction(fuzzerstate,"csrrw", 0, 0, CSR_IDS.STVAL))
            curr_addr += 4
            fuzzerstate.append_and_execute_instr(CSRRegInstruction(fuzzerstate,"csrrw", 0, 0, CSR_IDS.SSCRATCH))
            curr_addr += 4

        if not fuzzerstate.is_design_64bit and fuzzerstate.design_name != 'picorv32':
            fuzzerstate.append_and_execute_instr(CSRRegInstruction(fuzzerstate,"csrrw", 0, 0, CSR_IDS.MCYCLEH))
            curr_addr += 4
            fuzzerstate.append_and_execute_instr(CSRRegInstruction(fuzzerstate,"csrrw", 0, 0, CSR_IDS.MINSTRETH))
            curr_addr += 4

    # Start with enabled FPU, if the FPU exists.
    if fuzzerstate.design_has_fpu:
        # FUTURE Create dependencies on FPU_ENDIS_REGISTER_ID
        # Prepare FPU_ENDIS_REGISTER_ID, which will be used across the program's execution
        fuzzerstate.append_and_execute_instr(ImmRdInstruction_t0(fuzzerstate,"lui", FPU_ENDIS_REGISTER_ID, 0b10, fuzzerstate.is_design_64bit), True)
        curr_addr += 4
        # Enable the FPU
        fuzzerstate.append_and_execute_instr(CSRRegInstruction(fuzzerstate,"csrrw", 0, FPU_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS))
        curr_addr += 4
        # Set the initial rounding mode to zero initially, arbitrarily. We arbitrarily use the register x1 as an intermediate register
        fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"addi", 1, 0, 0, fuzzerstate.is_design_64bit), True)
        curr_addr += 4
        fuzzerstate.append_and_execute_instr(CSRRegInstruction(fuzzerstate,"csrrw", 0, 1, CSR_IDS.FCSR))
        curr_addr += 4

    if fuzzerstate.design_has_supervisor_mode or fuzzerstate.design_has_user_mode:
        fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"srli", MPP_TOP_ENDIS_REGISTER_ID, FPU_ENDIS_REGISTER_ID, 1, fuzzerstate.is_design_64bit), True)
        curr_addr += 4
        fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"srli", MPP_BOTH_ENDIS_REGISTER_ID, FPU_ENDIS_REGISTER_ID, 2, fuzzerstate.is_design_64bit), True)
        curr_addr += 4
        fuzzerstate.append_and_execute_instr(R12DInstruction_t0(fuzzerstate,"or", MPP_BOTH_ENDIS_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, MPP_TOP_ENDIS_REGISTER_ID), True)
        curr_addr += 4
        # Just for the alignment. Could be removed if we improved the alignment prediction. FUTURE.
        fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"addi", 0, 0, 0, fuzzerstate.is_design_64bit), True)
        curr_addr += 4
        # While it is not necesary to set the mpp initially, it is convenient to do so. If we don't, then we should adapt the initial values (typically to None) in privilegestate.py
        fuzzerstate.append_and_execute_instr(CSRRegInstruction(fuzzerstate,"csrrs", 0, MPP_BOTH_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS))
        curr_addr += 4
        fuzzerstate.append_and_execute_instr(CSRRegInstruction(fuzzerstate,"csrrs", 0, MPP_TOP_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS))
        curr_addr += 4

    if not ("vexriscv" in fuzzerstate.design_name and is_forbid_vexriscv_csrs()):
        if fuzzerstate.design_has_user_mode:
            fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"srli", SPP_ENDIS_REGISTER_ID, FPU_ENDIS_REGISTER_ID, 5, fuzzerstate.is_design_64bit), True)
            curr_addr += 4 # NO_COMPRESSED
            # While it is not necesary to set the mpp initially, it is convenient to do so. If we don't, then we should adapt the initial values (typically to None) in privilegestate.py
            fuzzerstate.append_and_execute_instr(CSRRegInstruction(fuzzerstate,"csrrs", 0, SPP_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS))
            curr_addr += 4 # NO_COMPRESSED

    # Set the rdep mask to the correct value

    if fuzzerstate.is_design_64bit:
        fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"addi", RDEP_MASK_REGISTER_ID, 0, -1, fuzzerstate.is_design_64bit), True)
        curr_addr += 4
        fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"slli", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, 32, fuzzerstate.is_design_64bit), True)
        curr_addr += 4
        fuzzerstate.append_and_execute_instr(RegImmInstruction_t0(fuzzerstate,"xori", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, -1, fuzzerstate.is_design_64bit), True)
        curr_addr += 4
        if DO_ASSERT:
            assert curr_addr == fuzzerstate.curr_bb_start_addr + len(fuzzerstate.instr_objs_seq[-1]) * 4 # NO_COMPRESSED

    # Set the pickable registers to random values. We use the last pickable register as an intermediate reg.
    # Relocate for the loads
    fuzzerstate.append_and_execute_instr(R12DInstruction_t0(fuzzerstate,"add", fuzzerstate.num_pickable_regs-1, 0, RELOCATOR_REGISTER_ID), True)
    curr_addr += 4

    if fuzzerstate.design_has_fpu:
        expect_padding = bool((curr_addr + (4*(fuzzerstate.num_pickable_regs+fuzzerstate.num_pickable_floating_regs-1))) & 0x7 == 4) # Says whether there will be a padding required to align the random data
        bytes_until_random_vals = 8 + 4*(fuzzerstate.num_pickable_regs+fuzzerstate.num_pickable_floating_regs-1) + int(expect_padding) * 4 # NO_COMPRESSED
    else:
        expect_padding = bool((curr_addr + (4*(fuzzerstate.num_pickable_regs-1))) & 0x7 == 4) # Says whether there will be a padding required to align the random data
        bytes_until_random_vals = 8 + 4*(fuzzerstate.num_pickable_regs-1) + int(expect_padding) * 4 # NO_COMPRESSED

    bytes_until_random_vals_base_for_debug = curr_addr

    # We pre-allocate the space for the initial block before generating the next bb address.
    num_reginit_vals = fuzzerstate.num_pickable_regs-1
    if fuzzerstate.design_has_fpu:
        num_reginit_vals += fuzzerstate.num_pickable_floating_regs
    for _ in range(num_reginit_vals):
        fuzzerstate.initial_reg_data_content.append(0 if random.random() < fuzzerstate.proba_reg_starts_with_zero else random.randrange(1 << 64))

    # Initial values for pickable registers are determined, so load them s.t. ISA simulation executes on correct initial arch. state.
    fuzzerstate.memview.set_initial_register_values(fuzzerstate, SPIKE_STARTADDR + bytes_until_random_vals_base_for_debug+bytes_until_random_vals)
    fuzzerstate.dump_memview_t0()
    next_instr = RegImmInstruction_t0(fuzzerstate,"addi", fuzzerstate.num_pickable_regs-1, fuzzerstate.num_pickable_regs-1, bytes_until_random_vals + curr_addr, fuzzerstate.is_design_64bit)
    fuzzerstate.append_and_execute_instr(next_instr, True)
    curr_addr += 4
    # Floating loads must be done before int loads, because the last pickable int register will be overwritten.
    if fuzzerstate.design_has_fpu:
        if DO_ASSERT:
            assert fuzzerstate.num_pickable_floating_regs <= fuzzerstate.num_pickable_regs, "For this param choice, we need to adapt slightly the initial block."
        for fp_reg_id in range(fuzzerstate.num_pickable_floating_regs):
            next_instr = FloatLoadInstruction(fuzzerstate,"fld" if fuzzerstate.is_design_64bit else "flw", fp_reg_id, fuzzerstate.num_pickable_regs-1, 8*(fp_reg_id+fuzzerstate.num_pickable_regs-1), -1, fuzzerstate.is_design_64bit)
            fuzzerstate.append_and_execute_instr(next_instr, True)
            curr_addr += 4
    for reg_id in range(1, fuzzerstate.num_pickable_regs):
        next_instr = IntLoadInstruction_t0(fuzzerstate,"ld" if fuzzerstate.is_design_64bit else "lw", reg_id, fuzzerstate.num_pickable_regs-1, 8*(reg_id-1), -1, fuzzerstate.is_design_64bit)
        fuzzerstate.append_and_execute_instr(next_instr, True)
        curr_addr += 4

    if DO_ASSERT:
        assert curr_addr == fuzzerstate.curr_bb_start_addr + len(fuzzerstate.instr_objs_seq[-1]) * 4, f"{curr_addr}, {fuzzerstate.curr_bb_start_addr + len(fuzzerstate.instr_objs_seq[-1]) * 4}" # NO_COMPRESSED

    # If there will be padding between the instructions and data, to ensure proper alignment of doubleword load and store ops for 64-bit CPUs 
    has_padding = bool((curr_addr+4) & 0x7) != 0
    if DO_ASSERT:
        assert expect_padding == has_padding, f"{expect_padding} != {has_padding}"
    # Allocate the initial block before choosing an address for the next bb.
    intended_initial_block_plus_reginit_size = len(fuzzerstate.instr_objs_seq[-1]) * 4 + 4 + len(fuzzerstate.initial_reg_data_content) * 8 + int(has_padding) * 4  # NO_COMPRESSED
    fuzzerstate.memview.alloc_mem_range(fuzzerstate.curr_bb_start_addr, fuzzerstate.curr_bb_start_addr+intended_initial_block_plus_reginit_size+4) # NO_COMPRESSED

    # Jump to the next basic block, say, with jal for simplicity
    range_bits_each_direction = get_range_bits_per_instrclass(ISAInstrClass.JAL)
    fuzzerstate.next_bb_addr = fuzzerstate.memview.gen_random_free_addr(4, BASIC_BLOCK_MIN_SPACE, curr_addr - (1 << range_bits_each_direction), curr_addr + (1 << range_bits_each_direction))
    if fuzzerstate.next_bb_addr is None:
        return False
    
    # JAL at end of initial block is the first to modify the architectural state of the pickable registers, so execute it.
    next_instr = create_instr("jal", fuzzerstate, curr_addr)
    # fuzzerstate.append_and_execute_instr(next_instr) # first instruction that is considered for ISA cascade simulation crosscheck
    fuzzerstate.append_and_execute_instr(next_instr, True)
    curr_addr += 4 # NO_COMPRESSED

    # Add a potential nop to align the ld that load the random vals into the registers
    fuzzerstate.initial_reg_data_addr = curr_addr
    if has_padding:
        fuzzerstate.initial_reg_data_addr += 4
        curr_addr += 4

    fuzzerstate.initial_block_data_start = curr_addr

    if DO_ASSERT:
        assert curr_addr == bytes_until_random_vals_base_for_debug + bytes_until_random_vals, f"curr_addr {hex(curr_addr)}, right-hand {hex(bytes_until_random_vals_base_for_debug + bytes_until_random_vals)} ({hex(bytes_until_random_vals_base_for_debug)} + {hex(bytes_until_random_vals)})"
        # Space taken by the random initial register values. We let some be zero.
    curr_addr += 8 * num_reginit_vals
    fuzzerstate.initial_block_data_end = curr_addr
    if DO_ASSERT:
        assert curr_addr == fuzzerstate.curr_bb_start_addr + intended_initial_block_plus_reginit_size, f"{curr_addr}, {fuzzerstate.curr_bb_start_addr + len(fuzzerstate.instr_objs_seq[-1]) * 4 + 4 + len(fuzzerstate.initial_reg_data_content) * 8 + int(has_padding) * 4}" # NO_COMPRESSED

    return True
