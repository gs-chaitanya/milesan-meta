# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This module is responsible for setting up the context for pruning the basic blocks and Instruction_t0s happening before the faulty Instruction_t0.

from dataclasses import dataclass
from params.runparams import DO_ASSERT
from params.fuzzparams import MAX_NUM_PICKABLE_REGS, USE_MMU, MPP_BOTH_ENDIS_REGISTER_ID, MPP_TOP_ENDIS_REGISTER_ID, RPROD_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID_VIRT, RDEP_MASK_REGISTER_ID, RELOCATOR_REGISTER_ID, TAINT_EN, MAX_NUM_STORE_LOCATIONS
from milesan.toleratebugs import is_tolerate_ras0
from rv.csrids import CSR_IDS
from common.spike import SPIKE_STARTADDR
from milesan.spikeresolution import get_current_layout
from milesan.privilegestate import PrivilegeStateEnum
from milesan.cfinstructionclasses_t0 import ImmRdInstruction_t0, RegImmInstruction_t0, IntLoadInstruction_t0, IntStoreInstruction_t0, CSRRegInstruction_t0, JALInstruction_t0, RawDataWord_t0, PrivilegeDescentInstruction_t0, R12DInstruction_t0
from milesan.randomize.pickstoreaddr import ALIGNMENT_BITS_MAX
from common.designcfgs import get_design_cl_size
from milesan.mmu_utils import phys2virt
from rv.asmutil import li_into_reg, to_unsigned

# @brief This function computes an upper bound on the size of the context setter basic block.
# Do not functools.cache because it is cheap to compute, even though it is not expected to change during a fuzzing run.
def get_context_setter_max_size(fuzzerstate):
    # Static overhead: 20: Upper bound on the number of Instruction_t0s needed to set up the context setter. Includes some margin.
    num_instrs_static = 20
    # Each CSR's overhead: 4: 3 Instruction_t0s to set up fcsr, and 4 bytes (~1 instr) to store its value.
    num_instrs_csrs = 0
    num_instrs_csrs += 4 # fcsr
    num_instrs_csrs += 4 # mepc
    num_instrs_csrs += 4 # sepc
    num_instrs_csrs += 4 # mcause
    num_instrs_csrs += 4 # scause
    num_instrs_csrs += 4 # mscratch
    num_instrs_csrs += 4 # sscratch
    num_instrs_csrs += 4 # mtvec
    num_instrs_csrs += 4 # stvec
    num_instrs_csrs += 4 # medeleg
    num_instrs_csrs += 8 # mstatus  is a bit special and requires more Instructions.
    num_instrs_csrs += 8 # minstret is a bit special and requires more Instructions.
    num_instrs_reset_last_reg = 1 # Reset the register used as an offset (should not be necessary)
    # Privilege restoration overhead
    num_instr_privilege_restoration = 6
    # Memory restoration overhead: 4: 3 Instruction_t0s + 4 bytes (~1 instr) to store the address where the byte will be stored. The number of bytes in a store location is defined as 1 << (ALIGNMENT_BITS_MAX)
    num_instrs_mem = 4 * fuzzerstate.max_num_store_locations * (1 << (ALIGNMENT_BITS_MAX))
    # num_instrs_mem = 4 * MAX_NUM_STORE_LOCATIONS * (1 << (ALIGNMENT_BITS_MAX)) # 4 instructions per store, max 8 bytes per store. Improve this with tigher bound?
    # Floating registers overhead: 4: 3 Instruction_t0s + 4-8 bytes (~1-2 instrs) to store the data + 4 bytes to potentially align.
    if fuzzerstate.design_has_fpu:
        if fuzzerstate.design_has_fpud:
            num_instrs_freg = fuzzerstate.num_pickable_floating_regs*4
        else:
            num_instrs_freg = 1+fuzzerstate.num_pickable_floating_regs*5
    else:
        num_instrs_freg = 0
    # 4: 3 Instructions + 4-8 bytes (~1-2 instrs) to store the data + 4 bytes to potentially align.
    if fuzzerstate.is_design_64bit:
        num_instrs_reg = fuzzerstate.num_pickable_regs*4
    else:
        num_instrs_reg = 1+fuzzerstate.num_pickable_regs*5
    return 4*(num_instrs_static + num_instrs_csrs + num_instr_privilege_restoration + num_instrs_mem + num_instrs_freg + num_instrs_reg + num_instrs_reset_last_reg) + get_design_cl_size(fuzzerstate.design_name)

@dataclass
class SavedContext:
    fcsr: int
    mepc: int
    sepc: int
    mcause: int
    scause: int
    mscratch: int
    sscratch: int
    mtvec: int
    stvec: int
    medeleg: int
    mstatus: int
    minstret: int
    minstreth: int # Only used for 32-bit
    satp: int
    privilege: PrivilegeStateEnum
    mem_bytes_dict: dict # mem_bytes_dict[addr]: value
    mem_bytes_t0_dict: dict # mem_bytes_t0_dict[addr]: value_t0
    freg_vals: list
    freg_vals_t0: list
    reg_vals: list
    reg_vals_t0: list
    saved_rprod_mask: int

# FUTURE Set the proper privilege mode, page tables, CSR values, etc.
# @brief This function generates the context setter basic block.
# @param next_jmp_addr: The address where the context setter will jump to. We do not call it next_bb_addr because it may target not the first Instruction_t0 of a basic block.
def gen_context_setter(fuzzerstate, saved_context, next_jmp_addr: int,tgt_addr_layout: int, tgt_addr_priv: PrivilegeStateEnum):
    # assert not USE_MMU, f"MMU not implemented."
    def addr_to_id_in_ctxsv(addr: int):
        if DO_ASSERT:
            assert addr >= fuzzerstate.ctxsv_bb_base_addr
            assert addr < fuzzerstate.ctxsv_bb_base_addr + get_context_setter_max_size(fuzzerstate)
            assert len(saved_context.mem_bytes_dict) <= fuzzerstate.num_store_locations * (1 << (ALIGNMENT_BITS_MAX)) # Check that we do not have too many writes to memory, Else, we may want to adapt the assumption in get_context_setter_max_size.
        return (addr - fuzzerstate.ctxsv_bb_base_addr) // 4

    addr_csr_loads = {} # addr_csr_loads[csr_id]: addr

    curr_addr = fuzzerstate.ctxsv_bb_base_addr
    assert fuzzerstate.ctxsv_bb_base_addr == fuzzerstate.ctxsv_bb_base_addr

    # Use the register MAX_NUM_PICKABLE_REGS to hold the absolute address of the start of this bb.
    # fuzzerstate.ctxsv_bb.append(ImmRdInstruction_t0(fuzzerstate,'auipc', MAX_NUM_PICKABLE_REGS, 0, is_rd_nonpickable_ok=True))
    # We put an lui+addi sequence here to move address of the first byte after the instructions here.
    fuzzerstate.ctxsv_bb.append(None)
    fuzzerstate.ctxsv_bb.append(None)
    fuzzerstate.ctxsv_bb.append(R12DInstruction_t0(fuzzerstate,"or",MAX_NUM_PICKABLE_REGS,MAX_NUM_PICKABLE_REGS,RELOCATOR_REGISTER_ID, is_rd_nonpickable_ok=True))
    curr_addr += 12 # NO_COMPRESSED

    ###
    # First, set the CSRs to the expected values
    ###

    # fcsr
    if fuzzerstate.design_has_fpu:
        raise NotImplementedError
        # Pre-relocate the address where we pre-store the fcsr value
        # Set the address of the fcsr val
        addr_csr_loads[CSR_IDS.FCSR] = curr_addr
        # fuzzerstate.ctxsv_bb.append(None)
        # Increase the address by 1
        fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, 0, 1, 0, is_rd_nonpickable_ok=True))
        curr_addr += 4 # NO_COMPRESSED
        # Load the fcsr value
        fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lwu" if fuzzerstate.is_design_64bit else "lw", 1, 1, 0, -1))
        curr_addr += 4 # NO_COMPRESSED
        # Write the value into fcsr
        fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.FCSR))
        curr_addr += 4 # NO_COMPRESSED

    # mepc, only if we start in machine mode (else, we will have to overwrite it anyways later)
    if saved_context.privilege == PrivilegeStateEnum.MACHINE and (fuzzerstate.design_has_supervisor_mode or fuzzerstate.design_has_user_mode):
        # satp is a bit special because bits above 31 are typically used as well. We must hence discriminate between 32 and 64 bit designs.
        if USE_MMU:
            addr_csr_loads[CSR_IDS.MEPC] = curr_addr+4
            if fuzzerstate.is_design_64bit:
                fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"ld", 1, MAX_NUM_PICKABLE_REGS, 0, -1))
                fuzzerstate.ctxsv_bb.append(None)
                # fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, 0, is_rd_nonpickable_ok=True))
                fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate, "csrrw", 0, 1, CSR_IDS.MEPC))
                curr_addr += 12 # NO_COMPRESSED
            else:
                raise NotImplementedError
                # Register 1 contains the lsbs and register 2 the msbs.
                # This is a draft implementation that has not been tested yet.
                # fuzzerstate.ctxsv_bb.append(None)
                # fuzzerstate.ctxsv_bb.append(None)
                fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lw", 1, MAX_NUM_PICKABLE_REGS, 0, -1))
                fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 1, 0, is_rd_nonpickable_ok=True))
                fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lw", 2, MAX_NUM_PICKABLE_REGS, 0, -1))
                fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 1, 0, is_rd_nonpickable_ok=True))
                fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.MEPC))
                fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 2, CSR_IDS.MEPC))
                curr_addr += 24 # NO_COMPRESSED
        else:
            addr_csr_loads[CSR_IDS.MEPC] = curr_addr+4
            fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lwu" if fuzzerstate.is_design_64bit else "lw", 1, MAX_NUM_PICKABLE_REGS, 0, -1))
            # fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, 0, is_rd_nonpickable_ok=True))
            fuzzerstate.ctxsv_bb.append(None)
            fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.MEPC))
            curr_addr += 12 # NO_COMPRESSED


    # sepc
    if fuzzerstate.design_has_supervisor_mode:
        # satp is a bit special because bits above 31 are typically used as well. We must hence discriminate between 32 and 64 bit designs.
        if USE_MMU:
            addr_csr_loads[CSR_IDS.SEPC] =  curr_addr+4
            if fuzzerstate.is_design_64bit:
                fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"ld", 1, MAX_NUM_PICKABLE_REGS, 0, -1))
                # fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, 0, is_rd_nonpickable_ok=True))
                fuzzerstate.ctxsv_bb.append(None)
                fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.SEPC))
                curr_addr += 12 # NO_COMPRESSED
            else:
                raise NotImplementedError
                # Register 1 contains the lsbs and register 2 the msbs.
                # This is a draft implementation that has not been tested yet.
                fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lw", 1, MAX_NUM_PICKABLE_REGS, 0, -1))
                fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 1, 0, is_rd_nonpickable_ok=True))
                fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 1, 0, is_rd_nonpickable_ok=True))
                fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lw", 2, MAX_NUM_PICKABLE_REGS, 0, -1))
                fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.SEPC))
                fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 2, CSR_IDS.SEPC))
                curr_addr += 24 # NO_COMPRESSED
        else:
            addr_csr_loads[CSR_IDS.SEPC] =  curr_addr+4
            fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lwu" if fuzzerstate.is_design_64bit else "lw", 1, MAX_NUM_PICKABLE_REGS, 0, -1))
            fuzzerstate.ctxsv_bb.append(None)
            # fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, 0, is_rd_nonpickable_ok=True))
            fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.SEPC))
            curr_addr += 12 # NO_COMPRESSED

    # mcause
    addr_csr_loads[CSR_IDS.MCAUSE] =  curr_addr+4
    fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lwu" if fuzzerstate.is_design_64bit else "lw", 1, MAX_NUM_PICKABLE_REGS, 0, -1))
    fuzzerstate.ctxsv_bb.append(None)
    # fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, 0, is_rd_nonpickable_ok=True))
    fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.MCAUSE))
    curr_addr += 12 # NO_COMPRESSED

    # scause
    if fuzzerstate.design_has_supervisor_mode:
        addr_csr_loads[CSR_IDS.SCAUSE] =  curr_addr+4
        fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lwu" if fuzzerstate.is_design_64bit else "lw", 1, MAX_NUM_PICKABLE_REGS, 0, -1))
        fuzzerstate.ctxsv_bb.append(None)
        # fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, 0, is_rd_nonpickable_ok=True))
        fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.SCAUSE))
        curr_addr += 12 # NO_COMPRESSED

    # mscratch
    addr_csr_loads[CSR_IDS.MSCRATCH] = curr_addr+4
    if fuzzerstate.is_design_64bit:
        fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"ld", 1, MAX_NUM_PICKABLE_REGS, 0, -1))
        # fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, 0, is_rd_nonpickable_ok=True))

    else:
        fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lwu" if fuzzerstate.is_design_64bit else "lw", 1, MAX_NUM_PICKABLE_REGS, 0, -1))
        # fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, 0, is_rd_nonpickable_ok=True))
    
    fuzzerstate.ctxsv_bb.append(None)
    curr_addr += 8 # NO_COMPRESSED

    fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.MSCRATCH))
    curr_addr += 4 # NO_COMPRESSED

    if fuzzerstate.design_has_supervisor_mode:
        addr_csr_loads[CSR_IDS.SSCRATCH] =  curr_addr+4
        if fuzzerstate.is_design_64bit:
            fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"ld", 1, MAX_NUM_PICKABLE_REGS, 0, -1))
            # fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, 0, is_rd_nonpickable_ok=True))
        else:
            fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lwu" if fuzzerstate.is_design_64bit else "lw", 1, MAX_NUM_PICKABLE_REGS, 0, -1))
            # fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, 0, is_rd_nonpickable_ok=True))
        fuzzerstate.ctxsv_bb.append(None)
        fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.SSCRATCH))
        curr_addr += 12 # NO_COMPRESSED

    # mtveccurr_addr-fuzzerstate.ctxsv_bb_base_addr
    # if fuzzerstate.design_has_supervisor_mode:
    if 'picorv32' not in fuzzerstate.design_name:
        # satp is a bit special because bits above 31 are typically used as well. We must hence discriminate between 32 and 64 bit designs.
        if USE_MMU:
            addr_csr_loads[CSR_IDS.MTVEC] =  curr_addr+4
            if fuzzerstate.is_design_64bit:
                fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"ld", 1, MAX_NUM_PICKABLE_REGS, 0, -1))
                fuzzerstate.ctxsv_bb.append(None)
                # fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, 0, is_rd_nonpickable_ok=True))
                fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.MTVEC))
                curr_addr += 12 # NO_COMPRESSED
            else:
                raise NotImplementedError
                # Register 1 contains the lsbs and register 2 the msbs.
                # This is a draft implementation that has not been tested yet.
                # fuzzerstate.ctxsv_bb.append(None)
                # fuzzerstate.ctxsv_bb.append(None)
                fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lw", 1, MAX_NUM_PICKABLE_REGS, 0, -1))
                fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 4, 0, is_rd_nonpickable_ok=True))
                fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lw", 2, MAX_NUM_PICKABLE_REGS, 0, -1))
                fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 4, 0, is_rd_nonpickable_ok=True))
                fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.MTVEC))
                fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 2, CSR_IDS.MTVEC))
                curr_addr += 24 # NO_COMPRESSED
        else:
            addr_csr_loads[CSR_IDS.MTVEC] =  curr_addr+4
            fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lwu" if fuzzerstate.is_design_64bit else "lw", 1, MAX_NUM_PICKABLE_REGS, 0, -1))
            fuzzerstate.ctxsv_bb.append(None)
            # fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, 0, is_rd_nonpickable_ok=True))
            fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.MTVEC))
            curr_addr += 12 # NO_COMPRESSED

    # stvec
    if fuzzerstate.design_has_supervisor_mode:
        # satp is a bit special because bits above 31 are typically used as well. We must hence discriminate between 32 and 64 bit designs.
        if USE_MMU:
            addr_csr_loads[CSR_IDS.STVEC] =  curr_addr+4
            if fuzzerstate.is_design_64bit:
                fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"ld", 1, MAX_NUM_PICKABLE_REGS, 0, -1))
                fuzzerstate.ctxsv_bb.append(None)
                # fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, 0, is_rd_nonpickable_ok=True))
                fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.STVEC))
                curr_addr += 12 # NO_COMPRESSED
            else:
                raise NotImplementedError
                # Register 1 contains the lsbs and register 2 the msbs.
                # This is a draft implementation that has not been tested yet.
                # fuzzerstate.ctxsv_bb.append(None)
                # fuzzerstate.ctxsv_bb.append(None)
                fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lw", 1, MAX_NUM_PICKABLE_REGS, 0, -1))
                fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 4, 0, is_rd_nonpickable_ok=True))
                fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lw", 2, MAX_NUM_PICKABLE_REGS, 0, -1))
                fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 4, 0, is_rd_nonpickable_ok=True))
                fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.STVEC))
                fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 2, CSR_IDS.STVEC))
                curr_addr += 24 # NO_COMPRESSED
        else:
            addr_csr_loads[CSR_IDS.STVEC] =  curr_addr+4
            fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lwu" if fuzzerstate.is_design_64bit else "lw", 1, MAX_NUM_PICKABLE_REGS, 0, -1))
            fuzzerstate.ctxsv_bb.append(None)
            # fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, 0, is_rd_nonpickable_ok=True))
            fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.STVEC))
            curr_addr += 12 # NO_COMPRESSED

    # medeleg
    if fuzzerstate.design_has_supervisor_mode:
        addr_csr_loads[CSR_IDS.MEDELEG] = curr_addr+4
        fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lwu" if fuzzerstate.is_design_64bit else "lw", 1, MAX_NUM_PICKABLE_REGS, 0, -1))
        fuzzerstate.ctxsv_bb.append(None)
        # fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, 0, is_rd_nonpickable_ok=True))
        fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.MEDELEG))
        curr_addr += 12 # NO_COMPRESSED

    # mstatus is a bit special because bits above 31 are typically used as well. We must hence discriminate between 32 and 64 bit designs.
    addr_csr_loads[CSR_IDS.MSTATUS] =  curr_addr+4
    if fuzzerstate.is_design_64bit:
        fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"ld", 1, MAX_NUM_PICKABLE_REGS, 0, -1))
        fuzzerstate.ctxsv_bb.append(None)
        # fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, 0, is_rd_nonpickable_ok=True))
        fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.MSTATUS))
        curr_addr += 12 # NO_COMPRESSED
    else:
        raise NotImplementedError
        # Register 1 contains the lsbs and register 2 the msbs.
        # This is a draft implementation that has not been tested yet.
        # fuzzerstate.ctxsv_bb.append(None)
        # fuzzerstate.ctxsv_bb.append(None)
        fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lw", 1, MAX_NUM_PICKABLE_REGS, 0, -1))
        fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 4, 0, is_rd_nonpickable_ok=True))
        fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lw", 2, MAX_NUM_PICKABLE_REGS, 0, -1))
        fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 4, 0, is_rd_nonpickable_ok=True))
        fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.MSTATUS))
        fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 2, CSR_IDS.MSTATUSH))
        curr_addr += 24 # NO_COMPRESSED

    # satp is a bit special because bits above 31 are typically used as well. We must hence discriminate between 32 and 64 bit designs.
    if USE_MMU:
        addr_csr_loads[CSR_IDS.SATP] =  curr_addr+4
        if fuzzerstate.is_design_64bit:
            fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"ld", 1, MAX_NUM_PICKABLE_REGS, 0, -1))
            fuzzerstate.ctxsv_bb.append(None)
            # fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, 0, is_rd_nonpickable_ok=True))
            fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.SATP))
            curr_addr += 12 # NO_COMPRESSED
        else:
            raise NotImplementedError
            # Register 1 contains the lsbs and register 2 the msbs.
            # This is a draft implementation that has not been tested yet.
            # fuzzerstate.ctxsv_bb.append(None)
            # fuzzerstate.ctxsv_bb.append(None)
            fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lw", 1, MAX_NUM_PICKABLE_REGS, 0, -1))
            fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 4, 0, is_rd_nonpickable_ok=True))
            fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lw", 2, MAX_NUM_PICKABLE_REGS, 0, -1))
            fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 4, 0, is_rd_nonpickable_ok=True))
            fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.SATP))
            fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 2, CSR_IDS.SATP))
            curr_addr += 24 # NO_COMPRESSED

    # minstret is a bit special because bits above 31 are typically used as well. We must hence discriminate between 32 and 64 bit designs.
    addr_csr_loads[CSR_IDS.MINSTRET] =  curr_addr+4
    if fuzzerstate.is_design_64bit:
        fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"ld", 1, MAX_NUM_PICKABLE_REGS, 0, -1))
        fuzzerstate.ctxsv_bb.append(None)
        # fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, 0, is_rd_nonpickable_ok=True))
        fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.MINSTRET))
        curr_addr += 12 # NO_COMPRESSED
    else:
        # Register 1 contains the lsbs and register 2 the msbs.
        raise NotImplementedError
        fuzzerstate.ctxsv_bb.append(None)
        fuzzerstate.ctxsv_bb.append(None)
        fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lw", 1, MAX_NUM_PICKABLE_REGS, 0, -1))
        fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 4, 0, is_rd_nonpickable_ok=True))
        fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lw", 2, MAX_NUM_PICKABLE_REGS, 0, -1))
        fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 4, 0, is_rd_nonpickable_ok=True))
        fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 1, CSR_IDS.MINSTRET))
        fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, 2, CSR_IDS.MINSTRETH))
        curr_addr += 24 # NO_COMPRESSED
    minstret_base_addr = curr_addr


    ##
    # Additionally, we set the RPROD mask if we use the MMU
    ##
    if USE_MMU:
        # RPROD_MASK_REGISTER_ID is a bit special because bits above 31 are typically used as well. We must hence discriminate between 32 and 64 bit designs.
        rprod_load = curr_addr+4
        if fuzzerstate.is_design_64bit:
            fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"ld", RPROD_MASK_REGISTER_ID, MAX_NUM_PICKABLE_REGS, 0, -1, is_rd_nonpickable_ok=True))
            fuzzerstate.ctxsv_bb.append(None)
            # fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, 0, is_rd_nonpickable_ok=True))
            fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", 0, 0, 0, is_rd_nonpickable_ok=True)) # might need a nop for allignment, might not, TODO
            curr_addr += 12 # NO_COMPRESSED
        else:
            # Register 1 contains the lsbs and register 2 the msbs.
            # This is a draft implementation that has not been tested yet.
            fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lw", RPROD_MASK_REGISTER_ID, MAX_NUM_PICKABLE_REGS, 0, -1, is_rd_nonpickable_ok=True))
            fuzzerstate.ctxsv_bb.append(None)
            # fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 4, 0, is_rd_nonpickable_ok=True))
            fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lw", 2, MAX_NUM_PICKABLE_REGS, 0, -1))
            fuzzerstate.ctxsv_bb.append(None)
            # fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 4, 0, is_rd_nonpickable_ok=True))
            fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"slli", 2, 2, 32))
            fuzzerstate.ctxsv_bb.append(R12DInstruction_t0(fuzzerstate,"or", RPROD_MASK_REGISTER_ID, RPROD_MASK_REGISTER_ID, 2, is_rd_nonpickable_ok=True))
            curr_addr += 24 # NO_COMPRESSED


    # Instead of writing from the ctx saver, we could also modify the ELF. However, we have better chances of 
    # replicating the microarch. state if we perform the writes to memory like the program we are reducing.
    addrs_memaddrs = []
    for mem_byte_id, (mem_byte_addr, mem_byte_val) in enumerate(saved_context.mem_bytes_dict.items()):
        if DO_ASSERT:
            assert mem_byte_val >= 0
            assert mem_byte_val < 256
            assert mem_byte_addr >= 0
            assert mem_byte_addr < fuzzerstate.memsize
        # Arbitrarily use register 1 to load the byte addr
        addrs_memaddrs.append(curr_addr+4)
        # fuzzerstate.ctxsv_bb.append(None) # will be replaced later on when addresses are written.
        # We load the byte addr into register 1
        fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lwu" if fuzzerstate.is_design_64bit else "lw", 1, MAX_NUM_PICKABLE_REGS, 0, -1, is_rd_nonpickable_ok=True))
        fuzzerstate.ctxsv_bb.append(None)
        # curr_addr += 4 # NO_COMPRESSED
        # fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 4, 0, is_rd_nonpickable_ok=True))
        curr_addr += 8 # NO_COMPRESSED

        # We set the byte value using an immediate

        if TAINT_EN:
            assert mem_byte_addr in saved_context.mem_bytes_t0_dict, f"No taint entry found for addr {hex(mem_byte_addr)}"
            mem_byte_val_t0 = saved_context.mem_bytes_t0_dict[mem_byte_addr]
            inst = RegImmInstruction_t0(fuzzerstate,"addi", 2, 0, mem_byte_val, mem_byte_val_t0, is_rd_nonpickable_ok=True)
        else:
            inst = RegImmInstruction_t0(fuzzerstate,"addi", 2, 0, mem_byte_val, is_rd_nonpickable_ok=True)
            
        fuzzerstate.ctxsv_bb.append(inst)

        curr_addr += 4 # NO_COMPRESSED
        # Store the value into memory
        fuzzerstate.ctxsv_bb.append(IntStoreInstruction_t0(fuzzerstate,"sb", 1, 2, 0, -1)) # sb dest, val, offset
        curr_addr += 4 # NO_COMPRESSED


    addr_reg_load_addi = curr_addr
    fuzzerstate.ctxsv_bb.append(None)
    curr_addr += 4 # NO_COMPRESSED
    for reg_id, reg_val in enumerate(saved_context.reg_vals):
        if DO_ASSERT:
            if TAINT_EN:
                assert reg_id < len(saved_context.reg_vals_t0)
                reg_val_t0 = saved_context.reg_vals_t0[reg_id]
                assert  reg_val_t0 >= 0
                assert reg_val_t0 < 1 << 64 if fuzzerstate.is_design_64bit else 1 << 32
            assert reg_val >= 0
            assert reg_val < 1 << 64 if fuzzerstate.is_design_64bit else 1 << 32
        # Set the address of the reg val
        if fuzzerstate.is_design_64bit:
            fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"ld", reg_id, MAX_NUM_PICKABLE_REGS, 8*reg_id, -1, is_rd_nonpickable_ok=True))
            curr_addr += 4 # NO_COMPRESSED
        else:
            fuzzerstate.ctxsv_bb.append(IntLoadInstruction_t0(fuzzerstate,"lw", reg_id, MAX_NUM_PICKABLE_REGS, 4*reg_id, -1, is_rd_nonpickable_ok=True))
            curr_addr += 4 # NO_COMPRESSED

    # fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, (4+4*int(fuzzerstate.is_design_64bit))*len(saved_context.reg_vals), 0, is_rd_nonpickable_ok=True))
    # fuzzerstate.ctxsv_bb.append(None)
    # curr_addr += 4 # NO_COMPRESSED


    if USE_MMU:
        # Fifth, set the sum and mprv bits in mstatus if needed
        ##
        lui_imm, addi_imm = li_into_reg(saved_context.mstatus & 0x60000, False)
        fuzzerstate.ctxsv_bb.append(ImmRdInstruction_t0(fuzzerstate,"lui", RDEP_MASK_REGISTER_ID_VIRT, lui_imm, is_rd_nonpickable_ok=True))
        fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", RDEP_MASK_REGISTER_ID_VIRT, RDEP_MASK_REGISTER_ID_VIRT, addi_imm, is_rd_nonpickable_ok=True))
        fuzzerstate.ctxsv_bb.append(R12DInstruction_t0(fuzzerstate,"and", RDEP_MASK_REGISTER_ID_VIRT, RDEP_MASK_REGISTER_ID_VIRT, RPROD_MASK_REGISTER_ID, is_rd_nonpickable_ok=True))
        fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrs", 0, RDEP_MASK_REGISTER_ID_VIRT, CSR_IDS.MSTATUS))
        curr_addr += 16



    ###
    # Finally, set the correct privilege level, if the saved context specifies something else than machine mode (at the end, to avoid having to deal with virtual memory fot the loads)
    ###
    if USE_MMU:
        if saved_context.privilege == PrivilegeStateEnum.SUPERVISOR or saved_context.privilege == PrivilegeStateEnum.USER:
            # Populate mpp
            if saved_context.privilege == PrivilegeStateEnum.SUPERVISOR:
                fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrs", 0, MPP_BOTH_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS))
                fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrc", 0, MPP_TOP_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS))
            else:
                fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrc", 0, MPP_BOTH_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS))
                fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", 0, 0, 0, is_rd_nonpickable_ok=True))
            curr_addr += 8 # NO_COMPRESSED
            # Populate mepc
            if tgt_addr_layout == -1:
                mepc_target = curr_addr + 12
                fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", RDEP_MASK_REGISTER_ID_VIRT, MAX_NUM_PICKABLE_REGS, mepc_target, is_rd_nonpickable_ok=True)) # The reg `MAX_NUM_PICKABLE_REGS` contains the start address of the context sette, is_rd_nonpickable_ok=Truer
                fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, RDEP_MASK_REGISTER_ID_VIRT, CSR_IDS.MEPC))
            else:
                mepc_target = curr_addr + 20
                mepc_target_virt = phys2virt(((mepc_target)+SPIKE_STARTADDR), tgt_addr_priv, tgt_addr_layout, fuzzerstate)
                lui_imm, addi_imm = li_into_reg((mepc_target_virt | 0x80000000) & 0xffffffff, False)
                fuzzerstate.ctxsv_bb.append(ImmRdInstruction_t0(fuzzerstate,"lui", RDEP_MASK_REGISTER_ID_VIRT, lui_imm, is_rd_nonpickable_ok=True))
                fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", RDEP_MASK_REGISTER_ID_VIRT, RDEP_MASK_REGISTER_ID_VIRT, addi_imm, is_rd_nonpickable_ok=True))
                fuzzerstate.ctxsv_bb.append(R12DInstruction_t0(fuzzerstate,"and", RDEP_MASK_REGISTER_ID_VIRT, RDEP_MASK_REGISTER_ID_VIRT, RPROD_MASK_REGISTER_ID, is_rd_nonpickable_ok=True))
                fuzzerstate.ctxsv_bb.append(CSRRegInstruction_t0(fuzzerstate,"csrrw", 0, RDEP_MASK_REGISTER_ID_VIRT, CSR_IDS.MEPC))
            mret = PrivilegeDescentInstruction_t0(fuzzerstate,True)
            mret.priv_level_after_op = tgt_addr_priv
            mret.va_layout_after_op = tgt_addr_layout
            # print(f"MEPC TARGET: phys: {hex(mepc_target)}, virt: {hex(mepc_target_virt)}")
            fuzzerstate.ctxsv_bb.append(mret) # mret
            # Add 2 nops for the mret, just in case the CPU is not doing great with mret sometimes :)
            fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", 0, 0, 0, is_rd_nonpickable_ok=True))
            curr_addr = (mepc_target+4) # NO_COMPRESSED

        # Reset the reg MAX_NUM_PICKABLE_REGS to 0 and RDEP_MASK_REGISTER_ID_VIRT
        fuzzerstate.ctxsv_bb.append(RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, 0, 0, is_rd_nonpickable_ok=True))
        curr_addr += 4 # NO_COMPRESSED
        fuzzerstate.ctxsv_bb.append(R12DInstruction_t0(fuzzerstate,"sub", RDEP_MASK_REGISTER_ID_VIRT, RDEP_MASK_REGISTER_ID, RELOCATOR_REGISTER_ID, is_rd_nonpickable_ok=True))
        curr_addr += 4 # NO_COMPRESSED

    # Jump to the next bb
    if DO_ASSERT:
        assert abs(next_jmp_addr - curr_addr) < 1 << 20 # Ensure that the jump is not too far for a jal
    fuzzerstate.ctxsv_bb.append(JALInstruction_t0(fuzzerstate,"jal", 0, next_jmp_addr - curr_addr))
    # print(f"Last context setter instruction: {fuzzerstate.ctxsv_bb[-1].get_str()}")
    fuzzerstate.ctxsv_bb_jal_instr_id = len(fuzzerstate.ctxsv_bb)-1
    curr_addr += 4 # NO_COMPRESSED
    instr_end_addr = curr_addr


    ###
    # Some padding before the actual values
    ###

    # Leave an extra CL space between the instructions and possibly tainted data to avoid prefetching tainted data. We also do this when the bug is disabled
    # since we don't want this possible interference when reducing the program as the bug could be mistakenly attributed to it.
    for _ in range(get_design_cl_size(fuzzerstate.design_name)//4): # Each word has 4 bytes.
        fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,0xdeadbeef))
        curr_addr += 4

    # For CSRs, we must ensure that the address is aligned to 8 bytes
    while curr_addr % 8 != 0:
        fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,0xdeadbeef))
        curr_addr += 4

    if DO_ASSERT:
        assert curr_addr == fuzzerstate.ctxsv_bb_base_addr + len(fuzzerstate.ctxsv_bb)*4, f"curr_addr is `{hex(curr_addr)}`, fuzzerstate.ctxsv_bb_base_addr + len(fuzzerstate.ctxsv_bb)*4 is `{hex(fuzzerstate.ctxsv_bb_base_addr + len(fuzzerstate.ctxsv_bb)*4)}`" # NO_COMPRESSED

    ###
    # The actual values will be set here
    ###

    assert fuzzerstate.ctxsv_bb[0] == None
    assert fuzzerstate.ctxsv_bb[1] == None
    data_start_addr = curr_addr
    lui_imm, addi_imm = li_into_reg(to_unsigned(curr_addr, fuzzerstate.is_design_64bit))
    fuzzerstate.ctxsv_bb[0] = ImmRdInstruction_t0(fuzzerstate, "lui", MAX_NUM_PICKABLE_REGS,lui_imm,is_rd_nonpickable_ok=True)
    fuzzerstate.ctxsv_bb[1] = RegImmInstruction_t0(fuzzerstate, "addi",MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, addi_imm, is_rd_nonpickable_ok=True)
    # Set the CSR values here. Use the register 1 to load the value, arbitrarily.
    if fuzzerstate.design_has_fpu:
        raise NotImplementedError
        # fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_csr_loads[CSR_IDS.FCSR])] = RegImmInstruction_t0(fuzzerstate,"addi", 1, MAX_NUM_PICKABLE_REGS, curr_addr-fuzzerstate.ctxsv_bb_base_addr, is_rd_nonpickable_ok=True)
        fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,saved_context.fcsr))
        fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,0xdeadbeef))
        curr_addr += 8 # NO_COMPRESSED

    if saved_context.privilege == PrivilegeStateEnum.MACHINE and (fuzzerstate.design_has_supervisor_mode or fuzzerstate.design_has_user_mode):
        # satp is a bit special because bits above 31 are typically used as well. We must hence discriminate between 32 and 64 bit designs.
        if USE_MMU:
            if DO_ASSERT:
                assert saved_context.mepc >> 64 == 0, "mepc is unexpectedly too large."
            # Little endian. For a number written big endian `abcd`, the bytes should be written in memory as `dcba`. So we write the lsbs first.
            if not fuzzerstate.is_design_64bit:
                raise NotImplementedError
                # Prepare register 2 to be written to the msb of mepc
                fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_csr_loads[CSR_IDS.MEPC])+1] = RegImmInstruction_t0(fuzzerstate,"addi", 2, MAX_NUM_PICKABLE_REGS, curr_addr-fuzzerstate.ctxsv_bb_base_addr+4, is_rd_nonpickable_ok=True)
            fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,saved_context.mepc & 0xffffffff))
            fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,saved_context.mepc >> 32))
            fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_csr_loads[CSR_IDS.MEPC])] = RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, is_rd_nonpickable_ok=True)
            curr_addr += 8 # NO_COMPRESSED
        else:
            fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,saved_context.mepc))
            fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,0xdeadbeef))
            fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_csr_loads[CSR_IDS.MEPC])] = RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, is_rd_nonpickable_ok=True)
            curr_addr += 8 # NO_COMPRESSED

    if fuzzerstate.design_has_supervisor_mode:
        # satp is a bit special because bits above 31 are typically used as well. We must hence discriminate between 32 and 64 bit designs.
        if USE_MMU:
            if DO_ASSERT:
                assert saved_context.sepc >> 64 == 0, "sepc is unexpectedly too large."
            # Little endian. For a number written big endian `abcd`, the bytes should be written in memory as `dcba`. So we write the lsbs first.
            if not fuzzerstate.is_design_64bit:
                raise NotImplementedError
                # Prepare register 2 to be written to the msb of sepc
                # fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_csr_loads[CSR_IDS.SEPC])+1] = RegImmInstruction_t0(fuzzerstate,"addi", 2, MAX_NUM_PICKABLE_REGS, curr_addr-fuzzerstate.ctxsv_bb_base_addr+4, is_rd_nonpickable_ok=True)
            fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,saved_context.sepc & 0xffffffff))
            fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,saved_context.sepc >> 32))
            fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_csr_loads[CSR_IDS.SEPC])] = RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, is_rd_nonpickable_ok=True)
            curr_addr += 8 # NO_COMPRESSED
        else:
            fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,saved_context.sepc))
            fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,0xdeadbeef))
            fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_csr_loads[CSR_IDS.SEPC])] = RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, is_rd_nonpickable_ok=True)
            curr_addr += 8 # NO_COMPRESSED

    # mcause
    fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,saved_context.mcause))
    fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,0xdeadbeef))
    fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_csr_loads[CSR_IDS.MCAUSE])] = RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, is_rd_nonpickable_ok=True)
    curr_addr += 8 # NO_COMPRESSED

    #scause
    if fuzzerstate.design_has_supervisor_mode:
        fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,saved_context.scause))
        fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,0xdeadbeef))
        fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_csr_loads[CSR_IDS.SCAUSE])] = RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, is_rd_nonpickable_ok=True)
        curr_addr += 8 # NO_COMPRESSED

    # mscratch
    fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,saved_context.mscratch & 0xffffffff))
    fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,saved_context.mscratch >> 32))
    fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_csr_loads[CSR_IDS.MSCRATCH])] = RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, is_rd_nonpickable_ok=True)
    curr_addr += 8 # NO_COMPRESSED

    if fuzzerstate.design_has_supervisor_mode:
        fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,saved_context.sscratch & 0xffffffff))
        fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,saved_context.sscratch >> 32))
        fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_csr_loads[CSR_IDS.SSCRATCH])] = RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, is_rd_nonpickable_ok=True)
        curr_addr += 8 # NO_COMPRESSED

    if 'picorv32' not in fuzzerstate.design_name:
        # satp is a bit special because bits above 31 are typically used as well. We must hence discriminate between 32 and 64 bit designs.
        if USE_MMU:
            if DO_ASSERT:
                assert saved_context.mtvec >> 64 == 0, "mtvec is unexpectedly too large."
            # Little endian. For a number written big endian `abcd`, the bytes should be written in memory as `dcba`. So we write the lsbs first.
            if not fuzzerstate.is_design_64bit:
                raise NotImplementedError
                # Prepare register 2 to be written to the msb of mtvec
                # fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_csr_loads[CSR_IDS.MTVEC])+1] = RegImmInstruction_t0(fuzzerstate,"addi", 2, MAX_NUM_PICKABLE_REGS, curr_addr-fuzzerstate.ctxsv_bb_base_addr+4, is_rd_nonpickable_ok=True)
            fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,saved_context.mtvec & 0xffffffff))
            fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate, saved_context.mtvec >> 32))
            fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_csr_loads[CSR_IDS.MTVEC])] = RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, is_rd_nonpickable_ok=True)
            curr_addr += 8 # NO_COMPRESSED
        else:
            fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,saved_context.mtvec))
            fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,0xdeadbeef))
            fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_csr_loads[CSR_IDS.MTVEC])] = RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, is_rd_nonpickable_ok=True)
            curr_addr += 8 # NO_COMPRESSED

    if fuzzerstate.design_has_supervisor_mode:
        # satp is a bit special because bits above 31 are typically used as well. We must hence discriminate between 32 and 64 bit designs.
        if USE_MMU:
            if DO_ASSERT:
                assert saved_context.stvec >> 64 == 0, "stvec is unexpectedly too large."
            # Little endian. For a number written big endian `abcd`, the bytes should be written in memory as `dcba`. So we write the lsbs first.
            if not fuzzerstate.is_design_64bit:
                raise NotImplementedError
                # Prepare register 2 to be written to the msb of stvec
                # fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_csr_loads[CSR_IDS.STVEC])+1] = RegImmInstruction_t0(fuzzerstate,"addi", 2, MAX_NUM_PICKABLE_REGS, curr_addr-fuzzerstate.ctxsv_bb_base_addr+4, is_rd_nonpickable_ok=True)
            fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,saved_context.stvec & 0xffffffff))
            fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,saved_context.stvec >> 32))
            fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_csr_loads[CSR_IDS.STVEC])] = RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, is_rd_nonpickable_ok=True)
            curr_addr += 8 # NO_COMPRESSED
        else:
            fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,saved_context.stvec))
            fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,0xdeadbeef))
            fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_csr_loads[CSR_IDS.STVEC])] = RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, is_rd_nonpickable_ok=True)
            curr_addr += 8 # NO_COMPRESSED

    if fuzzerstate.design_has_supervisor_mode:
        fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,saved_context.medeleg))
        fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,0xdeadbeef))
        fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_csr_loads[CSR_IDS.MEDELEG])] = RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, is_rd_nonpickable_ok=True)
        curr_addr += 8 # NO_COMPRESSED

    # mstatus is a bit special because bits above 31 are typically used as well. We must hence discriminate between 32 and 64 bit designs.
    if DO_ASSERT:
        assert saved_context.mstatus >> 64 == 0, "mstatus is unexpectedly too large."
    # Little endian. For a number written big endian `abcd`, the bytes should be written in memory as `dcba`. So we write the lsbs first.
    if not fuzzerstate.is_design_64bit:
        # Prepare register 2 to be written to the msb of mstatus
        raise NotImplementedError
        # fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_csr_loads[CSR_IDS.MSTATUS])+1] = RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, curr_addr-data_start_addr, is_rd_nonpickable_ok=True)
    fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,saved_context.mstatus & 0xffffffff))
    fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,saved_context.mstatus >> 32))
    fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_csr_loads[CSR_IDS.MSTATUS])] = RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, is_rd_nonpickable_ok=True)
    curr_addr += 8 # NO_COMPRESSED


    if USE_MMU:
        # satp is a bit special because bits above 31 are typically used as well. We must hence discriminate between 32 and 64 bit designs.
        if DO_ASSERT:
            assert saved_context.satp >> 64 == 0, "satp is unexpectedly too large."
        # Little endian. For a number written big endian `abcd`, the bytes should be written in memory as `dcba`. So we write the lsbs first.
        if not fuzzerstate.is_design_64bit:
            raise NotImplementedError
            # Prepare register 2 to be written to the msb of satp
            # fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_csr_loads[CSR_IDS.SATP])+1] = RegImmInstruction_t0(fuzzerstate,"addi", 2, MAX_NUM_PICKABLE_REGS, curr_addr-fuzzerstate.ctxsv_bb_base_addr+4, is_rd_nonpickable_ok=True)
        fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,saved_context.satp & 0xffffffff))
        fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,saved_context.satp >> 32))
        fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_csr_loads[CSR_IDS.SATP])] = RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, is_rd_nonpickable_ok=True)
        curr_addr += 8 # NO_COMPRESSED

    # mstatus is a bit special because bits above 31 are typically used as well. We must hence discriminate between 32 and 64 bit designs.
    if DO_ASSERT:
        assert saved_context.minstret >> 64 == 0, "minstret is unexpectedly too large."
    # Little endian. For a number written big endian `abcd`, the bytes should be written in memory as `dcba`. So we write the lsbs first.
    if not fuzzerstate.is_design_64bit:
        raise NotImplementedError
        # Prepare register 2 to be written to the msb of minstret
        # fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_csr_loads[CSR_IDS.MINSTRET])+1] = RegImmInstruction_t0(fuzzerstate,"addi", 2, MAX_NUM_PICKABLE_REGS, curr_addr-fuzzerstate.ctxsv_bb_base_addr+4, is_rd_nonpickable_ok=True)

    fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,(saved_context.minstret - ((instr_end_addr - (minstret_base_addr - 4 - 4*int(fuzzerstate.is_design_64bit))) // 4)) & 0xffffffff, signed=True))

    if fuzzerstate.is_design_64bit:
        fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,(saved_context.minstret - ((instr_end_addr - minstret_base_addr - 4) // 4)) >> 32, signed=True))
    else:
        # Should be checked in detail
        if (saved_context.minstret - ((instr_end_addr - (minstret_base_addr - 4 - 4*int(fuzzerstate.is_design_64bit))) // 4)) < 0: # If minstret is negative and will be increased before the start of the run
            fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,(((saved_context.minstret + (saved_context.minstreth << 32)) - ((instr_end_addr - minstret_base_addr - 4) // 4)) >> 32), signed=True))
        else:
            fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,(((saved_context.minstret + (saved_context.minstreth << 32)) - ((instr_end_addr - minstret_base_addr - 4) // 4)) >> 32), signed=True))
    
    curr_addr += 8 # NO_COMPRESSED
    fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_csr_loads[CSR_IDS.MINSTRET])] = RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, is_rd_nonpickable_ok=True)

    ###
    # We're now done with CSRs, we still have to handle the RPROD
    ###
    if USE_MMU:
        # RPROD_MASK_REGISTER_ID is a bit special because bits above 31 are typically used as well. We must hence discriminate between 32 and 64 bit designs.
        if DO_ASSERT:
            assert saved_context.saved_rprod_mask >> 64 == 0, "saved_rprod_mask is unexpectedly too large."
        # Little endian. For a number written big endian `abcd`, the bytes should be written in memory as `dcba`. So we write the lsbs first.
        if not fuzzerstate.is_design_64bit:
            raise NotImplementedError
            # Prepare register 2 to be written to the msb of saved_rprod_mask
            # fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(rprod_load)+1] = RegImmInstruction_t0(fuzzerstate,"addi", 2, MAX_NUM_PICKABLE_REGS, curr_addr-fuzzerstate.ctxsv_bb_base_addr+4, is_rd_nonpickable_ok=True)
        fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate, saved_context.saved_rprod_mask & 0xffffffff))
        fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate, saved_context.saved_rprod_mask >> 32))
        fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(rprod_load)] = RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 8, is_rd_nonpickable_ok=True)
        curr_addr += 8 # NO_COMPRESSED
        # print(f"Saving {hex(saved_context.saved_rprod_mask)} in rprod")

    # Memory bytes
    for mem_byte_id, (mem_byte_addr, mem_byte_val) in enumerate(saved_context.mem_bytes_dict.items()):
        # Set the address of the mem byte
        fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,mem_byte_addr + SPIKE_STARTADDR))
        fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addrs_memaddrs[mem_byte_id])] = RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 4, is_rd_nonpickable_ok=True)
        curr_addr += 4 # NO_COMPRESSED

    # Set the fpu register values here. Use the register 1 to load the address, arbitrarily.
    if fuzzerstate.design_has_fpu:
        assert False, "fpu not implemented yet."
        if fuzzerstate.design_has_fpud:
            # Align if needed
            if curr_addr % 8 != 0:
                fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,0))
                curr_addr += 4
            fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_freg_load_addi)] = RegImmInstruction_t0(fuzzerstate,"addi", 1, MAX_NUM_PICKABLE_REGS, curr_addr-fuzzerstate.ctxsv_bb_base_addr, is_rd_nonpickable_ok=True)
            for freg_id, freg_val in enumerate(saved_context.freg_vals):
                if DO_ASSERT:
                    assert freg_val >= 0
                    assert freg_val < 1 << 64
                fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,freg_val % (1 << 32)))
                fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,freg_val // (1 << 32)))
                curr_addr += 8
        else:
            if DO_ASSERT:
                assert freg_val >= 0
                assert freg_val < 1 << 32
            fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_freg_load_addi)] = RegImmInstruction_t0(fuzzerstate,"addi", 1, MAX_NUM_PICKABLE_REGS, curr_addr-fuzzerstate.ctxsv_bb_base_addr, is_rd_nonpickable_ok=True)
            for freg_id, freg_val in enumerate(saved_context.freg_vals):
                fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,freg_val))
                curr_addr += 4 # NO_COMPRESSED

    # Finally, set the integer registers here. Use the last register to load the address, to ensure that we will not overwrite some int register in the process.
    if fuzzerstate.is_design_64bit:
        # Align if needed
        if curr_addr % 8 != 0:
            fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,0xdeadbeef))
            curr_addr += 4
            fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_reg_load_addi)] = RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 4, is_rd_nonpickable_ok=True)
        else:
            fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_reg_load_addi)] = RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 0, is_rd_nonpickable_ok=True)

        for reg_id, reg_val in enumerate(saved_context.reg_vals):
            reg_val_t0 = 0
            if TAINT_EN:
                assert reg_id < len(saved_context.reg_vals_t0)
                reg_val_t0 = saved_context.reg_vals_t0[reg_id]
            print('For reg id %d, reg val is %s. Addr: %s' % (reg_id, hex(reg_val), hex(curr_addr)))
            fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,reg_val % (1 << 32), reg_val_t0 % (1 << 32))) # lower 32bit
            fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,reg_val // (1 << 32), reg_val_t0 // (1 << 32))) # upper 32bit
            curr_addr += 8
    else:
        fuzzerstate.ctxsv_bb[addr_to_id_in_ctxsv(addr_reg_load_addi)] = RegImmInstruction_t0(fuzzerstate,"addi", MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS, 0, is_rd_nonpickable_ok=True)
        for reg_id, reg_val in enumerate(saved_context.reg_vals):
            fuzzerstate.ctxsv_bb.append(RawDataWord_t0(fuzzerstate,reg_val,reg_val_t0))
            curr_addr += 4 # NO_COMPRESSED

    if DO_ASSERT:
        assert curr_addr == fuzzerstate.ctxsv_bb_base_addr + len(fuzzerstate.ctxsv_bb)*4, f"curr_addr is `{hex(curr_addr)}`, fuzzerstate.ctxsv_bb_base_addr + len(fuzzerstate.ctxsv_bb)*4 is `{hex(fuzzerstate.ctxsv_bb_base_addr + len(fuzzerstate.ctxsv_bb)*4)}`" # NO_COMPRESSED
        assert curr_addr <= fuzzerstate.ctxsv_bb_base_addr + fuzzerstate.ctxsv_size_upperbound, f"The context setter is too large: size is `{hex(curr_addr-fuzzerstate.ctxsv_bb_base_addr)}`, fuzzerstate.ctxsv_size_upperbound is `{hex(fuzzerstate.ctxsv_size_upperbound)}`."

    # The addresses are set in the constructors according to the BBs, which is not correct since we are in the context block now.
    # We correct these addresseses and privileges here.
    # TODO: This is quite ugly maybe change it if possible.
    # For the raw data, we write it to memview as soon as the address is set.
    priv_level =  PrivilegeStateEnum.MACHINE
    va_layout = -1
    for id,instr in enumerate(fuzzerstate.ctxsv_bb):
        assert instr is not None, f"Instruction at index {id} is None!"
        instr.paddr = fuzzerstate.ctxsv_bb_base_addr + 4*id + SPIKE_STARTADDR
        # instr.print()
        instr.priv_level = priv_level
        instr.iscontext = True
        if USE_MMU:
            instr.va_layout = va_layout
            if instr.priv_level == PrivilegeStateEnum.MACHINE:
                instr.vaddr = instr.paddr
            else:
                instr.vaddr = phys2virt(instr.paddr, instr.priv_level, instr.va_layout, fuzzerstate) - SPIKE_STARTADDR
        if isinstance(instr, (PrivilegeDescentInstruction_t0, CSRRegInstruction_t0, JALInstruction_t0)):
            va_layout, priv_level = get_current_layout(instr, va_layout, priv_level)
        if isinstance(instr, RawDataWord_t0):
            instr.write() # Write both value and taint to DMEM
        if isinstance(instr, RegImmInstruction_t0):
            instr.write_t0() # Could have tainted immediates, only need to write taint to IMEM
        # instr.print()
    # We store this state so we can reset the memview to it before (re-)simulating.
    # fuzzerstate.memview.store_state()
    fuzzerstate.memview.set_as_initial_state() # Is this correct since we execute the ctx saver block in the in-situ sim?
        