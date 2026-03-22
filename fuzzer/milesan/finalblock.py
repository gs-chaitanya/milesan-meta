# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This module defines the final block.

from params.runparams import DO_ASSERT, DEBUG_PRINT
from params.fuzzparams import USE_MMU, MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_FLOATING_REGS
from common.designcfgs import get_design_stop_sig_addr
from params.fuzzparams import RDEP_MASK_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, RPROD_MASK_REGISTER_ID
from milesan.privilegestate import PrivilegeStateEnum
from rv.asmutil import li_into_reg
from milesan.cfinstructionclasses import ImmRdInstruction, RegImmInstruction, IntStoreInstruction, JALInstruction, SpecialInstruction, R12DInstruction

def get_finalblock_max_size():
    # Keep original size to preserve PRNG sequence in alloc_final_basic_block (basicblock.py:428).
    # The actual final block is smaller now (tohost-only), but this only over-reserves space.
    return (10 + 2*MAX_NUM_PICKABLE_REGS + 2*MAX_NUM_PICKABLE_FLOATING_REGS - 1) * 4 + 10*4

# Returns the instruction objects of the tail basic block (tohost exit sequence)
def finalblock(fuzzerstate, design_name: str):
    try:
        stopsig_addr = get_design_stop_sig_addr(design_name)
    except:
        raise ValueError(f"Design `{design_name}` does not have the `stopsigaddr` attribute.")

    if DEBUG_PRINT: print(f"in final block, layout: {fuzzerstate.effective_curr_layout}, priv: ", fuzzerstate.privilegestate.privstate)

    ret = []

    ##
    # Handle virtual layouts
    ##

    # Set the U bit to the corresponding value
    sum_bit, mprv_bit = fuzzerstate.status_sum_mprv
    if (fuzzerstate.effective_curr_layout != -1 or (fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE and mprv_bit and (fuzzerstate.privilegestate.curr_mstatus_mpp != PrivilegeStateEnum.MACHINE))):
        
        pte_content = fuzzerstate.pagetablestate.all_pt_entries
        # Set the U bit to the corresponding value
        if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.USER or (fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE and mprv_bit and fuzzerstate.privilegestate.curr_mstatus_mpp == PrivilegeStateEnum.USER):
            for layout_id, va_layout in enumerate(pte_content):
                if fuzzerstate.pagetablestate.entangled_layouts[layout_id] != None: continue
                last_elem = len(va_layout[-1])-1
                va_layout[-1][last_elem-1] |= 0b10000
                va_layout[-1][last_elem] |= 0b10000
        # if the sum bit is on, we can still access supervisor mappings
        if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR or (fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE and mprv_bit and fuzzerstate.privilegestate.curr_mstatus_mpp == PrivilegeStateEnum.SUPERVISOR):
            for layout_id, va_layout in enumerate(pte_content):
                if fuzzerstate.pagetablestate.entangled_layouts[layout_id] != None: continue
                last_elem = len(va_layout[-1])-1
                va_layout[-1][last_elem-1] &= 0xffffffffffffffef
                va_layout[-1][last_elem] &= 0xffffffffffffffef

    ###
    # Load tohost address into MPP_BOTH_ENDIS_REGISTER_ID
    ###
    if fuzzerstate.effective_curr_layout == -1 and not (fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE and mprv_bit and (fuzzerstate.privilegestate.curr_mstatus_mpp != PrivilegeStateEnum.MACHINE and fuzzerstate.real_curr_layout != -1)):
        # Path 1: Non-MMU / physical address — use 64-bit split-load sequence
        lui_imm_stopsig, addi_imm_stopsig = li_into_reg(stopsig_addr & 0xFFFFFFFF, do_check_bounds=False)
        ret += [
            ImmRdInstruction(fuzzerstate, "lui", MPP_BOTH_ENDIS_REGISTER_ID, lui_imm_stopsig, is_rd_nonpickable_ok=True),
            RegImmInstruction(fuzzerstate, "addi", MPP_BOTH_ENDIS_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, addi_imm_stopsig, is_rd_nonpickable_ok=True),
        ]
        if fuzzerstate.is_design_64bit:
            lui_imm_stopsig_top, addi_imm_stopsig_top = li_into_reg((stopsig_addr >> 32) & 0xFFFFFFFF, do_check_bounds=False)
            ret += [
                R12DInstruction(fuzzerstate, "and", MPP_BOTH_ENDIS_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, RDEP_MASK_REGISTER_ID, is_rd_nonpickable_ok=True),
                ImmRdInstruction(fuzzerstate, "lui", RPROD_MASK_REGISTER_ID, lui_imm_stopsig_top, is_rd_nonpickable_ok=True),
                RegImmInstruction(fuzzerstate, "addi", RPROD_MASK_REGISTER_ID, RPROD_MASK_REGISTER_ID, addi_imm_stopsig_top, is_rd_nonpickable_ok=True),
                RegImmInstruction(fuzzerstate, "slli", RPROD_MASK_REGISTER_ID, RPROD_MASK_REGISTER_ID, 32, is_rd_nonpickable_ok=True),
                R12DInstruction(fuzzerstate, "or", MPP_BOTH_ENDIS_REGISTER_ID, RPROD_MASK_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, is_rd_nonpickable_ok=True),
            ]
    else:
        # Path 2: MMU / virtual address from page table state
        if DEBUG_PRINT: print(f"physical stopsig addr is: {hex(stopsig_addr)}")
        if USE_MMU:
            _, stopsig_addr = fuzzerstate.pagetablestate.finalblock_sig_vaddr[fuzzerstate.real_curr_layout]
        if DEBUG_PRINT: print(f"virtual stopsig addr is: {hex(stopsig_addr)}")

        lui_imm_stopsig, addi_imm_stopsig = li_into_reg(stopsig_addr & 0xFFFFFFFF, do_check_bounds=False)
        ret += [
            ImmRdInstruction(fuzzerstate, "lui", MPP_BOTH_ENDIS_REGISTER_ID, lui_imm_stopsig, is_rd_nonpickable_ok=True),
            RegImmInstruction(fuzzerstate, "addi", MPP_BOTH_ENDIS_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, addi_imm_stopsig, is_rd_nonpickable_ok=True),
        ]
        if fuzzerstate.is_design_64bit:
            lui_imm_stopsig_top, addi_imm_stopsig_top = li_into_reg((stopsig_addr >> 32) & 0xFFFFFFFF, do_check_bounds=False)
            ret += [
                R12DInstruction(fuzzerstate, "and", MPP_BOTH_ENDIS_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, RDEP_MASK_REGISTER_ID, is_rd_nonpickable_ok=True),
                ImmRdInstruction(fuzzerstate, "lui", RPROD_MASK_REGISTER_ID, lui_imm_stopsig_top, is_rd_nonpickable_ok=True),
                RegImmInstruction(fuzzerstate, "addi", RPROD_MASK_REGISTER_ID, RPROD_MASK_REGISTER_ID, addi_imm_stopsig_top, is_rd_nonpickable_ok=True),
                RegImmInstruction(fuzzerstate, "slli", RPROD_MASK_REGISTER_ID, RPROD_MASK_REGISTER_ID, 32, is_rd_nonpickable_ok=True),
                R12DInstruction(fuzzerstate, "or", MPP_BOTH_ENDIS_REGISTER_ID, RPROD_MASK_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, is_rd_nonpickable_ok=True),
            ]

    ###
    # Write 1 to tohost to trigger clean exit (HTIF protocol: 0 = no-op, 1 = exit code 0)
    ###
    ret.append(RegImmInstruction(fuzzerstate, "addi", RPROD_MASK_REGISTER_ID, 0, 1, is_rd_nonpickable_ok=True))
    ret.append(IntStoreInstruction(fuzzerstate, "sd" if fuzzerstate.is_design_64bit else "sw", MPP_BOTH_ENDIS_REGISTER_ID, RPROD_MASK_REGISTER_ID, 0, -1))
    ret.append(SpecialInstruction(fuzzerstate, "fence"))

    # Infinite loop in the end of the simulation
    ret.append(JALInstruction(fuzzerstate, "jal", 0, 0))

    if DO_ASSERT:
        assert len(ret) * 4 <= get_finalblock_max_size(), f"The final block is larger than expected: {len(ret) * 4} > {get_finalblock_max_size()}"

    return ret


# Spike does not support writing to some signaling addresses, but at the same time, we do not need it for spike resolution anyway. So let's replace it with an infinite loop.
def finalblock_spike_resolution(fuzzerstate):
    # Infinite loop in the end of the simulation
    jal_instr = JALInstruction(fuzzerstate,"jal", 0, 0)
    jal_instr.paddr = fuzzerstate.final_bb_base_addr
    return [jal_instr]
