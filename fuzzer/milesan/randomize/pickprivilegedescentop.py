# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script is used to pick an instruction from the privileged descent instruction ISA class.

from params.runparams import DO_ASSERT,DEBUG_PRINT
from params.fuzzparams import USE_MMU, MAX_NUM_INSTR_IN_PRV, MIN_NUM_INSTR_IN_PRV, USE_MMU
from milesan.privilegestate import PrivilegeStateEnum
from milesan.cfinstructionclasses_t0 import PrivilegeDescentInstruction_t0
from milesan.randomize.pickcleartaintops import clear_taints_with_random_instructions
from milesan.util import MmuState
from rv.asmutil import li_into_reg
from rv.csrids import CSR_IDS

import random

# @brief Generate a privileged descent instruction or an mpp/spp write instruction.
# @return a list of instructions
def gen_priv_descent_instr(fuzzerstate):
    instr_objs = []
    old_priv_state = fuzzerstate.privilegestate.privstate
    if DO_ASSERT:
        if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE:
            # Add `or fuzzerstate.privilegestate.is_sepc_populated` to implement sret in machine mode
            assert fuzzerstate.privilegestate.is_mepc_populated, "If we are in machine mode, then mepc or sepc should be populated if we want to descend privileges."
            assert fuzzerstate.privilegestate.curr_mstatus_mpp is not None, "mpp should be populated if we want to descend privileges from machine mode."
        else:
            assert fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR
            assert fuzzerstate.privilegestate.is_sepc_populated, "If we are in supervisor mode, then sepc should be populated if we want to descend privileges."
            assert fuzzerstate.privilegestate.curr_mstatus_spp is not None, "spp should be populated if we want to descend privileges from supervisor mode."

    is_mret = fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE

    # If there should not be any taint propagation from the privelege we're in to the one we are returning to.
    if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE and fuzzerstate.privilegestate.curr_mstatus_mpp not in fuzzerstate.taint_source_privs:
        instr_objs += clear_taints_with_random_instructions(fuzzerstate, untaint_all=True)
    elif fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR and PrivilegeStateEnum.SUPERVISOR in fuzzerstate.taint_source_privs and fuzzerstate.privilegestate.curr_mstatus_spp not in fuzzerstate.taint_source_privs:
        instr_objs += clear_taints_with_random_instructions(fuzzerstate, untaint_all=True)

    # Invalidate the corresponding epc and update the current privilege level.
    # Do not update or invalidate mpp/spp bits.
    if is_mret:
        fuzzerstate.privilegestate.is_mepc_populated = False
        fuzzerstate.privilegestate.privstate = fuzzerstate.privilegestate.curr_mstatus_mpp
        fuzzerstate.privilegestate.curr_mstatus_mpp = PrivilegeStateEnum.USER
    else:
        fuzzerstate.privilegestate.is_sepc_populated = False
        fuzzerstate.privilegestate.privstate = fuzzerstate.privilegestate.curr_mstatus_spp
        fuzzerstate.privilegestate.curr_mstatus_spp = PrivilegeStateEnum.USER


    if USE_MMU:
        if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE:
            if DEBUG_PRINT: print("------------ Switching back to bare due to machine mode ------------------")
            # Set the effective va layout to -1
            fuzzerstate.effective_curr_layout = -1
        else:
            if DEBUG_PRINT: 
                print(f"---------- Switching to layout number {fuzzerstate.real_curr_layout} to {fuzzerstate.privilegestate.privstate.name}")
                if fuzzerstate.real_curr_layout in fuzzerstate.taint_source_layouts: 
                    print(f"{fuzzerstate.real_curr_layout} is a taint source layout")
                if fuzzerstate.privilegestate.privstate in fuzzerstate.taint_source_privs:
                    print(f"{fuzzerstate.privilegestate.privstate.name} is a taint source privilege")
            # We do not want to allow U=>S transitions with big pages, so we disable exception delegation
            if fuzzerstate.is_design_64bit:
                user_sup_offset = (fuzzerstate.pagetablestate.vmem_base_list[fuzzerstate.real_curr_layout][PrivilegeStateEnum.SUPERVISOR] | 0x7fffffff) - (fuzzerstate.pagetablestate.vmem_base_list[fuzzerstate.real_curr_layout][PrivilegeStateEnum.USER] | 0x7fffffff)
                if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.USER and user_sup_offset != 0:
                    bb_id, instr_id = fuzzerstate.last_medeleg_coordinates
                    fuzzerstate.instr_objs_seq[bb_id][instr_id].val_to_write_spike = 0
                    fuzzerstate.instr_objs_seq[bb_id][instr_id].val_to_write_cpu = 0
                    fuzzerstate.privilegestate.medeleg_val = 0

            # Update the true va layout
            fuzzerstate.effective_curr_layout = fuzzerstate.real_curr_layout
            fuzzerstate.satp_set_not_used = False
            
        if fuzzerstate.real_curr_layout not in fuzzerstate.taint_source_layouts: 
            instr_objs += clear_taints_with_random_instructions(fuzzerstate, untaint_all=True)

    # The following is only relevant if leave machine mode
    if USE_MMU and fuzzerstate.privilegestate.privstate != PrivilegeStateEnum.MACHINE:
        # When leaving machine mode, mprv bit is cleared
        if old_priv_state == PrivilegeStateEnum.MACHINE: # and "cva6" not in fuzzerstate.design_name: #CVA6 has priv 1.10:
            sum_bit, _ = fuzzerstate.status_sum_mprv
            fuzzerstate.status_sum_mprv = sum_bit, False

        # Now that we know the priv level, fill in the immediate for RPROD
        if fuzzerstate.is_design_64bit and fuzzerstate.curr_mmu_state == MmuState.IDLE:
            (bb_id, instr_id), layout = fuzzerstate.satp_op_coordinates
            if (bb_id, instr_id) != (None, None):
                rdep_imm = fuzzerstate.pagetablestate.vmem_base_list[fuzzerstate.real_curr_layout][fuzzerstate.privilegestate.privstate] | 0x7fffffff
                imm_0_to_31 = rdep_imm & 0xffffffff
                imm_63_to_31 = rdep_imm >> 32
                lui_imm, addi_imm = li_into_reg(imm_0_to_31, False)
                fuzzerstate.instr_objs_seq[bb_id][instr_id].imm     = lui_imm
                fuzzerstate.instr_objs_seq[bb_id][instr_id+1].imm   = addi_imm
                lui_imm, addi_imm = li_into_reg(imm_63_to_31, False)
                fuzzerstate.instr_objs_seq[bb_id][instr_id+3].imm   = lui_imm
                fuzzerstate.instr_objs_seq[bb_id][instr_id+4].imm   = addi_imm
                fuzzerstate.satp_op_coordinates = ((None, None), None)

            if ((old_priv_state == PrivilegeStateEnum.SUPERVISOR and fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.USER) or (old_priv_state == PrivilegeStateEnum.USER and fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR)) and (fuzzerstate.pagetablestate.vmem_base_list[fuzzerstate.real_curr_layout][PrivilegeStateEnum.SUPERVISOR] | 0x7fffffff) - (fuzzerstate.pagetablestate.vmem_base_list[fuzzerstate.real_curr_layout][PrivilegeStateEnum.USER] | 0x7fffffff) != 0:
                assert False, "We are going from user to supervisor with page too larger, we do not handle that yet"
    
    # If we fuzz the MMU, we want to stay in priviledged mode longer
    if USE_MMU:
        fuzzerstate.num_instr_to_stay_in_prv = random.randint(MIN_NUM_INSTR_IN_PRV, MAX_NUM_INSTR_IN_PRV)
        if DEBUG_PRINT: print(f"will stay in this mode for {fuzzerstate.num_instr_to_stay_in_prv} instructions")
    instr_objs += [PrivilegeDescentInstruction_t0(fuzzerstate, is_mret)]
    fuzzerstate.intregpickstate.free_pageregs()
    return instr_objs

