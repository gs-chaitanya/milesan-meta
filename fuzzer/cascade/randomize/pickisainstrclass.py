# Copyright 2023 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

from params.runparams import DO_ASSERT
from cascade.toleratebugs import is_tolerate_kronos_fence, is_tolerate_picorv32_fence, is_forbid_vexriscv_csrs, is_tolerate_picorv32_missingmandatorycsrs, is_tolerate_picorv32_readhpm_nocsrrs, is_tolerate_picorv32_writehpm, is_tolerate_picorv32_readnonimplcsr
from cascade.util import ISAInstrClass, IntRegIndivState, MmuState, BASIC_BLOCK_MIN_SPACE
from params.fuzzparams import NUM_MIN_FREE_INTREGS, TAINT_IMM_PROTURBANCE_FACTOR, USE_MMU, NUM_MIN_UNTAINTED_INTREGS, MAX_NUM_FENCES_PER_EXECUTION, NUM_MAX_CONSUMED_INTREGS, NUM_MAX_RELOCUSED_INTREGS, PROTURBANCE_CONSUMED_REGS_PPFSM, PROTURBANCE_CONSUMED_REGS_EPCFSM, PROTURBANCE_CONSUMED_REGS_JALR, PROTURBANCE_CONSUMED_REGS_MEDELEG, PROTURBANCE_CONSUMED_REGS_TVECFSM, PROTURBANCE_CONSUMED_REGS_EXCEPTION, PROTURBANCE_RELOCUSED_REGS_ALU
from cascade.privilegestate import PrivilegeStateEnum, is_ready_to_descend_privileges
from cascade.util import IntRegIndivState
import random
from copy import copy

from cascade.randomize.pickmmuop import is_mmu_op_not_possible


# This module helps picking an ISAInstrClass.
# This is the first step of generating a random instruction without a specific structure.

# Must not all be 0. Must be filtered according to the capabilities of the different CPUs.
ISAINSTRCLASS_INITIAL_BOOSTERS = {
    ISAInstrClass.REGFSM:      0.1,
    ISAInstrClass.FPUFSM:      0,
    ISAInstrClass.ALU:         0.05,
    ISAInstrClass.ALU64:       0,
    ISAInstrClass.MULDIV:      0,
    ISAInstrClass.MULDIV64:    0,
    ISAInstrClass.AMO:         0,
    ISAInstrClass.AMO64:       0,
    ISAInstrClass.JAL :        0.01,
    ISAInstrClass.JALR:        0.01,
    ISAInstrClass.BRANCH:      0.01,
    ISAInstrClass.MEM:         0.01,
    ISAInstrClass.MEM64:       0,
    ISAInstrClass.MEMFPU:      0,
    ISAInstrClass.FPU:         0,
    ISAInstrClass.FPU64:       0,
    ISAInstrClass.MEMFPUD:     0,
    ISAInstrClass.FPUD:        0,
    ISAInstrClass.FPUD64:      0,
    ISAInstrClass.TVECFSM:     0.3,
    ISAInstrClass.PPFSM:       0.3,
    ISAInstrClass.EPCFSM:      0.3,
    ISAInstrClass.MEDELEG:     0.3,
    ISAInstrClass.EXCEPTION:   0.01,
    ISAInstrClass.RANDOM_CSR:  0.05,
    ISAInstrClass.DESCEND_PRV: 0.5,
    ISAInstrClass.SPECIAL:     0,
    ISAInstrClass.MMU:         0.5,
    ISAInstrClass.MSTATUS:     0,
    ISAInstrClass.CLEARTAINT:  0.00
}


###
# Helper functions
###

# @param weights a list either None (equal weights) or as long as ISAInstrClass
# return a ISAInstrClass
# Do NOT @cache this function, as it is a random function.
def _gen_next_isainstrclass_from_weights(weights: list = None) -> ISAInstrClass:
    ret = random.choices(list(weights.keys()), weights.values(), k=1)[0]
    assert weights[ret] != 0
    return ret

# @brief For now, the weights used for choosing instructions are fixed over time.
# This function filters the isainstrclass weights according to the capabilities of a given CPU
# FUTURE: Use coverage metrics or other kinds of scheduling.
# FUTURE: Use a Markov chain for executing floating point instructions in a row.
# @return a normalized dict of instruction classes supported by the CPU
# DO NOT @cache
def _get_isainstrclass_filtered_weights(fuzzerstate, curr_alloc_cursor):
    if DO_ASSERT:
        assert fuzzerstate.design_has_fpu or not fuzzerstate.design_has_fpud, "Cannot have double but not simple precision"
    ret_dict = copy(fuzzerstate.isapickweights)
    if not fuzzerstate.is_design_64bit:
        ret_dict[ISAInstrClass.ALU64]    = 0
        ret_dict[ISAInstrClass.MULDIV64] = 0
        ret_dict[ISAInstrClass.AMO64]    = 0
        ret_dict[ISAInstrClass.MEM64]    = 0
        ret_dict[ISAInstrClass.FPU64]    = 0
        ret_dict[ISAInstrClass.FPUD64]   = 0
    if not fuzzerstate.design_has_fpu:
        ret_dict[ISAInstrClass.MEMFPU]   = 0
        ret_dict[ISAInstrClass.FPU]      = 0
        ret_dict[ISAInstrClass.FPU64]    = 0
        ret_dict[ISAInstrClass.MEMFPUD]  = 0
        ret_dict[ISAInstrClass.FPUD]     = 0
        ret_dict[ISAInstrClass.FPUD64]   = 0
        ret_dict[ISAInstrClass.FPUFSM]   = 0
    elif not fuzzerstate.is_fpu_activated:
        ret_dict[ISAInstrClass.MEMFPU]   = 0
        ret_dict[ISAInstrClass.FPU]      = 0
        ret_dict[ISAInstrClass.FPU64]    = 0
        ret_dict[ISAInstrClass.MEMFPUD]  = 0
        ret_dict[ISAInstrClass.FPUD]     = 0
        ret_dict[ISAInstrClass.FPUD64]   = 0
    if not fuzzerstate.design_has_fpud:
        ret_dict[ISAInstrClass.MEMFPUD] = 0
        ret_dict[ISAInstrClass.FPUD]    = 0
        ret_dict[ISAInstrClass.FPUD64]  = 0
    if not fuzzerstate.design_has_muldiv:
        ret_dict[ISAInstrClass.MULDIV]   = 0
        ret_dict[ISAInstrClass.MULDIV64] = 0
    if not fuzzerstate.design_has_amo:
        ret_dict[ISAInstrClass.AMO]   = 0
        ret_dict[ISAInstrClass.AMO64] = 0
    if not fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE:
        ret_dict[ISAInstrClass.FPUFSM] = 0
    if (not fuzzerstate.authorize_privileges) or not (fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE and fuzzerstate.design_has_supervisor_mode) \
        or "vexriscv" in fuzzerstate.design_name and is_forbid_vexriscv_csrs():
        # There is no notion of delegation if supervisor mode is not supported
        ret_dict[ISAInstrClass.MEDELEG] = 0
    # For now, do not populate the mtvec/stvec more than necessary
    if (not fuzzerstate.authorize_privileges) or not (fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE and not fuzzerstate.privilegestate.is_mtvec_populated) and not ((fuzzerstate.privilegestate.privstate in (PrivilegeStateEnum.MACHINE, PrivilegeStateEnum.SUPERVISOR)) and not fuzzerstate.privilegestate.is_stvec_populated and fuzzerstate.design_has_supervisor_mode) or \
        "picorv32" in fuzzerstate.design_name \
        or "vexriscv" in fuzzerstate.design_name and is_forbid_vexriscv_csrs()\
        or fuzzerstate.curr_mmu_state == MmuState.MMU_PROD_2:
        ret_dict[ISAInstrClass.TVECFSM] = 0
    # For now, do not populate the mepc/sepc more than necessary
    if (not fuzzerstate.authorize_privileges) or not ((fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE and not (fuzzerstate.privilegestate.is_mepc_populated and fuzzerstate.privilegestate.is_sepc_populated)) or \
        fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR and not fuzzerstate.privilegestate.is_sepc_populated) or \
        "picorv32" in fuzzerstate.design_name \
        or "vexriscv" in fuzzerstate.design_name and is_forbid_vexriscv_csrs():
        ret_dict[ISAInstrClass.EPCFSM] = 0
    # Do not descend privileges as long as medeleg is undefined because we have no way of certainly coming back up
    # However, this ISA class still encompasses setting mpp and spp bits, to we tolerate this ISA class at all times when executing as a non-user.
    if not is_ready_to_descend_privileges(fuzzerstate) or fuzzerstate.memview.get_available_contig_space(curr_alloc_cursor)-(5*4) < BASIC_BLOCK_MIN_SPACE\
        or fuzzerstate.curr_mmu_state == MmuState.MMU_PROD_J or fuzzerstate.curr_mmu_state == MmuState.MMU_PROD_1:
        ret_dict[ISAInstrClass.DESCEND_PRV] = 0
    # Decrease the proba if we know it will be a mpp/spp
    if (not fuzzerstate.authorize_privileges) or fuzzerstate.privilegestate.privstate != PrivilegeStateEnum.MACHINE or "picorv32" in fuzzerstate.design_name: # To support sret from machine mode: `not in (PrivilegeStateEnum.MACHINE, PrivilegeStateEnum.SUPERVISOR):`
        ret_dict[ISAInstrClass.PPFSM] = 0
    # No exception if no exception is possible
    if (not fuzzerstate.authorize_privileges) or not fuzzerstate.privilegestate.is_ready_to_take_exception(fuzzerstate) or "picorv32" in fuzzerstate.design_name \
        or (USE_MMU and fuzzerstate.is_design_64bit and ((fuzzerstate.pagetablestate.vmem_base_list[fuzzerstate.real_curr_layout][PrivilegeStateEnum.USER] | 0x7fffffff) - (fuzzerstate.pagetablestate.vmem_base_list[fuzzerstate.real_curr_layout][PrivilegeStateEnum.SUPERVISOR] | 0x7fffffff)) != 0) \
        or fuzzerstate.num_instr_to_stay_in_prv > 0\
        or fuzzerstate.curr_mmu_state == MmuState.MMU_PROD_J or fuzzerstate.curr_mmu_state == MmuState.MMU_PROD_1:
        ret_dict[ISAInstrClass.EXCEPTION] = 0
    if not fuzzerstate.privilegestate.privstate in (PrivilegeStateEnum.MACHINE, PrivilegeStateEnum.SUPERVISOR) \
        or "vexriscv" in fuzzerstate.design_name and is_forbid_vexriscv_csrs() \
        or "picorv32" in fuzzerstate.design_name and not is_tolerate_picorv32_missingmandatorycsrs() and not is_tolerate_picorv32_readnonimplcsr() and not is_tolerate_picorv32_writehpm() and not is_tolerate_picorv32_readhpm_nocsrrs():
        ret_dict[ISAInstrClass.RANDOM_CSR] = 0
    if "kronos" in fuzzerstate.design_name and not is_tolerate_kronos_fence() \
        or "picorv32" in fuzzerstate.design_name and not is_tolerate_picorv32_fence() \
            or (MAX_NUM_FENCES_PER_EXECUTION is not None and fuzzerstate.special_instrs_count > MAX_NUM_FENCES_PER_EXECUTION):
        ret_dict[ISAInstrClass.SPECIAL] = 0
    if not USE_MMU or is_mmu_op_not_possible(fuzzerstate, curr_alloc_cursor):
        ret_dict[ISAInstrClass.MMU] = 0
    if not USE_MMU or fuzzerstate.privilegestate.privstate != PrivilegeStateEnum.MACHINE \
        or (((fuzzerstate.pagetablestate.vmem_base_list[fuzzerstate.real_curr_layout][PrivilegeStateEnum.SUPERVISOR] | 0x7fffffff) - (fuzzerstate.pagetablestate.vmem_base_list[fuzzerstate.real_curr_layout][PrivilegeStateEnum.USER] | 0x7fffffff)) != 0 and fuzzerstate.is_design_64bit) \
        or "cva6" in fuzzerstate.design_name: #cva6 does not use the same ISA than spike, hard to change
        ret_dict[ISAInstrClass.MSTATUS] = 0
    if USE_MMU and (fuzzerstate.intregpickstate.get_num_regs_in_state(IntRegIndivState.FREE) + fuzzerstate.intregpickstate.get_num_regs_in_state(IntRegIndivState.RELOCUSED)) < 3: # we need two and theres always the zero reg
        ret_dict[ISAInstrClass.MEM] = 0

    # Normalize the weights
    if DO_ASSERT:
        assert sum(ret_dict.values()) > 0, "The sum of filtered isa pick weights must be strictly positive!"
    norm_factor = 1/sum(ret_dict.values())
    for curr_key in ret_dict:
        ret_dict[curr_key] = ret_dict[curr_key] * norm_factor

    return ret_dict

# Sets the REGFSM weight to 0 if no register can be produced, consumed or relocated
def _filter_regfsm_weight(fuzzerstate, filtered_weights: list):
    if fuzzerstate.curr_mmu_state != MmuState.IDLE: # Or RPROD is not in sync with the registers produced
        filtered_weights[ISAInstrClass.REGFSM] = 0
        return filtered_weights

    # When theres a lot of consumed registers, don't create mode and increase likeliness for the instructions that move them to RELOCUSED.
    if fuzzerstate.intregpickstate.get_num_regs_in_state(IntRegIndivState.CONSUMED) > NUM_MAX_CONSUMED_INTREGS:
        filtered_weights[ISAInstrClass.REGFSM] = 0
        filtered_weights[ISAInstrClass.TVECFSM] *= PROTURBANCE_CONSUMED_REGS_TVECFSM
        filtered_weights[ISAInstrClass.PPFSM] *= PROTURBANCE_CONSUMED_REGS_PPFSM
        filtered_weights[ISAInstrClass.EPCFSM] *= PROTURBANCE_CONSUMED_REGS_EPCFSM
        filtered_weights[ISAInstrClass.MEDELEG] *= PROTURBANCE_CONSUMED_REGS_MEDELEG
        filtered_weights[ISAInstrClass.JALR] *= PROTURBANCE_CONSUMED_REGS_JALR
        filtered_weights[ISAInstrClass.EXCEPTION] *= PROTURBANCE_CONSUMED_REGS_EXCEPTION
        return filtered_weights


    if fuzzerstate.intregpickstate.get_num_regs_in_state(IntRegIndivState.FREE) + fuzzerstate.intregpickstate.get_num_regs_in_state(IntRegIndivState.RELOCUSED) > NUM_MIN_FREE_INTREGS or \
            fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PRODUCED0) or \
            (fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PRODUCED1) and \
            fuzzerstate.intregpickstate.exists_untainted_reg_in_state(IntRegIndivState.FREE, allow_zero = False)):
            return filtered_weights

    filtered_weights[ISAInstrClass.REGFSM] = 0
    return filtered_weights

# We need at least one untainted and free input register and one free or relocused output register.
def _filter_csr_weight(fuzzerstate, filtered_weights: list):
    if fuzzerstate.intregpickstate.get_num_untainted_regs_in_state(IntRegIndivState.RELOCUSED) > NUM_MAX_RELOCUSED_INTREGS:
        filtered_weights[ISAInstrClass.RANDOM_CSR] = 0
        filtered_weights[ISAInstrClass.ALU] *= PROTURBANCE_RELOCUSED_REGS_ALU
        return filtered_weights

    if fuzzerstate.intregpickstate.get_num_untainted_regs_in_state(IntRegIndivState.FREE) > 0 and \
        (fuzzerstate.intregpickstate.get_num_regs_in_state(IntRegIndivState.FREE) > 1  or \
        fuzzerstate.intregpickstate.get_num_regs_in_state(IntRegIndivState.RELOCUSED) > 0):
        return filtered_weights

    filtered_weights[ISAInstrClass.RANDOM_CSR] = 0
    return filtered_weights

# Filters out the sensitive instructions considering whether there are available registers in the suitable state
def _filter_sensitive_instr_weights(fuzzerstate, filtered_weights: list):
    if not fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.CONSUMED):
        filtered_weights[ISAInstrClass.JAL]     = 0
        # We use branches with two dependent registers, so we don't need CONSUMED registers.
        # filtered_weights[ISAInstrClass.BRANCH]  = 0
        filtered_weights[ISAInstrClass.MEDELEG] = 0
        filtered_weights[ISAInstrClass.TVECFSM] = 0
        filtered_weights[ISAInstrClass.EPCFSM]  = 0
        filtered_weights[ISAInstrClass.JALR]    = 0
        filtered_weights[ISAInstrClass.MEM]     = 0
        filtered_weights[ISAInstrClass.MEM64]   = 0
        filtered_weights[ISAInstrClass.MEMFPU]  = 0
        filtered_weights[ISAInstrClass.MEMFPUD] = 0
        filtered_weights[ISAInstrClass.MSTATUS] = 0
    return filtered_weights

# When there's too much taint, we choose an RegImm or ImmRd to untaint some register(s).
# When there's only little taint, we increase chance for RegImm or ImmRd to add taint.
def _filter_taint(fuzzerstate, filtered_weights: list):
    n_free_untainted_regs = fuzzerstate.intregpickstate.get_num_untainted_regs_in_state(IntRegIndivState.FREE)
    if n_free_untainted_regs < NUM_MIN_UNTAINTED_INTREGS:
        filtered_weights = dict.fromkeys(filtered_weights,0)
        filtered_weights[ISAInstrClass.ALU] = ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.ALU]
        filtered_weights[ISAInstrClass.ALU64] = ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.ALU64]
        filtered_weights[ISAInstrClass.CLEARTAINT] = ISAINSTRCLASS_INITIAL_BOOSTERS[ISAInstrClass.CLEARTAINT]
    elif n_free_untainted_regs > NUM_MIN_UNTAINTED_INTREGS*2 and fuzzerstate.privilegestate.privstate in fuzzerstate.taint_in_priv:
        filtered_weights[ISAInstrClass.ALU] *= TAINT_IMM_PROTURBANCE_FACTOR # Add taint with immediates if we are in the alowed priveleges only.
        filtered_weights[ISAInstrClass.ALU64] *= TAINT_IMM_PROTURBANCE_FACTOR

    if DO_ASSERT:
        if not (fuzzerstate.privilegestate.privstate in fuzzerstate.taint_in_priv or not fuzzerstate.intregpickstate.exists_tainted_reg()):
            fuzzerstate.intregpickstate.print()
            assert False, f"There should not be any taint in { fuzzerstate.privilegestate.privstate.name}. Allowed are {[p.name for p in fuzzerstate.taint_in_priv]}"

    return filtered_weights

###
# Exposed function
###

# Do NOT @cache this function, as it is a random function.
def gen_next_isainstrclass(fuzzerstate, curr_alloc_cursor, no_mmu_op: bool = False) -> ISAInstrClass:
    filtered_weights = _get_isainstrclass_filtered_weights(fuzzerstate, curr_alloc_cursor)
    filtered_weights = _filter_regfsm_weight(fuzzerstate, filtered_weights)
    filtered_weights = _filter_csr_weight(fuzzerstate, filtered_weights)
    filtered_weights = _filter_sensitive_instr_weights(fuzzerstate, filtered_weights)
    if no_mmu_op:
        filtered_weights[ISAInstrClass.MMU] = 0

    filtered_weights = _filter_taint(fuzzerstate, filtered_weights)

    return _gen_next_isainstrclass_from_weights(filtered_weights)
