# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This module is responsible for picking specific operations among exceptions.

from milesan.cfinstructionclasses import JALInstruction, SimpleIllegalInstruction, SimpleExceptionEncapsulator, MisalignedMemInstruction, EcallEbreakInstruction, TvecWriterInstruction, EPCWriterInstruction, GenericCSRWriterInstruction, CSRRegInstruction, PrivilegeDescentInstruction, CSRRegInstructions, Float3Instruction, Float3Instructions
from milesan.cfinstructionclasses_t0 import TvecWriterInstruction_t0, EPCWriterInstruction_t0, GenericCSRWriterInstruction_t0, SimpleExceptionEncapsulator_t0, CSRRegInstruction_t0, SimpleIllegalInstruction_t0, MisalignedMemInstruction_t0, MstatusWriterInstruction_t0, R12DInstruction_t0, RegImmInstruction_t0, ImmRdInstruction_t0, IntLoadInstruction_t0
from milesan.privilegestate import PrivilegeStateEnum
from milesan.randomize.createcfinstr import gen_random_rounding_mode
from milesan.randomize.pickcleartaintops import clear_taints_with_random_instructions
from milesan.toleratebugs import is_tolerate_rocket_minstret, is_tolerate_kronos_readbadcsr, is_tolerate_picorv32_readnonimplcsr, is_forbid_vexriscv_csrs, is_tolerate_vexriscv_fpu_disabled, is_tolerate_vexriscv_fpu_leak
from milesan.util import ExceptionCauseVal, IntRegIndivState
from milesan.mmu_utils import PHYSICAL_PAGE_SIZE
from common.spike import SPIKE_MEDELEG_MASK, SPIKE_STARTADDR
from params.fuzzparams import MPP_BOTH_ENDIS_REGISTER_ID, MPP_TOP_ENDIS_REGISTER_ID, SPP_ENDIS_REGISTER_ID, SIMPLE_ILLEGAL_INSTRUCTION_PROBA, PROBA_PICK_WRONG_FPU, MAX_NUM_PICKABLE_FLOATING_REGS, MAX_NUM_PICKABLE_REGS, TAINT_EN, USE_MMU
from params.runparams import DO_ASSERT
from rv.csrids import CSR_IDS, INTERESTING_CSRS_INACCESSIBLE_FROM_SUPERVISOR, INTERESTING_CSRS_INACCESSIBLE_FROM_USER
from copy import copy
import random
###
# Exception type
###

EXCEPTION_OP_TYPE_INITIAL_BOOSTERS = {
    ExceptionCauseVal.ID_INSTR_ADDR_MISALIGNED:        1,
    ExceptionCauseVal.ID_INSTR_ACCESS_FAULT:           0, # 4,
    ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION:          1,
    ExceptionCauseVal.ID_BREAKPOINT:                   0.1,
    ExceptionCauseVal.ID_LOAD_ADDR_MISALIGNED:         1,
    ExceptionCauseVal.ID_LOAD_ACCESS_FAULT:            1, # 2,
    ExceptionCauseVal.ID_STORE_AMO_ADDR_MISALIGNED:    0,
    ExceptionCauseVal.ID_STORE_AMO_ACCESS_FAULT:       0, # 2,
    ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_U_MODE: 0.1,
    ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_S_MODE: 0.1,
    ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_M_MODE: 0.1,
    ExceptionCauseVal.ID_INSTRUCTION_PAGE_FAULT:       0, # 4,
    ExceptionCauseVal.ID_LOAD_PAGE_FAULT:              1, # 2,
    ExceptionCauseVal.ID_STORE_AMO_PAGE_FAULT:         0  # 2
}

# @param weights a list either None (equal weights) or as long as ExceptionCauseVal
# return an ExceptionCauseVal
# Do NOT @cache this function, as it is a random function.
def _gen_next_exceptionoptype(fuzzerstate) -> ExceptionCauseVal:
    # Depending on delegations and whether mtvec and stvec are populated, select which exceptions are possible
    weights = copy(_get_exceptionoptype_filtered_weights(fuzzerstate))
    if DO_ASSERT:
        assert sum(weights.values()) > 0, "The sum of filtered exceptionop pick weights must be strictly positive! Currently: " + str(sum(weights.values()))
    # If there's a single possibility, then return that one
    for curr_exception_type, curr_weight in weights.items():
        if curr_weight == 1:
            return curr_exception_type
    ret = None

    ret = random.choices(list(ExceptionCauseVal), weights=weights.values())[0]
    return ret

# @brief For now, the weights used for choosing instructions are fixed over time.
# This function filters the exceptionoptype weights according to the capabilities of a given CPU
# @return a normalized dict of ExceptionCauseVals that can currently be used.
# DO NOT @cache
def _get_exceptionoptype_filtered_weights(fuzzerstate):
    takable_exceptions = fuzzerstate.privilegestate.gen_takable_exception_dict(fuzzerstate)
    ret_dict = {
        exception_type: int(takable_exceptions[exception_type]) * fuzzerstate.exceptionoppickweights[exception_type]
        for exception_type in list(ExceptionCauseVal)
    }
    # Normalize the weights
    if DO_ASSERT:
        assert sum(ret_dict.values()) > 0, "The sum of filtered exceptionop pick weights must be strictly positive! Currently: " + str(sum(ret_dict.values()))
    norm_factor = 1/sum(ret_dict.values())
    for curr_key in ret_dict.keys():
        ret_dict[curr_key] = ret_dict[curr_key] * norm_factor
    return ret_dict

###
# From exception type, pick an exception instruction
###

# Illegal instructions can result from either a simple non-existing instruction, or from an illegal CSR access.
# Warning: the privilege state of fuzzerstate is already updated!!
# @param old_privilege the privilege state before the exception
def pick_illegal_instruction(is_mtvec, fuzzerstate):
    if "vexriscv" in fuzzerstate.design_name and is_tolerate_vexriscv_fpu_disabled() and not fuzzerstate.is_fpu_activated:
        rm = gen_random_rounding_mode()
        frs1, frs2 = random.randrange(MAX_NUM_PICKABLE_FLOATING_REGS), random.randrange(MAX_NUM_PICKABLE_FLOATING_REGS)
        frd = random.randrange(MAX_NUM_PICKABLE_FLOATING_REGS)
        return SimpleExceptionEncapsulator_t0(fuzzerstate,is_mtvec, None, Float3Instruction('fadd.s', 0, 0, 0, 0, False),  ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION)
    if "vexriscv" in fuzzerstate.design_name and is_tolerate_vexriscv_fpu_leak() and fuzzerstate.is_fpu_activated:
        rs1 = random.randrange(MAX_NUM_PICKABLE_REGS)
        rd = random.randrange(MAX_NUM_PICKABLE_REGS)
        return SimpleExceptionEncapsulator_t0(fuzzerstate,is_mtvec, None, CSRRegInstruction_t0(fuzzerstate,'csrrw', rd, rs1, CSR_IDS.FCSR),  ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION)

    if "vexriscv" in fuzzerstate.design_name and is_forbid_vexriscv_csrs():
        corrected_simple_illegal_instruction_proba = 1
    else:
        corrected_simple_illegal_instruction_proba = SIMPLE_ILLEGAL_INSTRUCTION_PROBA
    if corrected_simple_illegal_instruction_proba < random.random():
        return SimpleExceptionEncapsulator_t0(fuzzerstate, is_mtvec, None, SimpleIllegalInstruction_t0(fuzzerstate, is_mtvec), ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION)

    if not fuzzerstate.design_has_fpu or not fuzzerstate.is_fpu_activated \
        and not ("vexriscv" in fuzzerstate.design_name and is_forbid_vexriscv_csrs()):
        if random.random() < PROBA_PICK_WRONG_FPU * 0.01**fuzzerstate.design_has_fpu:
            rm = gen_random_rounding_mode()
            frs1, frs2 = random.randrange(MAX_NUM_PICKABLE_FLOATING_REGS), random.randrange(MAX_NUM_PICKABLE_FLOATING_REGS)
            frd = random.randrange(MAX_NUM_PICKABLE_FLOATING_REGS)
            return SimpleExceptionEncapsulator_t0(fuzzerstate,is_mtvec, None, Float3Instruction(random.choice(Float3Instructions), frd, frs1, frs2, rm, False), ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION)

    if fuzzerstate.privilegestate.prev_privstate == PrivilegeStateEnum.MACHINE:
        if 'kronos' in fuzzerstate.design_name and not is_tolerate_kronos_readbadcsr() \
            or 'picorv32' in fuzzerstate.design_name and not is_tolerate_picorv32_readnonimplcsr():
            candidate_instructions = [
                SimpleExceptionEncapsulator_t0(fuzzerstate,is_mtvec, None, SimpleIllegalInstruction_t0(fuzzerstate, is_mtvec), ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION),
            ]
        else:
            candidate_instructions = [
                SimpleExceptionEncapsulator_t0(fuzzerstate,is_mtvec, None, SimpleIllegalInstruction_t0(fuzzerstate, is_mtvec),  ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION),
                SimpleExceptionEncapsulator_t0(fuzzerstate,is_mtvec, None, CSRRegInstruction_t0(fuzzerstate,"csrrw", random.randrange(fuzzerstate.num_pickable_regs), random.randrange(fuzzerstate.num_pickable_regs), CSR_IDS.UNIMP),  ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION),
            ]
    elif fuzzerstate.privilegestate.prev_privstate == PrivilegeStateEnum.SUPERVISOR:
        candidate_instructions = [
            SimpleExceptionEncapsulator_t0(fuzzerstate,is_mtvec, None, PrivilegeDescentInstruction(fuzzerstate, True), ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION),
            SimpleExceptionEncapsulator_t0(fuzzerstate,is_mtvec, None, CSRRegInstruction_t0(fuzzerstate,"csrrw", random.randrange(fuzzerstate.num_pickable_regs), random.randrange(fuzzerstate.num_pickable_regs), random.choice(INTERESTING_CSRS_INACCESSIBLE_FROM_SUPERVISOR)),  ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION),
        ]
    elif fuzzerstate.privilegestate.prev_privstate == PrivilegeStateEnum.USER:
        candidate_instructions = [
            SimpleExceptionEncapsulator_t0(fuzzerstate,is_mtvec, None, random.choice([PrivilegeDescentInstruction(fuzzerstate, True), PrivilegeDescentInstruction(fuzzerstate, False)]), ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION),
            SimpleExceptionEncapsulator_t0(fuzzerstate,is_mtvec, None, CSRRegInstruction_t0(fuzzerstate,"csrrw", random.randrange(fuzzerstate.num_pickable_regs), random.randrange(fuzzerstate.num_pickable_regs), random.choice(INTERESTING_CSRS_INACCESSIBLE_FROM_USER)),  ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION),
        ]
    else:
        raise Exception("Unknown privilege state: " + str(fuzzerstate.privilegestate.prev_privstate))
    ret = random.choice(candidate_instructions)
    return ret

# Has the side effect of consuming a tvec
def gen_next_exception_instr_from_instroptype(fuzzerstate, exception_op_type: ExceptionCauseVal):
    # Check for delegations
    if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE:
        is_mtvec = True
    else:
        if DO_ASSERT:
            assert fuzzerstate.privilegestate.medeleg_val is not None
        is_mtvec = not (fuzzerstate.privilegestate.medeleg_val & (1 << exception_op_type.value))

    if DO_ASSERT:
        assert fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE or exception_op_type not in (ExceptionCauseVal.ID_INSTR_ACCESS_FAULT, ExceptionCauseVal.ID_LOAD_ADDR_MISALIGNED, ExceptionCauseVal.ID_STORE_AMO_ADDR_MISALIGNED) or (fuzzerstate.privilegestate.medeleg_val >> exception_op_type.value)&1 == (fuzzerstate.privilegestate.medeleg_val >> ExceptionCauseVal.ID_LOAD_PAGE_FAULT)&1, "We can only do misaligned exceptions from supervisor/user if we either both or neither delegate the page fault and the misaligned access as the order of exceptions is platform-specific."
    # Pollutes the corresponding epc and updates xpp
    if is_mtvec:
        fuzzerstate.privilegestate.is_mepc_populated = False
        fuzzerstate.privilegestate.curr_mstatus_mpp = fuzzerstate.privilegestate.privstate
    else:
        fuzzerstate.privilegestate.is_sepc_populated = False
        fuzzerstate.privilegestate.curr_mstatus_spp = fuzzerstate.privilegestate.privstate

    # Consume the tvec
    if DO_ASSERT:
        if is_mtvec:
            assert fuzzerstate.privilegestate.is_mtvec_populated
        else:
            assert fuzzerstate.privilegestate.is_stvec_populated
    if is_mtvec:
        fuzzerstate.privilegestate.is_mtvec_populated = False
    else:
        fuzzerstate.privilegestate.is_stvec_populated = False

    # Update the privilege state
    fuzzerstate.privilegestate.prev_privstate = fuzzerstate.privilegestate.privstate
    fuzzerstate.effective_prev_layout = fuzzerstate.effective_curr_layout

    if is_mtvec:
        fuzzerstate.privilegestate.privstate = PrivilegeStateEnum.MACHINE
        fuzzerstate.effective_curr_layout = -1
    else:
        fuzzerstate.privilegestate.privstate = PrivilegeStateEnum.SUPERVISOR
        if USE_MMU: user_sup_offset = (fuzzerstate.pagetablestate.vmem_base_list[fuzzerstate.real_curr_layout][fuzzerstate.privilegestate.privstate] | 0x7fffffff) - (fuzzerstate.pagetablestate.vmem_base_list[fuzzerstate.real_curr_layout][fuzzerstate.privilegestate.prev_privstate] | 0x7fffffff)
        if USE_MMU and fuzzerstate.privilegestate.prev_privstate == PrivilegeStateEnum.USER and user_sup_offset != 0:
            # FIXME EXTEND this will not be 0 if we use only one level of pages
            print(f"before raising a exception USER => SUP we must adjust the RPROD REG")
            print(f"{hex(fuzzerstate.pagetablestate.vmem_base_list[fuzzerstate.real_curr_layout][fuzzerstate.privilegestate.prev_privstate] | 0x7fffffff)}")
            print(f"{hex(fuzzerstate.pagetablestate.vmem_base_list[fuzzerstate.real_curr_layout][fuzzerstate.privilegestate.privstate] | 0x7fffffff)}")
            print(f"offset in rprod will be: {hex(user_sup_offset)}")
            assert False, f"We do not support deleguation if the top 32 bit of RPROD change from user to supervisor mode yet"


    # Generate depending on the exception type.
    if exception_op_type == ExceptionCauseVal.ID_INSTR_ADDR_MISALIGNED:
        if DO_ASSERT:
            assert not fuzzerstate.design_has_compressed_support, "Compressed instructions are supported, so no instruction address misalignment can occur."
        # The instruction misalignment will always be 2 bytes, because CF instructions have a granularity of 2 bytes.
        # Select the address to load. We care about blacklisting, in the (erroneous) case where the data would have some influence.
        misaligned_tgt_addr = random.randrange(0, (fuzzerstate.memview_blacklist.memsize-1) // 4) * 4 + 2 # -1 because we dont want to have an access fault but an instruction misaligned fault here.
        if DO_ASSERT:
            assert misaligned_tgt_addr % 4 == 2
            assert misaligned_tgt_addr >= 0
            assert misaligned_tgt_addr + 4 < fuzzerstate.memview_blacklist.memsize
        # Find out the address of the instruction to be created, to make the relative jump
        jal_addr = fuzzerstate.bb_start_addr_seq[-1] + 4*len(fuzzerstate.instr_objs_seq) # NO_COMPRESSED
        # Misaligned memory accesses trigger a page fault and a misaligned address exception. Their priority and order of 
        # handling is open to the platform, therefore we can't rely on the SEPC and SCAUSE values.
        if USE_MMU:
            fuzzerstate.csrfile.regs[CSR_IDS.SEPC].unreliable = True
            fuzzerstate.csrfile.regs[CSR_IDS.SCAUSE].unreliable = True
        return SimpleExceptionEncapsulator_t0(fuzzerstate,is_mtvec, None, JALInstruction(fuzzerstate, "jal", 0, misaligned_tgt_addr - jal_addr),exception_op_type)
    elif exception_op_type == ExceptionCauseVal.ID_INSTR_ACCESS_FAULT:
        raise NotImplementedError("ID_INSTR_ACCESS_FAULT not yet supported")
    elif exception_op_type == ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION:
        return pick_illegal_instruction(is_mtvec, fuzzerstate)
    elif exception_op_type == ExceptionCauseVal.ID_BREAKPOINT:
        fuzzerstate.is_minstret_inaccurate_because_ecall_ebreak = ('rocket' in fuzzerstate.design_name and not is_tolerate_rocket_minstret()) # rocket has minstret inaccurate because of ecall/ebreak
        return SimpleExceptionEncapsulator_t0(fuzzerstate,is_mtvec, None, EcallEbreakInstruction(fuzzerstate,"ebreak"),exception_op_type)
    elif exception_op_type == ExceptionCauseVal.ID_LOAD_ADDR_MISALIGNED:
        if DO_ASSERT:
            assert fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PAGE_ADDR) or fuzzerstate.privilegestate.privstate in fuzzerstate.taint_sink_privs and fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PAGE_T0_ADDR)
            assert fuzzerstate.design_has_misaligned_data_support
        # Misaligned memory accesses trigger a page fault and a misaligned address exception. Their priority and order of 
        # handling is open to the platform, therefore we can't rely on the SEPC and SCAUSE values.
        if USE_MMU:
            fuzzerstate.csrfile.regs[CSR_IDS.SEPC].unreliable = True
            fuzzerstate.csrfile.regs[CSR_IDS.SCAUSE].unreliable = True
        return SimpleExceptionEncapsulator_t0(fuzzerstate,is_mtvec,None,MisalignedMemInstruction_t0(fuzzerstate, is_mtvec, True),exception_op_type)
    elif exception_op_type == ExceptionCauseVal.ID_LOAD_ACCESS_FAULT:
        raise NotImplementedError("ID_LOAD_ACCESS_FAULT not yet supported")
    elif exception_op_type == ExceptionCauseVal.ID_STORE_AMO_ADDR_MISALIGNED:
        if DO_ASSERT:
            assert fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PAGE_ADDR) or fuzzerstate.privilegestate.privstate in fuzzerstate.taint_sink_privs and fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PAGE_T0_ADDR)
        # Misaligned memory accesses trigger a page fault and a misaligned address exception. Their priority and order of 
        # handling is open to the platform, therefore we can't rely on the SEPC and SCAUSE values.
        if USE_MMU:
            fuzzerstate.csrfile.regs[CSR_IDS.SEPC].unreliable = True
            fuzzerstate.csrfile.regs[CSR_IDS.SCAUSE].unreliable = True
        return SimpleExceptionEncapsulator_t0(fuzzerstate,is_mtvec,None, MisalignedMemInstruction_t0(fuzzerstate, is_mtvec, False), exception_op_type)
    elif exception_op_type == ExceptionCauseVal.ID_STORE_AMO_ACCESS_FAULT:
        raise NotImplementedError("ID_STORE_AMO_ACCESS_FAULT not yet supported")
    elif exception_op_type == ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_U_MODE:
        if DO_ASSERT:
            assert fuzzerstate.privilegestate.prev_privstate == PrivilegeStateEnum.USER
        fuzzerstate.is_minstret_inaccurate_because_ecall_ebreak = ('rocket' in fuzzerstate.design_name and not is_tolerate_rocket_minstret()) # rocket has minstret inaccurate because of ecall/ebreak
        return SimpleExceptionEncapsulator_t0(fuzzerstate,is_mtvec, None, EcallEbreakInstruction(fuzzerstate,"ecall"),exception_op_type)
    elif exception_op_type == ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_S_MODE:
        if DO_ASSERT:
            assert fuzzerstate.privilegestate.prev_privstate == PrivilegeStateEnum.SUPERVISOR
        fuzzerstate.is_minstret_inaccurate_because_ecall_ebreak = ('rocket' in fuzzerstate.design_name and not is_tolerate_rocket_minstret()) # rocket has minstret inaccurate because of ecall/ebreak
        return SimpleExceptionEncapsulator_t0(fuzzerstate,is_mtvec, None, EcallEbreakInstruction(fuzzerstate,"ecall"),exception_op_type)
    elif exception_op_type == ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_M_MODE:
        if DO_ASSERT:
            assert fuzzerstate.privilegestate.prev_privstate == PrivilegeStateEnum.MACHINE
        fuzzerstate.is_minstret_inaccurate_because_ecall_ebreak = ('rocket' in fuzzerstate.design_name and not is_tolerate_rocket_minstret()) # rocket has minstret inaccurate because of ecall/ebreak
        return SimpleExceptionEncapsulator_t0(fuzzerstate,is_mtvec, None, EcallEbreakInstruction(fuzzerstate,"ecall"),exception_op_type)
    elif exception_op_type == ExceptionCauseVal.ID_INSTRUCTION_PAGE_FAULT:
        raise NotImplementedError("ID_INSTRUCTION_PAGE_FAULT not yet supported")
    elif exception_op_type == ExceptionCauseVal.ID_LOAD_PAGE_FAULT:
        if DO_ASSERT:
            assert fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PAGE_T0_ADDR)
            assert fuzzerstate.privilegestate.prev_privstate not in fuzzerstate.taint_source_privs or fuzzerstate.effective_prev_layout not in fuzzerstate.taint_source_layouts # we only do page faults to tainted pages
        instr_str = random.choice([i for i in IntLoadInstruction_t0.authorized_instr_strs if not i.startswith("c")])
        alignment = 1 if "lb" in instr_str else 2 if "lh" in instr_str else 4 if "lw" in instr_str else 8 if "ld" in instr_str else None
        assert alignment is not None, f"Invalid instr_str: {instr_str}"
        imm = random.randrange(-PHYSICAL_PAGE_SIZE//2,PHYSICAL_PAGE_SIZE//2, alignment)
        rs1 = fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.PAGE_T0_ADDR)
        # RD needs to be a free register. Otherwise, it might be set free, but not actually be free because it's not overwritten.
        rd = fuzzerstate.intregpickstate.pick_int_inputreg() 
        return SimpleExceptionEncapsulator_t0(fuzzerstate,is_mtvec, None, IntLoadInstruction_t0(fuzzerstate, instr_str, rd, rs1, imm, None, False),exception_op_type)

    elif exception_op_type == ExceptionCauseVal.ID_STORE_AMO_PAGE_FAULT:
        raise NotImplementedError("ID_STORE_AMO_PAGE_FAULT not yet supported")

###
# Exposed functions
###

# Has the side effect of consuming a tvec
# @return a CFInstructionType that will cause an exception on this design.
def gen_exception_instr(fuzzerstate):
    exception_op_type = _gen_next_exceptionoptype(fuzzerstate)
    instr_objs = []
    if TAINT_EN:
        if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE:
            is_mtvec = True
        else:
            if DO_ASSERT:
                assert fuzzerstate.privilegestate.medeleg_val is not None
            is_mtvec = not (fuzzerstate.privilegestate.medeleg_val & (1 << exception_op_type.value))

        # We untaint the registers if we either delegate the exception to a privilege that does not have taint access, or we do not delegate and M mode does not have taint access.
        if not is_mtvec and (PrivilegeStateEnum.SUPERVISOR not in fuzzerstate.taint_source_privs or fuzzerstate.effective_curr_layout not in fuzzerstate.taint_source_layouts) or is_mtvec and PrivilegeStateEnum.MACHINE not in fuzzerstate.taint_source_privs:
            instr_objs += clear_taints_with_random_instructions(fuzzerstate, untaint_all=True)
    instr_objs += [gen_next_exception_instr_from_instroptype(fuzzerstate, exception_op_type)]
    fuzzerstate.intregpickstate.free_pageregs()
    return instr_objs


###
# Other exposed functions
# Generating tvec and medeleg
###

# @brief this function generates an instruction that will fill the tvec with the provided value.
# @return a CFInstructionType that will fill the tvec with the provided value.
def gen_tvecfill_instr(fuzzerstate):

    can_populate_mtvec = fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE and not fuzzerstate.privilegestate.is_mtvec_populated
    can_populate_stvec = ((fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR) or \
                            (fuzzerstate.design_has_supervisor_mode and fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE)) \
                            and not fuzzerstate.privilegestate.is_stvec_populated

    if DO_ASSERT:
        assert can_populate_mtvec or can_populate_stvec

    is_mtvec = True # If True, then mtvec, else stvec

    # Choose between mtvec and stvec
    if can_populate_mtvec:
        if can_populate_stvec:
            is_mtvec = random.random() < 0.5
        else:
            is_mtvec = True
    else:
        is_mtvec = False

    # Get some consumed register
    rs1 = fuzzerstate.intregpickstate.pick_untainted_int_reg_in_state(IntRegIndivState.CONSUMED)
    producer_id = fuzzerstate.intregpickstate.get_producer_id(rs1)
    fuzzerstate.intregpickstate.set_regstate(rs1, IntRegIndivState.RELOCUSED)

    # If this is the first write to the reg, then the reset val should be ignored
    if is_mtvec:
        if fuzzerstate.privilegestate.is_mtvec_still_reset_val:
            fuzzerstate.privilegestate.is_mtvec_still_reset_val = False
            rd = 0
        else:
            rd = fuzzerstate.intregpickstate.pick_int_outputreg()
        fuzzerstate.privilegestate.is_mtvec_populated = True
    else:
        if fuzzerstate.privilegestate.is_stvec_still_reset_val:
            fuzzerstate.privilegestate.is_stvec_still_reset_val = False
            rd = 0
        else:
            rd = fuzzerstate.intregpickstate.pick_int_outputreg()
        fuzzerstate.privilegestate.is_stvec_populated = True
    
    # if rd > 0 and fuzzerstate.csrfile.regs[CSR_IDS.MTVEC].unreliable and is_mtvec or fuzzerstate.csrfile.regs[CSR_IDS.STVEC].unreliable and not is_mtvec:
    #     fuzzerstate.intregpickstate.set_regstate(rd, IntRegIndivState.RELOCUSED, force=True)
    # if rs1 > 0:
    #     fuzzerstate.intregpickstate.set_regstate(rs1, IntRegIndivState.RELOCUSED, force=True)
    #     if is_mtvec:
    #         fuzzerstate.csrfile.regs[CSR_IDS.MTVEC].unreliable = True
    #     else:
    #         fuzzerstate.csrfile.regs[CSR_IDS.STVEC].unreliable = True
    # TODO: use above, would be cleaner
    if rd > 0:
        fuzzerstate.intregpickstate.set_regstate(rd, IntRegIndivState.RELOCUSED, force=True)
    return TvecWriterInstruction_t0(fuzzerstate,is_mtvec, rd, rs1, producer_id)

# @brief this function generates an instruction that will fill the epc with the provided value.
# @return a CFInstructionType that will fill the epc with the provided value.
def gen_epcfill_instr(fuzzerstate):
    if DO_ASSERT:
        assert fuzzerstate.privilegestate.privstate != PrivilegeStateEnum.USER
        assert not (fuzzerstate.privilegestate.is_mepc_populated and fuzzerstate.privilegestate.is_sepc_populated)

    can_populate_mepc = fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE and not fuzzerstate.privilegestate.is_mepc_populated
    can_populate_sepc = ((fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR) or \
                            (fuzzerstate.design_has_supervisor_mode and fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE)) \
                            and not fuzzerstate.privilegestate.is_sepc_populated

    if DO_ASSERT:
        assert can_populate_mepc or can_populate_sepc

    is_mepc = True # If True, then mepc, else sepc

    # Choose between mepc and sepc, if one is already populated, make the other, we want to avoid making too many
    if (fuzzerstate.privilegestate.is_mepc_populated or fuzzerstate.privilegestate.is_sepc_populated) and (can_populate_mepc and can_populate_sepc):
        if fuzzerstate.privilegestate.is_mepc_populated:
            is_mepc = False
    else:
        if can_populate_mepc:
            if can_populate_sepc:
                is_mepc = random.random() < 0.5
            else:
                is_mepc = True
        else:
            is_mepc = False


    # Get some consumed register
    rs1 = fuzzerstate.intregpickstate.pick_untainted_int_reg_in_state(IntRegIndivState.CONSUMED)
    producer_id = fuzzerstate.intregpickstate.get_producer_id(rs1)
    fuzzerstate.intregpickstate.set_regstate(rs1, IntRegIndivState.RELOCUSED)

    # If this is the first write to the reg, then the reset val should be ignored
    if is_mepc:
        if fuzzerstate.privilegestate.is_mepc_still_reset_val:
            fuzzerstate.privilegestate.is_mepc_still_reset_val = False
            rd = 0
        else:
            rd = fuzzerstate.intregpickstate.pick_int_outputreg()
        fuzzerstate.privilegestate.is_mepc_populated = True
    else:
        if fuzzerstate.privilegestate.is_sepc_still_reset_val:
            fuzzerstate.privilegestate.is_sepc_still_reset_val = False
            rd = 0
        else:
            rd = fuzzerstate.intregpickstate.pick_int_outputreg()
        fuzzerstate.privilegestate.is_sepc_populated = True

    # if rd > 0 and fuzzerstate.csrfile.regs[CSR_IDS.MEPC].unreliable and is_mepc or fuzzerstate.csrfile.regs[CSR_IDS.SEPC].unreliable and not is_mepc:
    #     fuzzerstate.intregpickstate.set_regstate(rd, IntRegIndivState.RELOCUSED, force=True)
    # if rs1 > 0:
    #     fuzzerstate.intregpickstate.set_regstate(rs1, IntRegIndivState.RELOCUSED, force=True)
    #     if is_mepc:
    #         fuzzerstate.csrfile.regs[CSR_IDS.MEPC].unreliable = True
    #     else:
    #         fuzzerstate.csrfile.regs[CSR_IDS.MEPC].unreliable = True

    # TODO: use above, would be cleaner
    if rd > 0:
        fuzzerstate.intregpickstate.set_regstate(rd, IntRegIndivState.RELOCUSED, force=True)

    return EPCWriterInstruction_t0(fuzzerstate, is_mepc, rd, rs1, producer_id)

# @brief this function generates an instruction that will fill the xPP field of mstatus with the provided value.
# @return a CFInstructionType that will fill the xPP field of mstatus with the provided value.
def gen_ppfill_instrs(fuzzerstate):
    if DO_ASSERT:
        assert fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE, "The function gen_ppfill_instrs should only be called in machine mode. Currently in " + str(fuzzerstate.privilegestate.privstate)

    # Technically, spp can be written even if supervisor mode does not exist. But leave this detail for the FUTURE.
    if fuzzerstate.design_has_supervisor_mode:
        is_mpp = random.random() < 0.5
    else:
        is_mpp = True

    # Ignore the return value of mstatus for now
    rd = 0

    # rd = fuzzerstate.intregpickstate.pick_int_outputreg()

    # Choose the target. It should be a valid target.
    if is_mpp:
        if not fuzzerstate.design_has_supervisor_mode and not fuzzerstate.design_has_user_mode or fuzzerstate.real_curr_layout == -1:
            target_privlvl = PrivilegeStateEnum.MACHINE
        elif fuzzerstate.design_has_supervisor_mode and not fuzzerstate.design_has_user_mode:
            # target_privlvl = random.choice([PrivilegeStateEnum.SUPERVISOR, PrivilegeStateEnum.MACHINE])
            target_privlvl = PrivilegeStateEnum.SUPERVISOR
        elif not fuzzerstate.design_has_supervisor_mode and fuzzerstate.design_has_user_mode:
            # target_privlvl = random.choice([PrivilegeStateEnum.USER, PrivilegeStateEnum.MACHINE])
            target_privlvl = PrivilegeStateEnum.USER
        else:
            target_privlvl = None
            ran_in_taint_sink = False
            for priv in fuzzerstate.taint_sink_privs: # If we did not execute in any taink sink privileges yet, choose it.
                if fuzzerstate.n_instr_in_priv[priv] != 0:
                    ran_in_taint_sink = True
            
            ran_in_taint_source = False
            for priv in fuzzerstate.taint_source_privs: # If we did not execute in all leakage source privileges yet, prefer those.
                if fuzzerstate.n_instr_in_priv[priv] != 0:
                    ran_in_taint_source = True

            if ran_in_taint_sink and ran_in_taint_source or not ran_in_taint_sink and not ran_in_taint_source:
                target_privlvl = random.choice(list(fuzzerstate.taint_sink_privs | fuzzerstate.taint_source_privs))
            elif ran_in_taint_sink and not ran_in_taint_source:
                target_privlvl = random.choice(list(fuzzerstate.taint_source_privs))
            elif ran_in_taint_source and not ran_in_taint_sink:
                target_privlvl = random.choice(list(fuzzerstate.taint_sink_privs))

    else:
        if fuzzerstate.design_has_user_mode:
            target_privlvl = random.choice([PrivilegeStateEnum.USER, PrivilegeStateEnum.SUPERVISOR])
        else:
            target_privlvl = PrivilegeStateEnum.SUPERVISOR

    if is_mpp:
        if target_privlvl == PrivilegeStateEnum.USER:
            ret = [CSRRegInstruction_t0(fuzzerstate,"csrrc", rd, MPP_BOTH_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS, False, (False,None), PrivilegeStateEnum.USER)]
        elif target_privlvl == PrivilegeStateEnum.SUPERVISOR:
            # Could theretically be done in a single instruction if we had one more mask register.
            ret =  [CSRRegInstruction_t0(fuzzerstate,"csrrs", rd, MPP_BOTH_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS, False, (False,None), PrivilegeStateEnum.SUPERVISOR), 
                    CSRRegInstruction_t0(fuzzerstate,"csrrc", rd, MPP_TOP_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS,False, (False,None), PrivilegeStateEnum.SUPERVISOR)]
        elif target_privlvl == PrivilegeStateEnum.MACHINE:
            ret = [CSRRegInstruction_t0(fuzzerstate,"csrrs", rd, MPP_BOTH_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS,False, (False,None), PrivilegeStateEnum.MACHINE)]
        else:
            raise NotImplementedError("Hypervisor mode not implemented")
    else:
        if target_privlvl == PrivilegeStateEnum.USER:
            ret = [CSRRegInstruction_t0(fuzzerstate,"csrrc", rd, SPP_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS, False, (False,None), PrivilegeStateEnum.USER)]
        elif target_privlvl == PrivilegeStateEnum.SUPERVISOR:
            ret = [CSRRegInstruction_t0(fuzzerstate,"csrrs", rd, SPP_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS,False, (False,None), PrivilegeStateEnum.SUPERVISOR)]
        else:
            raise Exception("Invalid target privlvl when setting spp")

    # Update the mpp/spp in our bookkeeping
    if is_mpp:
        fuzzerstate.privilegestate.curr_mstatus_mpp = target_privlvl
    else:
        fuzzerstate.privilegestate.curr_mstatus_spp = target_privlvl
    return ret

# @brief this function generates an instruction that will fill medeleg with the provided value.
# @return a CFInstructionType that will fill the tvec with the provided value.
def gen_medeleg_instr(fuzzerstate):
    from common.profiledesign import get_medeleg_mask
    
    if DO_ASSERT:
        assert fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE

    # Random values for both the supported and unsupported bits, but only for the CPU.
    val_to_write_spike = 0
    val_to_write_cpu   = 0
    supported_medeleg_bits = get_medeleg_mask(fuzzerstate.design_name)
    supported_medeleg_bits &= SPIKE_MEDELEG_MASK
    supported_medeleg_bits_arr = []
    while supported_medeleg_bits:
        supported_medeleg_bits_arr.append(supported_medeleg_bits & 1)
        supported_medeleg_bits >>= 1
    del supported_medeleg_bits
    # print('Supported medeleg bits', supported_medeleg_bits_arr)
    for bit_id, bit_val in enumerate(supported_medeleg_bits_arr):
        # The line below is a cool idea but makes the analysis more difficult, so we don't do it for now and we AND with bit_val
        # random_bit = random.randint(0, 1) # If this exception type is supported by the CPU, then the bit must be the same in Spike and in the CPU
        random_bit = random.randint(0, 1)
        # If the bit is not supported by the CPU, set it to 0 for Spike, but set it randomly for the CPU.
        if bit_val == 1:
            val_to_write_spike |= random_bit << bit_id
            val_to_write_cpu |= random_bit << bit_id


    # Get some consumed register
    rs1 = fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
    producer_id = fuzzerstate.intregpickstate.get_producer_id(rs1)
    fuzzerstate.intregpickstate.set_regstate(rs1, IntRegIndivState.RELOCUSED)

    if fuzzerstate.privilegestate.medeleg_val is None:
        rd = 0 # The reset value of medeleg differ between spike and the CPU. # FUTURE we can get any and call it POLLUTED
    else:
        rd = fuzzerstate.intregpickstate.pick_int_outputreg()

    # Update the delegated state in our model, -> this is now updated when the instruction is executed.
    fuzzerstate.privilegestate.medeleg_val = val_to_write_spike
    if rd > 0:
        fuzzerstate.intregpickstate.set_regstate(rd, IntRegIndivState.RELOCUSED, force=True) # MEDLEG changes between spike and final elf, so cannot be used for taint computation
    return GenericCSRWriterInstruction_t0(fuzzerstate, CSR_IDS.MEDELEG, rd, rs1, producer_id, val_to_write_spike, val_to_write_cpu)

# @brief function to set/unsed the SUM/MPRV bits in mstatus
def gen_sum_mprv_op(fuzzerstate):
    # TODO, we can change the SUM bit in mstatus as well, we should randomly choose if we are in M mode, and use sstatus if in S mode

    # First we randomly choose the state of SUM and MPRV, maybe we should set it to the opposite 
    # Is it a clear or a set
    if random.randint(0, 1) :
        instr_str = "csrrc"
        is_set = False
    else:
        instr_str = "csrrs"
        is_set = True

    old_sum, old_mprv = fuzzerstate.status_sum_mprv
    if random.randint(0, 1):
        mstatus_mask = (1 << 18) ^ SPIKE_STARTADDR # SUM, SPIKE_STARTADDR hack to avoid adding it later
        fuzzerstate.status_sum_mprv = is_set, old_mprv
    else:
        mstatus_mask = (1 << 17) ^ SPIKE_STARTADDR # MPRV, SPIKE_STARTADDR hack to avoid adding it later
        fuzzerstate.status_sum_mprv = old_sum, is_set

    #TODO MXR (Make eXecutable Readable) not supported yet

    # Pick register
    #rd = fuzzerstate.intregpickstate.pick_int_outputreg()
    rs1 = fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
    producer_id = fuzzerstate.intregpickstate.get_producer_id(rs1)
    fuzzerstate.intregpickstate.set_regstate(rs1, IntRegIndivState.RELOCUSED)

    # Create the instruction and set the state
    return MstatusWriterInstruction_t0(0, rs1, producer_id, instr_str, mstatus_mask)