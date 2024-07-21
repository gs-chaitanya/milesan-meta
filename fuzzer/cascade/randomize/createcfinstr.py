# Copyright 2023 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

import random
import numpy as np

from params.runparams import DO_ASSERT, PRINT_FSM_TRANSITIONS

from params.fuzzparams import NUM_MIN_FREE_INTREGS, NUM_MIN_UNTAINTED_INTREGS, REG_FSM_WEIGHTS, NONTAKEN_BRANCH_INTO_RANDOM_DATA_PROBA, PROBA_NEW_SATP_NOT_USED, NUM_MAX_PRODUCED0_REGS, NUM_MAX_PRODUCED1_REGS, TAINT_NONTAKEN_BRANCH_IMM, TAINT_IMMRD_IMM, P_LOAD_TAINT
from params.runparams import GET_DATA
from cascade.util import IntRegIndivState, INSTRUCTIONS_BY_ISA_CLASS, ISAInstrClass
from cascade.cfinstructionclasses import *
from cascade.cfinstructionclasses_t0 import *
from cascade.toleratebugs import is_tolerate_branchpred
from cascade.spikeresolution import get_current_layout
from cascade.mmu_utils import li_doubleword, PHYSICAL_PAGE_SIZE, PAGE_ALIGNMENT_SHIFT, PAGE_ALIGNMENT_BITS, PAGE_ALIGNMENT_MASK
from rv.util import PARAM_REGTYPE, PARAM_SIZES_BITS_32, PARAM_SIZES_BITS_64
# This module creates an instruction from its instruction string, and some state which will condition which registers and immediates will be picked, and with which probability.

###
# Utility functions
###

def gen_random_imm(instr_str: str, is_design_64bit: bool):
    if DO_ASSERT:
        assert PARAM_REGTYPE[INSTRUCTION_IDS[instr_str]][-1] == ''
    if is_design_64bit:
        imm_width = PARAM_SIZES_BITS_64[INSTRUCTION_IDS[instr_str]][-1]
    else:
        imm_width = PARAM_SIZES_BITS_32[INSTRUCTION_IDS[instr_str]][-1]
    if PARAM_IS_SIGNED[INSTRUCTION_IDS[instr_str]][-1]:
        left_bound  = -(1<<(imm_width-1))
        right_bound = 1<<(imm_width-1)
    else:
        left_bound  = 0
        right_bound = 1<<imm_width
    return random.randrange(left_bound, right_bound)

def gen_random_imm_t0(instr_str: str, fuzzerstate):
    n_free_untainted_regs = fuzzerstate.intregpickstate.get_num_untainted_regs_in_state(IntRegIndivState.FREE)
    n_relocused_tainted_regs = fuzzerstate.intregpickstate.get_num_tainted_regs_in_state(IntRegIndivState.RELOCUSED)
    assert n_relocused_tainted_regs == 0 # Relocused regs are excluded from taint propagation, thus this should always be zero
    if n_free_untainted_regs > NUM_MIN_UNTAINTED_INTREGS: #  we can still taint some more
        return gen_random_imm(instr_str, fuzzerstate.is_design_64bit)
    else:
        return 0x0

# For when the randomnees must be separated from program construction.
# This facilitates bug enabling/disabling because it can be ensured that the remaining program remaing unchanged,
# while only the portion that triggers the bug is modified.
def gen_random_imm_from_rng(rng: np.random.RandomState, instr_str: str, is_design_64bit: bool):
    if DO_ASSERT:
        assert PARAM_REGTYPE[INSTRUCTION_IDS[instr_str]][-1] == ''
    if is_design_64bit:
        imm_width = PARAM_SIZES_BITS_64[INSTRUCTION_IDS[instr_str]][-1]
    else:
        imm_width = PARAM_SIZES_BITS_32[INSTRUCTION_IDS[instr_str]][-1]
    if PARAM_IS_SIGNED[INSTRUCTION_IDS[instr_str]][-1]:
        left_bound  = -(1<<(imm_width-1))
        right_bound = 1<<(imm_width-1)
    else:
        left_bound  = 0
        right_bound = 1<<imm_width
    return rng.randint(left_bound, right_bound)

# Random rounding modes
def gen_random_rounding_mode():
    return random.sample([0, 1, 2, 3, 4, 7], 1)[0]

###
# Functions for creation by CFInstructionClass
###

# Integer instructions

def _create_R12DInstruction(instr_str: str, fuzzerstate, iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in R12DInstructions
    rs1, rs2 = tuple(fuzzerstate.intregpickstate.pick_tainted_int_inputregs(2))
    rd = fuzzerstate.intregpickstate.pick_untainted_int_outputreg_nonzero()
    return R12DInstruction_t0(fuzzerstate, instr_str, rd, rs1, rs2, iscompressed)

def _create_ImmRdInstruction(instr_str: str, fuzzerstate, iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in ImmRdInstructions

    imm = gen_random_imm(instr_str, fuzzerstate.is_design_64bit)    

    if fuzzerstate.privilegestate.privstate in fuzzerstate.taint_in_priv and "auipc" not in instr_str:
        n_free_untainted_regs = fuzzerstate.intregpickstate.get_num_untainted_regs_in_state(IntRegIndivState.FREE)
        if n_free_untainted_regs < NUM_MIN_UNTAINTED_INTREGS: # There's too much taint, remove some.
            imm_t0 = 0 
            rd = fuzzerstate.intregpickstate.pick_tainted_int_outputreg()
        else:
            if TAINT_IMMRD_IMM:
                imm_t0 = gen_random_imm_t0(instr_str, fuzzerstate)
            else:
                imm_t0 = 0
            rd = fuzzerstate.intregpickstate.pick_untainted_int_outputreg_nonzero()
    else:
        imm_t0 = 0
        rd = fuzzerstate.intregpickstate.pick_int_outputreg_nonzero()


    if rd > 0:
        fuzzerstate.intregpickstate.set_regstate(rd, IntRegIndivState.FREE)

    return ImmRdInstruction_t0(fuzzerstate,instr_str, rd, imm, imm_t0, iscompressed)

def _create_RegImmInstruction(instr_str: str, fuzzerstate, iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in RegImmInstructions

    
    imm = gen_random_imm(instr_str, fuzzerstate.is_design_64bit)

    if fuzzerstate.privilegestate.privstate in fuzzerstate.taint_in_priv:
        n_free_untainted_regs = fuzzerstate.intregpickstate.get_num_untainted_regs_in_state(IntRegIndivState.FREE)
        if n_free_untainted_regs < NUM_MIN_UNTAINTED_INTREGS: # There's too much taint, remove some.
            imm_t0 = 0 
            rs1 = fuzzerstate.intregpickstate.pick_untainted_int_inputreg(force=True)
            rd = fuzzerstate.intregpickstate.pick_tainted_int_outputreg()
        else:
            if TAINT_IMMRD_IMM:
                imm_t0 = gen_random_imm_t0(instr_str, fuzzerstate)
            else:
                imm_t0 = 0
            rs1 = fuzzerstate.intregpickstate.pick_tainted_int_inputreg()
            rd = fuzzerstate.intregpickstate.pick_untainted_int_outputreg_nonzero()
    else:
        imm_t0 = 0
        rs1 = fuzzerstate.intregpickstate.pick_int_inputreg()
        rd = fuzzerstate.intregpickstate.pick_int_outputreg_nonzero()


    return RegImmInstruction_t0(fuzzerstate, instr_str, rd, rs1, imm, imm_t0, iscompressed)


def _create_BranchInstruction(instr_str: str, fuzzerstate, curr_addr: int, iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in BranchInstructions
    rs1, rs2 = tuple(fuzzerstate.intregpickstate.pick_untainted_int_inputregs(2, force=True))
    plan_taken = fuzzerstate.curr_branch_taken
    if fuzzerstate.is_design_64bit:
        curr_param_size = PARAM_SIZES_BITS_64[INSTRUCTION_IDS[instr_str]][-1]
    else:
        curr_param_size = PARAM_SIZES_BITS_32[INSTRUCTION_IDS[instr_str]][-1]
    # The rng should have randomness that follows from the system random state but not have any reciprocal effects
    # This is necessary s.t. the bugs can be enabled/disabled without further influencing program construction
    # except unavoidable sideeffects due to change in data-flow

    rng = np.random.RandomState(random.randrange(0,2**31)) 
    if plan_taken:
        # print('A', flush=True)
        imm = fuzzerstate.next_bb_addr-curr_addr
    else: # The non-taken branches still have microarchitectual effects we need to account for.
        # Select whether to direct toward a random data basic block. This might (speculatively) load
        # random data into the BPUs.
        is_random_data_block_in_reach = False
        for addr_pair in fuzzerstate.random_data_block_ranges:
            is_random_data_block_in_reach |= abs(addr_pair[0] - curr_addr) < (1<<11) and abs(addr_pair[1] - 4 - curr_addr) < (1<<11)
        if is_random_data_block_in_reach and random.random() < NONTAKEN_BRANCH_INTO_RANDOM_DATA_PROBA:
            target_addr =  None
            # TODO do we need to modify this for virtual addresses? Think not since we can't jump further than a page anyway
            while target_addr is None or (fuzzerstate.memview.is_cl_tainted(curr_addr+imm+SPIKE_STARTADDR) and not is_tolerate_branchpred(fuzzerstate.design_name)):
                target_addr = fuzzerstate.memview.gen_random_addr_from_randomblock_from_rng(rng,2,4)
                imm = (target_addr - curr_addr)&((1<<curr_param_size-1)-1)

        else:
            imm = None
            while imm is None or (fuzzerstate.memview.is_cl_tainted(curr_addr+imm+SPIKE_STARTADDR) and not is_tolerate_branchpred(fuzzerstate.design_name)):
                imm = gen_random_imm_from_rng(rng, instr_str, fuzzerstate.is_design_64bit)

    if DO_ASSERT:
            assert is_tolerate_branchpred(fuzzerstate.design_name) or not fuzzerstate.memview.is_cl_tainted(curr_addr+imm+SPIKE_STARTADDR), f"Chose tainted CL at {hex(curr_addr+imm+SPIKE_STARTADDR)} (plan_taken: {plan_taken}, is_random_data_block_in_reach: {is_random_data_block_in_reach})"
    
    imm_t0 = 0
    if TAINT_NONTAKEN_BRANCH_IMM:
        if TAINT_EN and not plan_taken and random.random() < 0.5 and fuzzerstate.privilegestate.privstate in fuzzerstate.taint_in_priv:
            imm_t0 = random.randint(0, 1<<curr_param_size)
    instr = BranchInstruction_t0(fuzzerstate, instr_str, rs1, rs2, imm, imm_t0, plan_taken, iscompressed)
    return instr
    
def _create_JALInstruction(instr_str: str, fuzzerstate, curr_addr: int, iscompressed: bool):
    rd = fuzzerstate.intregpickstate.pick_untainted_int_outputreg()
    imm = fuzzerstate.next_bb_addr-curr_addr
    if rd > 0:
        fuzzerstate.intregpickstate.set_regstate(rd, IntRegIndivState.FREE)
    return JALInstruction_t0(fuzzerstate, instr_str, rd, imm, iscompressed)

def _create_JALRInstruction(instr_str: str, fuzzerstate, iscompressed: bool, curr_addr: int = None): # curr_addr for compatibility in _create_spectre_gadget_instrobjs 
    assert curr_addr is None
    rs1 = fuzzerstate.intregpickstate.pick_untainted_int_reg_in_state(IntRegIndivState.CONSUMED, force = True)
    assert not fuzzerstate.intregpickstate.regs[rs1].get_val_t0(), f"rs1 {ABI_INAMES[rs1]} for JALR is tainted!"
    rd = fuzzerstate.intregpickstate.pick_untainted_int_outputreg()
    imm = 0
    producer_id = fuzzerstate.intregpickstate.get_producer_id(rs1)
    fuzzerstate.intregpickstate.set_regstate(rs1, IntRegIndivState.RELOCUSED)
    if rd > 0:
        fuzzerstate.intregpickstate.set_regstate(rd, IntRegIndivState.FREE)
    if DO_ASSERT:
        assert producer_id > 0
    return JALRInstruction_t0(fuzzerstate, instr_str, rd, rs1, imm, producer_id, iscompressed)

def _create_SpecialInstruction(instr_str: str, fuzzerstate, iscompressed: bool):
    rd = fuzzerstate.intregpickstate.pick_int_outputreg(authorize_sideeffects=False) # The fence instructions don't write to rd, thus we don't set them free.
    rs1 = fuzzerstate.intregpickstate.pick_int_inputreg()
    return SpecialInstruction_t0(fuzzerstate, instr_str, rd, rs1)

def _create_IntLoadInstruction(instr_str: str, fuzzerstate, iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in IntLoadInstructions
        if fuzzerstate.privilegestate.privstate in fuzzerstate.taint_in_priv:
            assert fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PAGE_T0_ADDR)
        else:
            assert fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PAGE_ADDR)

    if TAINT_EN:
        if fuzzerstate.privilegestate.privstate in fuzzerstate.taint_in_priv:
            if fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PAGE_ADDR):
                taint = random.random() < P_LOAD_TAINT
            else:
                taint = True
        else:
            taint = False
    rs1 = fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.PAGE_T0_ADDR if taint else IntRegIndivState.PAGE_ADDR)
    rd = fuzzerstate.intregpickstate.pick_int_outputreg()
    alignment = 1 if instr_str in ["lb","lbu"] else 2 if instr_str in ["lh","lhu"] else 4 if instr_str in ["lw","lwu"] else 8 if instr_str == "ld" else None
    assert alignment is not None, f"Invalid instr_str: {instr_str}"
    imm = random.randrange(-PHYSICAL_PAGE_SIZE//2,PHYSICAL_PAGE_SIZE//2, alignment)

    return IntLoadInstruction_t0(fuzzerstate, instr_str, rd, rs1, imm, None, iscompressed)

def _create_IntStoreInstruction(instr_str: str, fuzzerstate, iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in IntStoreInstructions
        if fuzzerstate.privilegestate.privstate in fuzzerstate.taint_in_priv:
            assert fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PAGE_T0_ADDR)
        else:
            assert fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PAGE_ADDR)

    if TAINT_EN:
        taint = fuzzerstate.privilegestate.privstate in fuzzerstate.taint_in_priv
    rs1 = fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.PAGE_T0_ADDR if taint else IntRegIndivState.PAGE_ADDR)
    rs2 = fuzzerstate.intregpickstate.pick_int_inputreg()
    alignment = 1 if instr_str == "sb" else 2 if instr_str == "sh" else 4 if instr_str == "sw" else 8 if instr_str == "sd" else None
    assert alignment is not None, f"Invalid instr_str: {instr_str}"
    imm = random.randrange(-PHYSICAL_PAGE_SIZE//2,PHYSICAL_PAGE_SIZE//2, alignment)

    return IntStoreInstruction_t0(fuzzerstate, instr_str, rs1, rs2, imm, None, iscompressed)

# Floating-point instructions

def _create_FloatLoadInstruction  (instr_str: str, fuzzerstate, iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in FloatLoadInstructions
    rs1 = fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
    frd = fuzzerstate.floatregpickstate.pick_float_outputreg()
    imm = 0
    producer_id = fuzzerstate.intregpickstate.get_producer_id(rs1)
    fuzzerstate.intregpickstate.set_regstate(rs1, IntRegIndivState.FREE)
    if DO_ASSERT:
        assert producer_id > 0
    return FloatLoadInstruction(fuzzerstate, instr_str, frd, rs1, imm, producer_id, iscompressed)
def _create_FloatStoreInstruction (instr_str: str, fuzzerstate, iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in FloatStoreInstructions
    rs1 = fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
    frs2 = fuzzerstate.floatregpickstate.pick_float_inputreg()
    imm = 0
    producer_id = fuzzerstate.intregpickstate.get_producer_id(rs1)
    fuzzerstate.intregpickstate.set_regstate(rs1, IntRegIndivState.FREE)
    if DO_ASSERT:
        assert producer_id > 0
    return FloatStoreInstruction(fuzzerstate, instr_str, rs1, frs2, imm, producer_id, iscompressed)
def _create_FloatToIntInstruction (instr_str: str, fuzzerstate, iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in FloatToIntInstructions
    rm = gen_random_rounding_mode()
    frs1 = fuzzerstate.floatregpickstate.pick_float_inputreg()
    rd = fuzzerstate.intregpickstate.pick_int_outputreg()
    return FloatToIntInstruction(fuzzerstate, instr_str, rd, frs1, rm, iscompressed)
def _create_IntToFloatInstruction (instr_str: str, fuzzerstate, iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in IntToFloatInstructions
    rm = gen_random_rounding_mode()
    rs1 = fuzzerstate.intregpickstate.pick_int_inputreg()
    frd = fuzzerstate.floatregpickstate.pick_float_outputreg()
    return IntToFloatInstruction(fuzzerstate, instr_str, frd, rs1, rm, iscompressed)
def _create_Float4Instruction     (instr_str: str, fuzzerstate, iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in Float4Instructions
    rm = gen_random_rounding_mode()
    frs1, frs2, frs3 = tuple(fuzzerstate.floatregpickstate.pick_float_inputregs(3))
    frd = fuzzerstate.floatregpickstate.pick_float_outputreg()
    return Float4Instruction(fuzzerstate, instr_str, frd, frs1, frs2, frs3, rm, iscompressed)
def _create_Float3Instruction     (instr_str: str, fuzzerstate, iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in Float3Instructions
    rm = gen_random_rounding_mode()
    frs1, frs2 = tuple(fuzzerstate.floatregpickstate.pick_float_inputregs(2))
    frd = fuzzerstate.floatregpickstate.pick_float_outputreg()
    return Float3Instruction(fuzzerstate, instr_str, frd, frs1, frs2, rm, iscompressed)
def _create_Float3NoRmInstruction (instr_str: str, fuzzerstate, iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in Float3NoRmInstructions
    frs1, frs2 = tuple(fuzzerstate.floatregpickstate.pick_float_inputregs(2))
    frd = fuzzerstate.floatregpickstate.pick_float_outputreg()
    return Float3NoRmInstruction(fuzzerstate, instr_str, frd, frs1, frs2, iscompressed)
def _create_Float2Instruction     (instr_str: str, fuzzerstate, iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in Float2Instructions
    rm = gen_random_rounding_mode()
    frs1 = fuzzerstate.floatregpickstate.pick_float_inputreg()
    frd = fuzzerstate.floatregpickstate.pick_float_outputreg()
    return Float2Instruction(fuzzerstate, instr_str, frd, frs1, rm, iscompressed)
def _create_FloatIntRd2Instruction(instr_str: str, fuzzerstate, iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in FloatIntRd2Instructions
    frs1, frs2 = tuple(fuzzerstate.floatregpickstate.pick_float_inputregs(2))
    rd = fuzzerstate.intregpickstate.pick_int_outputreg()
    return FloatIntRd2Instruction(fuzzerstate, instr_str, rd, frs1, frs2, iscompressed)
def _create_FloatIntRd1Instruction(instr_str: str, fuzzerstate, iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in FloatIntRd1Instructions
    frs1 = fuzzerstate.floatregpickstate.pick_float_inputreg()
    rd = fuzzerstate.intregpickstate.pick_int_outputreg()
    return FloatIntRd1Instruction(fuzzerstate, instr_str, rd, frs1, iscompressed)
def _create_FloatIntRs1Instruction(instr_str: str, fuzzerstate, iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in FloatIntRs1Instructions
    frd = fuzzerstate.floatregpickstate.pick_float_outputreg()
    rs1 = fuzzerstate.intregpickstate.pick_int_inputreg()
    return FloatIntRs1Instruction(fuzzerstate, instr_str, frd, rs1, iscompressed)

###
# Exposed function
###

def create_regfsm_instrobjs(fuzzerstate):
    # Check which reg fsm operations are doable
    doable_fsm_ops = np.zeros(3, dtype=np.int8)
    n_free_or_relocused_regs =  fuzzerstate.intregpickstate.get_num_regs_in_state(IntRegIndivState.FREE) +  fuzzerstate.intregpickstate.get_num_regs_in_state(IntRegIndivState.RELOCUSED)
    doable_fsm_ops[0] = n_free_or_relocused_regs > NUM_MIN_FREE_INTREGS
    doable_fsm_ops[1] = fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PRODUCED0)
    doable_fsm_ops[2] = fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PRODUCED1)
    doable_fsm_ops[2] &= fuzzerstate.intregpickstate.exists_untainted_reg_in_state(IntRegIndivState.FREE, allow_zero = False)

    effective_weights = doable_fsm_ops * REG_FSM_WEIGHTS
    # if not np.any(effective_weights):
    #     fuzzerstate.intregpickstate.print()
    #     print(f"n_free_or_relocused: {n_free_or_relocused_regs}")
    assert np.any(effective_weights), f"No FSM operation possible! {doable_fsm_ops}"

    if fuzzerstate.intregpickstate.get_num_regs_in_state(IntRegIndivState.PRODUCED0) > NUM_MAX_PRODUCED0_REGS:
        return create_targeted_producer1_instrobj(fuzzerstate) # PRODUCED0 -> PRODUCED1
    elif fuzzerstate.intregpickstate.get_num_regs_in_state(IntRegIndivState.PRODUCED1) > NUM_MAX_PRODUCED1_REGS:
        return create_targeted_consumer_instrobj(fuzzerstate)  # PRODUCED1 -> FREE/CONSUMED

    choice = random.choices(range(len(effective_weights)), weights=effective_weights, k=1)[0]

    if choice == 0: # FREE -> PRODUCED0
        return create_targeted_producer0_instrobj(fuzzerstate)
    elif choice == 1: # PRODUCED0 -> PRODUCED1
        return create_targeted_producer1_instrobj(fuzzerstate)
    elif choice == 2: # PRODUCED1 -> FREE/CONSUMED
        return create_targeted_consumer_instrobj(fuzzerstate)
    else:
        raise ValueError(f"Unexpected choice: `{choice}`.")

def create_targeted_producer0_instrobj(fuzzerstate):
    fuzzerstate.next_producer_id += 1
    rd = fuzzerstate.intregpickstate.pick_untainted_int_outputreg_nonzero(authorize_sideeffects=False, force = False) # Rd will be untainted after execution.
    fuzzerstate.intregpickstate.set_producer_id(rd, fuzzerstate.next_producer_id)
    # fuzzerstate.intregpickstate.set_producer1_location(rd, len(fuzzerstate.instr_objs_seq), len(fuzzerstate.instr_objs_seq[0])) # Optimization currently unused
    fuzzerstate.intregpickstate.set_regstate(rd, IntRegIndivState.PRODUCED0)
    # return [PlaceholderProducerInstr0(rd, fuzzerstate.next_producer_id, fuzzerstate.is_design_64bit)]
    # return [PlaceholderProducerInstr0_t0],[(fuzzerstate, rd, fuzzerstate.next_producer_id)]
    return [PlaceholderProducerInstr0_t0(fuzzerstate, rd, fuzzerstate.next_producer_id)]

def create_targeted_producer1_instrobj(fuzzerstate):
    rd = fuzzerstate.intregpickstate.pick_untainted_int_reg_in_state(IntRegIndivState.PRODUCED0, force = True)  # rd should not be tainted
    # assert fuzzerstate.intregpickstate.regs[rd].get_val_t0() == 0, f"Register {ABI_INAMES[rd]} in produced0 state is tainted!"
    # fuzzerstate.intregpickstate.set_producer1_location(rd, len(fuzzerstate.instr_objs_seq), len(fuzzerstate.instr_objs_seq[0])) # Optimization currently unused
    fuzzerstate.intregpickstate.set_regstate(rd, IntRegIndivState.PRODUCED1)
    # return [PlaceholderProducerInstr1(rd, fuzzerstate.intregpickstate.get_producer_id(rd), fuzzerstate.is_design_64bit)]
    # return [PlaceholderProducerInstr1_t0],[(fuzzerstate, rd, fuzzerstate.intregpickstate.get_producer_id(rd))]
    return [PlaceholderProducerInstr1_t0(fuzzerstate, rd, fuzzerstate.intregpickstate.get_producer_id(rd))]

def create_targeted_consumer_instrobj(fuzzerstate):
    rdep = fuzzerstate.intregpickstate.pick_untainted_int_inputreg_nonzero(force = True) # We want to create dependencies, therefore we choose not to accept x0. Also it should not be tainted to avoid tainting the PC.
    rprod = fuzzerstate.intregpickstate.pick_untainted_int_reg_in_state(IntRegIndivState.PRODUCED1, force = True) # Produced registers should always be untainted by construction.
    assert fuzzerstate.intregpickstate.regs[rdep].get_val_t0() == 0
    # WARNING: We CANNOT throw a PRODUCEDX into the nature because its value will change between spike and RTL.
    rd = rprod
    fuzzerstate.intregpickstate.set_regstate(rprod, IntRegIndivState.CONSUMED)
    if USE_MMU:
        fuzzerstate.intregpickstate.set_regstate(rdep, IntRegIndivState.RELOCUSED, force=True)
    if fuzzerstate.is_design_64bit:
        # return [PlaceholderPreConsumerInstr_t0, PlaceholderPreConsumerInstr_t0, PlaceholderConsumerInstr_t0], \
        # [(fuzzerstate, rprod, fuzzerstate.intregpickstate.get_producer_id(rprod), True), (fuzzerstate, rdep, fuzzerstate.intregpickstate.get_producer_id(rprod)), (fuzzerstate, rd, rdep, rprod, fuzzerstate.intregpickstate.get_producer_id(rprod))]
        return [
            PlaceholderPreConsumerInstr_t0(fuzzerstate, rprod, fuzzerstate.intregpickstate.get_producer_id(rprod), True),
            PlaceholderPreConsumerInstr_t0(fuzzerstate, rdep, fuzzerstate.intregpickstate.get_producer_id(rprod)),
            PlaceholderConsumerInstr_t0(fuzzerstate, rd, rdep, rprod, fuzzerstate.intregpickstate.get_producer_id(rprod))
        ]
    else:
        # return [PlaceholderConsumerInstr(rd, rdep, rprod, fuzzerstate.intregpickstate.get_producer_id(rprod))]
        # return [PlaceholderConsumerInstr_t0], [(fuzzerstate, rd, rdep, rprod, fuzzerstate.intregpickstate.get_producer_id(rprod))]
        return [PlaceholderConsumerInstr_t0(fuzzerstate, rd, rdep, rprod, fuzzerstate.intregpickstate.get_producer_id(rprod))]

# TODO: create exception when reading from tainted memory region from priv that does not have access
def create_memfsm_instrobjs(fuzzerstate):
    if len(fuzzerstate.instr_objs_seq[-1]):
        last_instr = fuzzerstate.instr_objs_seq[-1][-1] # We need the layout from the previous instruction
    else: # In case its the first instruciton of a block.
        last_instr = fuzzerstate.instr_objs_seq[-2][-1] # We need the layout from the previous instruction

    va_layout, priv_level = get_current_layout(last_instr, last_instr.va_layout, last_instr.priv_level)

    # if priv_level in  fuzzerstate.taint_in_priv:
    if not fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PAGE_T0_ADDR):
        tainted = True
    elif not fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PAGE_ADDR):
        tainted = False
    else:
        tainted = random.random() < 0.5
    # else:
    #     tainted = False
    addr  = fuzzerstate.memview.gen_random_page_addr_from_randomblocks(tainted=tainted)
    # print(f"Paddr: {hex(addr)}")
    assert addr is not None

    if va_layout == -1: # We don't need 64bit values in bare.
        assert not USE_MMU or priv_level == PrivilegeStateEnum.MACHINE, f"We need to be in machine mode to use bare translation when the MMU is enabled."
        if tainted:
            if not fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PAGE_T0_ADDR):
                rd = fuzzerstate.intregpickstate.pick_untainted_int_outputreg_nonzero(force = False) # Rd will be untainted after execution.
            else:
                rd =  fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.PAGE_T0_ADDR)
        else:
            if not fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PAGE_ADDR):
                rd = fuzzerstate.intregpickstate.pick_untainted_int_outputreg_nonzero(force = False) # Rd will be untainted after execution.
            else:
                rd =  fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.PAGE_ADDR)

        fuzzerstate.intregpickstate.set_regstate(rd, IntRegIndivState.PAGE_T0_ADDR if tainted else IntRegIndivState.PAGE_ADDR, force=True)
        uimm0, uimm1 = li_into_reg(to_unsigned(addr, fuzzerstate.is_design_64bit), False)
        # if fuzzerstate.intregpickstate.exists_free_intreg_in_range()
        return [
            ImmRdInstruction_t0(fuzzerstate, "lui", rd, uimm0),
            RegImmInstruction_t0(fuzzerstate, "addi",rd,rd,uimm1),
            R12DInstruction_t0(fuzzerstate, "xor",rd,rd,RELOCATOR_REGISTER_ID),
        ]

    else: # if we use the MMU, we need to get the virtual address and use one extra instruction to set up the 64 bit vaddress.
        assert priv_level != PrivilegeStateEnum.MACHINE, f"We can't be in machine mode and use vaddr translation."
        if tainted:
            if not fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PAGE_T0_ADDR):
                (rd,tmp) = fuzzerstate.intregpickstate.pick_untainted_int_outputregs_nonzero(2,force = False) # Rd and tmp will be untainted after execution.
            else:
                rd =  fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.PAGE_T0_ADDR)
                tmp =  fuzzerstate.intregpickstate.pick_untainted_int_outputreg_nonzero(force = False)
        else:
            if not fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PAGE_ADDR):
                (rd,tmp) = fuzzerstate.intregpickstate.pick_untainted_int_outputregs_nonzero(2,force = False) # Rd and tmp will be untainted after execution.
            else:
                rd =  fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.PAGE_ADDR)
                tmp =  fuzzerstate.intregpickstate.pick_untainted_int_outputreg_nonzero(force = False)

        fuzzerstate.intregpickstate.set_regstate(rd, IntRegIndivState.PAGE_T0_ADDR if tainted else IntRegIndivState.PAGE_ADDR, force=True)
        addr = phys2virt(addr, priv_level, va_layout,fuzzerstate,absolute_addr=True)
        # print(f"Vaddr: {hex(addr)}, tainted: {tainted}")
        instr_objs = li_doubleword(addr, rd, tmp, fuzzerstate)
        return instr_objs

# The reservation in the MemoryView is already done ahead and should not be reiterated here.
# @param jalr_addr_reg: only meaningful if a jalr is present (in the latter case, it should be the next instruction)
def create_instr(instr_str: str, fuzzerstate, curr_addr: int, iscompressed: bool = False):
    if DO_ASSERT:
        assert not iscompressed

    # Integer instructions
    if instr_str in R12DInstructions:
        return _create_R12DInstruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in ImmRdInstructions:
        return _create_ImmRdInstruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in RegImmInstructions:
        return _create_RegImmInstruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in BranchInstructions:
        return _create_BranchInstruction(instr_str, fuzzerstate, curr_addr, iscompressed)
    elif instr_str in JALInstructions:
        return _create_JALInstruction(instr_str, fuzzerstate, curr_addr, iscompressed)
    elif instr_str in JALRInstructions:
        return _create_JALRInstruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in SpecialInstructions:
        return _create_SpecialInstruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in IntLoadInstructions:
        return _create_IntLoadInstruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in IntStoreInstructions:
        return _create_IntStoreInstruction(instr_str, fuzzerstate, iscompressed)
    # Floating point instructions
    elif instr_str in FloatLoadInstructions:
        return _create_FloatLoadInstruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in FloatStoreInstructions:
        return _create_FloatStoreInstruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in FloatToIntInstructions:
        return _create_FloatToIntInstruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in IntToFloatInstructions:
        return _create_IntToFloatInstruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in Float4Instructions:
        return _create_Float4Instruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in Float3Instructions:
        return _create_Float3Instruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in Float3NoRmInstructions:
        return _create_Float3NoRmInstruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in Float2Instructions:
        return _create_Float2Instruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in FloatIntRd2Instructions:
        return _create_FloatIntRd2Instruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in FloatIntRd1Instructions:
        return _create_FloatIntRd1Instruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in FloatIntRs1Instructions:
        return _create_FloatIntRs1Instruction(instr_str, fuzzerstate, iscompressed)

    else:
        raise ValueError(f"Unexpected instruction string: `{instr_str}`")
