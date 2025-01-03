# Copyright 2023 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

import random
from copy import copy
from params.runparams import DO_ASSERT
from params.fuzzparams import USE_COMPRESSED, COMPRESS_INSTRUCTION
from milesan.randomize.pickinstrtype import gen_next_instrstr_from_isaclass
from milesan.util import INSTRUCTIONS_BY_ISA_CLASS
from milesan.randomize.pickisainstrclass import _get_isainstrclass_filtered_weights, _gen_next_isainstrclass_from_weights
from milesan.util_compressed import *
from milesan.cfinstructionclasses import *
from milesan.cfinstructionclasses_t0 import *
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
    
    rand_val = random.randrange(left_bound, right_bound)
    return rand_val


def _create_R12DInstruction(instr_str: str, fuzzerstate, iscompressed: bool):
    rs1 = fuzzerstate.intregpickstate.pick_int_inputreg()
    rs2 = fuzzerstate.intregpickstate.pick_int_inputreg()
    rd = fuzzerstate.intregpickstate.pick_untainted_int_outputreg_nonzero()
    if USE_COMPRESSED and instr_str in IS_COMPRESSABLE:
        instr_str_cmp, is_compressable = handle_R12D(rd, rs1, rs2, instr_str)
        if is_compressable and (random.random() < COMPRESS_INSTRUCTION):
            iscompressed = True
            instr_str = instr_str_cmp
    return R12DInstruction_t0(fuzzerstate, instr_str, rd, rs1, rs2, iscompressed)

def _create_ImmRdInstruction(instr_str: str, fuzzerstate, iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in ImmRdInstructions

    imm = gen_random_imm(instr_str, fuzzerstate.is_design_64bit)    
    rd = fuzzerstate.intregpickstate.pick_int_inputreg()
    if USE_COMPRESSED and instr_str in IS_COMPRESSABLE:
        instr_str_cmp, is_compressable = handle_ImRd(rd, imm, instr_str)
        if is_compressable and (random.random() < COMPRESS_INSTRUCTION):
            iscompressed = True
            # print(f"compressed {instr_str} into {instr_str_cmp}") #DEBUG
            instr_str = instr_str_cmp

    return ImmRdInstruction_t0(fuzzerstate,instr_str, rd, imm, 0, iscompressed)

def _create_RegImmInstruction(instr_str: str, fuzzerstate, iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in RegImmInstructions
    rs1 = fuzzerstate.intregpickstate.pick_int_inputreg()
    rd = fuzzerstate.intregpickstate.pick_int_inputreg()
    imm = gen_random_imm(instr_str,fuzzerstate.is_design_64bit)    

    if USE_COMPRESSED and instr_str in IS_COMPRESSABLE:
        instr_str_cmp, is_compressable = handle_RegImm(rd, rs1, imm, instr_str, fuzzerstate.is_design_64bit)
        if is_compressable and (random.random() < COMPRESS_INSTRUCTION):  
            iscompressed = True
            # print(f"compressed {instr_str}, {ABI_INAMES[rd]}, {ABI_INAMES[rs1]}, {hex(imm)}, into {instr_str_cmp}") #DEBUG
            instr_str = instr_str_cmp

    return RegImmInstruction_t0(fuzzerstate, instr_str, rd, rs1, imm, 0, iscompressed)


def _create_BranchInstruction(instr_str: str, fuzzerstate, curr_addr: int, iscompressed: bool):
    rs1 = fuzzerstate.intregpickstate.pick_int_inputreg()
    rs2 = fuzzerstate.intregpickstate.pick_int_inputreg()
    imm = gen_random_imm(instr_str,fuzzerstate.is_design_64bit)    
    return BranchInstruction_t0(fuzzerstate, instr_str, rs1, rs2, imm, 0x0, None, iscompressed)
    
def _create_JALInstruction(instr_str: str, fuzzerstate, curr_addr: int, iscompressed: bool):
    rd = fuzzerstate.intregpickstate.pick_int_inputreg()
    imm = gen_random_imm(instr_str,fuzzerstate.is_design_64bit)    
    if USE_COMPRESSED and len(fuzzerstate.instr_objs_seq) > 1 and instr_str in IS_COMPRESSABLE: # no compressed in initial block
        instr_str_cmp, is_compressable = handle_JAL(rd, imm, instr_str, fuzzerstate.is_design_64bit)
        if is_compressable and (random.random() < COMPRESS_INSTRUCTION):
            iscompressed = True
            # print(f"compressed {instr_str} into {instr_str_cmp}") #DEBUG
            instr_str = instr_str_cmp
    return JALInstruction_t0(fuzzerstate, instr_str, rd, imm, iscompressed)

def _create_JALRInstruction(instr_str: str, fuzzerstate, iscompressed: bool, curr_addr: int = None): # curr_addr for compatibility in _create_spectre_gadget_instrobjs 
    rs1 = fuzzerstate.intregpickstate.pick_int_inputreg()
    rd = fuzzerstate.intregpickstate.pick_int_inputreg()
    imm = gen_random_imm(instr_str,fuzzerstate.is_design_64bit)    
    producer_id = None
    return JALRInstruction_t0(fuzzerstate, instr_str, rd, rs1, imm, producer_id, iscompressed)

def _create_SpecialInstruction(instr_str: str, fuzzerstate, iscompressed: bool):
    rd = fuzzerstate.intregpickstate.pick_int_outputreg(authorize_sideeffects=False) # The fence instructions don't write to rd, thus we don't set them free.
    rs1 = fuzzerstate.intregpickstate.pick_int_inputreg()
    return SpecialInstruction_t0(fuzzerstate, instr_str, rd, rs1)

def _create_IntLoadInstruction(instr_str: str, fuzzerstate, iscompressed: bool):
    rs1 = fuzzerstate.intregpickstate.pick_int_inputreg()
    rd = fuzzerstate.intregpickstate.pick_int_outputreg()
    imm = gen_random_imm(instr_str,fuzzerstate.is_design_64bit)    

    if USE_COMPRESSED and instr_str in IS_COMPRESSABLE:
        instr_str_cmp, is_compressable = handle_IntLoad(rd, rs1, imm, instr_str)
        if is_compressable and (random.random() < COMPRESS_INSTRUCTION):
            iscompressed = True
            # print(f"compressed {instr_str} into {instr_str_cmp}") #DEBUG
            instr_str = instr_str_cmp

    return IntLoadInstruction_t0(fuzzerstate, instr_str, rd, rs1, imm, None, iscompressed)

def _create_IntStoreInstruction(instr_str: str, fuzzerstate, iscompressed: bool):
    rs1 = fuzzerstate.intregpickstate.pick_int_inputreg()
    rs2 = fuzzerstate.intregpickstate.pick_int_inputreg()
    imm = gen_random_imm(instr_str,fuzzerstate.is_design_64bit)    

    if USE_COMPRESSED and instr_str in IS_COMPRESSABLE:
        instr_str_cmp, is_compressable = handle_IntStore(rs1, rs2, imm, instr_str)
        if is_compressable and (random.random() < COMPRESS_INSTRUCTION):
            iscompressed = True
            #print(f"compressed {instr_str} into {instr_str_cmp}") #DEBUG
            instr_str = instr_str_cmp

    return IntStoreInstruction_t0(fuzzerstate, instr_str, rs1, rs2, imm, None, iscompressed)


###
# Exposed function
###

def _create_speculative_instr(instr_str: str, fuzzerstate, curr_addr: int, iscompressed: bool = False):
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
    else:
        raise ValueError(f"Unexpected instruction string: `{instr_str}`")

def create_speculative_instr(fuzzerstate, curr_addr: int):
    weights = copy(fuzzerstate.isapickweights)
    weights[ISAInstrClass.MMU] = 0
    weights[ISAInstrClass.REGFSM] = 0
    weights[ISAInstrClass.CLEARTAINT] = 0
    weights[ISAInstrClass.DESCEND_PRV] = 0
    weights[ISAInstrClass.PPFSM] = 0
    weights[ISAInstrClass.EXCEPTION] = 0
    weights[ISAInstrClass.MEMFSM] = 0
    weights[ISAInstrClass.EPCFSM] = 0
    weights[ISAInstrClass.RANDOM_CSR] = 0
    weights[ISAInstrClass.TVECFSM] = 0
    weights[ISAInstrClass.MEDELEG] = 0

    isa_class = _gen_next_isainstrclass_from_weights(weights)
    instr_str = gen_next_instrstr_from_isaclass(isa_class, fuzzerstate)
    instr = _create_speculative_instr(instr_str, fuzzerstate, curr_addr)
    instr.paddr = curr_addr
    return SpeculativeInstructionEncapsulator(fuzzerstate,instr)