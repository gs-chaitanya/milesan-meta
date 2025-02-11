# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

import random
from copy import copy
from params.runparams import DO_ASSERT
from params.fuzzparams import USE_COMPRESSED, COMPRESS_INSTRUCTION, DISALLOW_NESTED_SPECULATION
from milesan.randomize.pickinstrtype import gen_next_instrstr_from_isaclass
from milesan.util import INSTRUCTIONS_BY_ISA_CLASS
from milesan.randomize.pickisainstrclass import _gen_next_isainstrclass_from_weights
from milesan.util_compressed import *
from milesan.cfinstructionclasses import *
from milesan.cfinstructionclasses_t0 import *
from milesan.randomize.createcfinstr import is_tolerate_R12DInstruction
from milesan.randomize.pickexceptionop import gen_ppfill_instrs, gen_exception_instr, gen_medeleg_instr
from milesan.randomize.pickprivilegedescentop import gen_priv_descent_instr
from rv.util import PARAM_REGTYPE, PARAM_SIZES_BITS_32, PARAM_SIZES_BITS_64
# This module creates an instruction from its instruction string, and some state which will condition which registers and immediates will be picked, and with which probability.

MAX_N_TRIES_IMM = 1000
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


def try_gen_random_free_imm(instr_str: str, fuzzerstate, curr_addr: int):
    tries = 0
    target_addr = None
    while target_addr is None or not fuzzerstate.memview.is_mem_range_free(target_addr-SPIKE_STARTADDR, 4):
        imm = gen_random_imm(instr_str,fuzzerstate.is_design_64bit)    
        target_addr = curr_addr + imm
        if target_addr < SPIKE_STARTADDR or target_addr > SPIKE_STARTADDR + fuzzerstate.memview.memsize:
            break
        tries += 1
        if tries > MAX_N_TRIES_IMM:
            return False
    return imm


def gen_random_free_imm(instr_str: str, fuzzerstate, curr_addr: int):
    imm = try_gen_random_free_imm(instr_str, fuzzerstate, curr_addr)
    if not imm:
        raise ValueError(f"Couldn't find a free address/immediate for instruction {instr_str} and addr {hex(curr_addr)}")
    return imm

    
def _create_R12DInstruction(instr_str: str, fuzzerstate, iscompressed: bool):
    # When this is executed transiently, don't pick tainted registers when in taint-source domain. In taint-sink domain, 
    # no registers are (architecturally) tainted, so we don't need to explicitly check which domain we are in.
    if not is_tolerate_R12DInstruction(instr_str, fuzzerstate) and not is_tolerate_transient_exec_str(fuzzerstate,instr_str):
        rs1, rs2 = tuple(fuzzerstate.intregpickstate.pick_untainted_int_inputregs(2,force=True))
    else:
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
    # When we DISABLE_TAINT_SOURCE_GADGETS is enabled, tainted regs should not be chosen in the transient window.
    if not is_tolerate_transient_exec_str(fuzzerstate, instr_str):
        rs1 = fuzzerstate.intregpickstate.pick_untainted_int_inputreg(force=True)
        rs2 = fuzzerstate.intregpickstate.pick_untainted_int_inputreg(force=True)
    else:
        rs1 = fuzzerstate.intregpickstate.pick_int_inputreg()
        rs2 = fuzzerstate.intregpickstate.pick_int_inputreg()
    
    imm = gen_random_free_imm(instr_str, fuzzerstate, curr_addr)

    return BranchInstruction_t0(fuzzerstate, instr_str, rs1, rs2, imm, 0x0, None, iscompressed)
    
def _create_JALInstruction(instr_str: str, fuzzerstate, curr_addr: int, iscompressed: bool):
    rd = fuzzerstate.intregpickstate.pick_int_inputreg()
    # TODO don't pick addresses where there's already code
    imm = gen_random_free_imm(instr_str,fuzzerstate,0x0)  
    if USE_COMPRESSED and len(fuzzerstate.instr_objs_seq) > 1 and instr_str in IS_COMPRESSABLE: # no compressed in initial block
        instr_str_cmp, is_compressable = handle_JAL(rd, imm, instr_str, fuzzerstate.is_design_64bit)
        if is_compressable and (random.random() < COMPRESS_INSTRUCTION):
            iscompressed = True
            # print(f"compressed {instr_str} into {instr_str_cmp}") #DEBUG
            instr_str = instr_str_cmp
    return JALInstruction_t0(fuzzerstate, instr_str, rd, imm, iscompressed)

def _create_JALRInstruction(instr_str: str, fuzzerstate, iscompressed: bool, curr_addr: int = None): # curr_addr for compatibility in _create_spectre_gadget_instrobjs 
    if not is_tolerate_transient_exec_str(fuzzerstate, instr_str):
        rs1 = fuzzerstate.intregpickstate.pick_untainted_int_inputreg(force=True)
    else:
        rs1 = fuzzerstate.intregpickstate.pick_int_inputreg()
    rd = fuzzerstate.intregpickstate.pick_int_inputreg()
    # TODO don't pick addresses where there's already code
    imm = gen_random_imm(instr_str,fuzzerstate.is_design_64bit)

    producer_id = None
    return JALRInstruction_t0(fuzzerstate, instr_str, rd, rs1, imm, producer_id, iscompressed)

def _create_SpecialInstruction(instr_str: str, fuzzerstate, iscompressed: bool):
    rd = fuzzerstate.intregpickstate.pick_int_outputreg(authorize_sideeffects=False) # The fence instructions don't write to rd, thus we don't set them free.
    rs1 = fuzzerstate.intregpickstate.pick_int_inputreg()
    return SpecialInstruction_t0(fuzzerstate, instr_str, rd, rs1)

def _create_IntLoadInstruction(instr_str: str, fuzzerstate, iscompressed: bool):
    if not is_tolerate_transient_exec_str(fuzzerstate, instr_str):
        rs1 = fuzzerstate.intregpickstate.pick_untainted_int_inputreg(force=True)
    else:
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
    if not is_tolerate_transient_exec_str(fuzzerstate, instr_str):
        rs1 = fuzzerstate.intregpickstate.pick_untainted_int_inputreg(force=True)
    else:
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



def create_speculative_instrs(fuzzerstate, curr_addr: int, domain: tuple):
    assert domain[0] in range(-1, fuzzerstate.num_layouts), f"Invalid layout {domain[0]}"
    assert domain[1] in list(PrivilegeStateEnum), f"Invalid privilege {domain[1]}"

    weights =  copy(fuzzerstate.isapickweights)
    # # We don't try to speculatively mess with the FSMs for now
    weights[ISAInstrClass.MMU] = 0
    weights[ISAInstrClass.REGFSM] = 0
    weights[ISAInstrClass.CLEARTAINT] = 0
    # weights[ISAInstrClass.DESCEND_PRV] = 0
    # weights[ISAInstrClass.PPFSM] = 0
    # weights[ISAInstrClass.EXCEPTION] = 0
    weights[ISAInstrClass.MEMFSM] = 0
    weights[ISAInstrClass.EPCFSM] = 0
    weights[ISAInstrClass.RANDOM_CSR] = 0
    weights[ISAInstrClass.TVECFSM] = 0
    # weights[ISAInstrClass.MEDELEG] = 0

    # disallow nested speculation, can't reduce it properly yet...
    # We would have to choose the immediates s.t. the target addresses don't have any code allocated yet.
    if DISALLOW_NESTED_SPECULATION:
        weights[ISAInstrClass.JALR] = 0
        weights[ISAInstrClass.JAL] = 0
        weights[ISAInstrClass.BRANCH] = 0

    # randomize
    fuzzerstate.privilegestate.privstate = random.choice(list(PrivilegeStateEnum))
    fuzzerstate.privilegestate.is_mepc_populated = True
    fuzzerstate.privilegestate.is_mtvec_populated = True
    fuzzerstate.privilegestate.is_sepc_populated = True
    fuzzerstate.privilegestate.is_stvec_populated = True
    fuzzerstate.privilegestate.curr_mstatus_mpp = random.choice(list(PrivilegeStateEnum))
    fuzzerstate.privilegestate.curr_mstatus_spp = random.choice(list(PrivilegeStateEnum))
    fuzzerstate.real_curr_layout = random.choice(range(-1,fuzzerstate.num_layouts))
    fuzzerstate.effective_curr_layout = random.choice(range(-1,fuzzerstate.num_layouts))
    # artificially set some register to consumed if we don't have one to enable more special instructions
    if not fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.CONSUMED):
        consumed_reg = random.choice(range(1,fuzzerstate.intregpickstate.num_pickable_regs))
        fuzzerstate.intregpickstate.set_regstate(consumed_reg, IntRegIndivState.CONSUMED, force=True)


    # allow any register
    fuzzerstate.intregpickstate.free_relocusedregs()

    isa_class = _gen_next_isainstrclass_from_weights(weights)

    if isa_class == ISAInstrClass.DESCEND_PRV:
        # fuzzerstate.privilegestate.privstate = random.choice([PrivilegeStateEnum.MACHINE, PrivilegeStateEnum.SUPERVISOR])
        # instrs = gen_priv_descent_instr(fuzzerstate)
        instrs = [PrivilegeDescentInstruction_t0(fuzzerstate, is_mret=fuzzerstate.privilegestate.privstate==PrivilegeStateEnum.MACHINE)]
    elif isa_class == ISAInstrClass.PPFSM:
        # assert False, "not implemented"
        fuzzerstate.privilegestate.privstate = PrivilegeStateEnum.MACHINE
        instrs = gen_ppfill_instrs(fuzzerstate)
    elif isa_class == ISAInstrClass.EXCEPTION:
        instrs = gen_exception_instr(fuzzerstate)
    elif isa_class == ISAInstrClass.MEDELEG:
        fuzzerstate.privilegestate.privstate = PrivilegeStateEnum.MACHINE
        instrs = [gen_medeleg_instr(fuzzerstate)]
    else:
        instr_str = gen_next_instrstr_from_isaclass(isa_class, fuzzerstate)
        instrs = [_create_speculative_instr(instr_str, fuzzerstate, curr_addr)]
    
    paddr =  curr_addr|SPIKE_STARTADDR
    for instr in instrs:
        instr.paddr = paddr
        instr.va_layout, instr.priv_level = domain
        if not None in domain:
            instr.vaddr = phys2virt(instr.paddr, instr.priv_level, instr.va_layout, fuzzerstate,absolute_addr=False)

        if isinstance(instr, GenericCSRWriterInstruction_t0):
            instr.csr_instr.paddr = instr.paddr
            instr.csr_instr.vaddr = instr.vaddr
            instr.csr_instr.priv_level = instr.priv_level
        elif isinstance(instr, SimpleExceptionEncapsulator):
            instr.instr.paddr = instr.paddr
            instr.instr.vaddr = instr.vaddr
            instr.instr.priv_level = instr.priv_level
        
        paddr += 2 if instr.iscompressed else 4

        assert instr.va_layout != -1 or instr.priv_level == PrivilegeStateEnum.MACHINE, f"{instr.get_str()}"
    return [SpeculativeInstructionEncapsulator(fuzzerstate,instr) for instr in instrs]