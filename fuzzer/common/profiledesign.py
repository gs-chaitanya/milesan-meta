# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script provides a facility to profile designs in terms of:
# - Supported medeleg bits
# - WLRL behavior for writes to mcause (we assume that the behavior is the same for scause)

from params.runparams import DO_ASSERT
from rv.csrids import CSR_IDS
from rv.util import INSTRUCTION_IDS, PARAM_SIZES_BITS_32, PARAM_SIZES_BITS_64, PARAM_IS_SIGNED
from rv.asmutil import li_into_reg, INSTR_FUNCS
from milesan.util_compressed import COMPRESSED_INST_EQUIV
from common.designcfgs import get_design_boot_addr, is_design_32bit, get_design_stop_sig_addr, get_design_reg_dump_addr, design_has_supervisor_mode, get_design_march_flags
from params.fuzzparams import RDEP_MASK_REGISTER_ID
from params.runparams import DEBUG_PRINT
from milesan.cfinstructionclasses import ImmRdInstruction, RegImmInstruction, IntStoreInstruction, CSRImmInstruction, CSRRegInstruction, SpecialInstruction
from milesan.cfinstructionclasses_t0 import RegImmInstruction_t0, ImmRdInstruction_t0, R12DInstruction, CSRImmInstruction
from milesan.fuzzerstate import FuzzerState
from milesan.genelf import gen_elf_from_bbs
from milesan.fuzzsim import runtest_verilator_forprofiling, run_rtl_and_load_regstream
from milesan.util import INSTRUCTIONS_BY_ISA_CLASS
from milesan.registers import MAX_32b, MAX_64b, MAX_20b, MAX_12b, ABI_INAMES
from milesan.spikeresolution import SPIKE_STARTADDR
###
# Internal functions
###

# The snippet will dump a register value of the medeleg when fed with ones and then read back
# @param design_name: the name of the design to profile
# @return a snippet that dumps the register value
def __gen_medeleg_profiling_snippet(design_name: str):
    # Get some info about the design
    try:
        stopsig_addr = get_design_stop_sig_addr(design_name)
    except:
        raise ValueError(f"Design `{design_name}` does not have the `stopsigaddr` attribute.")
    try:
        regdump_addr = get_design_reg_dump_addr(design_name)
    except:
        raise ValueError(f"Design `{design_name}` does not have the `regdumpaddr` attribute.")

    if DO_ASSERT:
        assert regdump_addr < 0x80000000, f"For the destination address `{hex(regdump_addr)}`, we will need to manage sign extension, which is not yet implemented here."
        assert stopsig_addr < 0x80000000, f"For the destination address `{hex(stopsig_addr)}`, we will need to manage sign extension, which is not yet implemented here."

    # We use the fuzzerstate for convenience but use very few of its features for this function's purposes. In particular, we do not bother about memviews.
    fuzzerstate = FuzzerState(get_design_boot_addr(design_name), design_name, 1 << 16, 0, 1, True)

    fuzzerstate.reset()
    fuzzerstate.init_new_bb() # Update fuzzer state to support a new basic block

    is_design_64bit = not is_design_32bit(design_name)

    ###
    # Write -1 into medeleg, then read it back
    ###

    # Write full ones into the medeleg register
    fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction(fuzzerstate,"addi", 1, 0, -1))
    fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction(fuzzerstate,"csrrw", 0, 1, CSR_IDS.MEDELEG))
    # Read medeleg into register 1.
    fuzzerstate.instr_objs_seq[-1].append(CSRImmInstruction(fuzzerstate,"csrrwi", 1, 0, CSR_IDS.MEDELEG))

    # Dump the register
    lui_imm, addi_imm = li_into_reg(regdump_addr)
    fuzzerstate.instr_objs_seq[-1].append(ImmRdInstruction(fuzzerstate,"lui", RDEP_MASK_REGISTER_ID, lui_imm, is_rd_nonpickable_ok=True))
    fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction(fuzzerstate, "addi", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, addi_imm, is_rd_nonpickable_ok=True))
    fuzzerstate.instr_objs_seq[-1].append(IntStoreInstruction(fuzzerstate,"sd" if is_design_64bit else "sw", RDEP_MASK_REGISTER_ID, 1, 0, -1))
    fuzzerstate.instr_objs_seq[-1].append(SpecialInstruction(fuzzerstate,"fence"))

    # Quit the simulation
    lui_imm, addi_imm = li_into_reg(stopsig_addr)
    fuzzerstate.instr_objs_seq[-1].append(ImmRdInstruction(fuzzerstate,"lui", RDEP_MASK_REGISTER_ID, lui_imm, is_rd_nonpickable_ok=True))
    fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction(fuzzerstate,"addi", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, addi_imm, is_rd_nonpickable_ok=True))
    fuzzerstate.instr_objs_seq[-1].append(IntStoreInstruction(fuzzerstate, "sd" if is_design_64bit else "sw", RDEP_MASK_REGISTER_ID, 1, 0, -1))
    fuzzerstate.instr_objs_seq[-1].append(SpecialInstruction(fuzzerstate,"fence"))

    return fuzzerstate

def __gen_asid_profiling_snippet(design_name):
    # Get some info about the design
    try:
        stopsig_addr = get_design_stop_sig_addr(design_name)
    except:
        raise ValueError(f"Design `{design_name}` does not have the `stopsigaddr` attribute.")
    try:
        regdump_addr = get_design_reg_dump_addr(design_name)
    except:
        raise ValueError(f"Design `{design_name}` does not have the `regdumpaddr` attribute.")

    if DO_ASSERT:
        assert regdump_addr < 0x80000000, f"For the destination address `{hex(regdump_addr)}`, we will need to manage sign extension, which is not yet implemented here."
        assert stopsig_addr < 0x80000000, f"For the destination address `{hex(stopsig_addr)}`, we will need to manage sign extension, which is not yet implemented here."

    # We use the fuzzerstate for convenience but use very few of its features for this function's purposes. In particular, we do not bother about memviews.
    fuzzerstate = FuzzerState(get_design_boot_addr(design_name), design_name, 1 << 16, 0, 1, True)

    fuzzerstate.reset()
    fuzzerstate.init_new_bb() # Update fuzzer state to support a new basic block

    is_design_64bit = not is_design_32bit(design_name)

    ###
    # Write 1's in the asid field into satp, then read it back
    ###

    # Write full ones into the SATP register
    if is_design_64bit:
        fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction(fuzzerstate,"addi", 1, 0, 0xff))
        fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction(fuzzerstate,"slli", 1, 1, 8))
        fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction(fuzzerstate,"addi", 1, 1, 0xff))
        fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction(fuzzerstate,"slli", 1, 1, 44))
    else:
        fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction(fuzzerstate,"addi", 1, 0, 0x1ff))
        fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction(fuzzerstate,"slli", 1, 1, 21))

    fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction(fuzzerstate,"csrrw", 0, 1, CSR_IDS.SATP))
    # Read SATP into register 1.
    fuzzerstate.instr_objs_seq[-1].append(CSRImmInstruction(fuzzerstate,"csrrwi", 1, 0, CSR_IDS.SATP))

    # Dump the register
    lui_imm, addi_imm = li_into_reg(regdump_addr)
    fuzzerstate.instr_objs_seq[-1].append(ImmRdInstruction(fuzzerstate,"lui", RDEP_MASK_REGISTER_ID, lui_imm, is_rd_nonpickable_ok=True))
    fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction(fuzzerstate,"addi", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, addi_imm, is_rd_nonpickable_ok=True))
    fuzzerstate.instr_objs_seq[-1].append(IntStoreInstruction(fuzzerstate,"sd" if is_design_64bit else "sw", RDEP_MASK_REGISTER_ID, 1, 0, -1))
    fuzzerstate.instr_objs_seq[-1].append(SpecialInstruction(fuzzerstate,"fence"))

    # Quit the simulation
    lui_imm, addi_imm = li_into_reg(stopsig_addr)
    fuzzerstate.instr_objs_seq[-1].append(ImmRdInstruction(fuzzerstate,"lui", RDEP_MASK_REGISTER_ID, lui_imm, is_rd_nonpickable_ok=True))
    fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction(fuzzerstate,"addi", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, addi_imm, is_rd_nonpickable_ok=True))
    fuzzerstate.instr_objs_seq[-1].append(IntStoreInstruction(fuzzerstate,"sd" if is_design_64bit else "sw", RDEP_MASK_REGISTER_ID, 1, 0, -1))
    fuzzerstate.instr_objs_seq[-1].append(SpecialInstruction(fuzzerstate,"fence"))

    return fuzzerstate


def __gen_ct_profiling_snippet(design_name, test_instr_str):

    # Get some info about the design
    try:
        stopsig_addr = get_design_stop_sig_addr(design_name)
    except:
        raise ValueError(f"Design `{design_name}` does not have the `stopsigaddr` attribute.")
    try:
        regdump_addr = get_design_reg_dump_addr(design_name)
    except:
        raise ValueError(f"Design `{design_name}` does not have the `regdumpaddr` attribute.")

    if DO_ASSERT:
        assert regdump_addr < 0x80000000, f"For the destination address `{hex(regdump_addr)}`, we will need to manage sign extension, which is not yet implemented here."
        assert stopsig_addr < 0x80000000, f"For the destination address `{hex(stopsig_addr)}`, we will need to manage sign extension, which is not yet implemented here."

    # We use the fuzzerstate for convenience but use very few of its features for this function's purposes. In particular, we do not bother about memviews.
    fuzzerstate = FuzzerState(get_design_boot_addr(design_name), design_name, 1 << 16, 0, 1, True)
    fuzzerstate.reset()
    fuzzerstate.init_new_bb() # Update fuzzer state to support a new basic block

    is_design_64bit = not is_design_32bit(design_name)

    # Dump the register
    lui_imm, addi_imm = li_into_reg(regdump_addr)
    fuzzerstate.instr_objs_seq[-1].append(ImmRdInstruction(fuzzerstate,"lui", RDEP_MASK_REGISTER_ID, lui_imm, is_rd_nonpickable_ok=True))
    
    fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction(fuzzerstate,"addi", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, addi_imm, is_rd_nonpickable_ok=True))


    if is_design_64bit:
        curr_param_size = PARAM_SIZES_BITS_64[INSTRUCTION_IDS['lui']][-1]
    else:
        curr_param_size = PARAM_SIZES_BITS_32[INSTRUCTION_IDS['lui']][-1]
    if PARAM_IS_SIGNED[INSTRUCTION_IDS['lui']][-1]:
        imm =  2**(curr_param_size-1)-1
    else:
        imm =  2**(curr_param_size)-1

    fuzzerstate.instr_objs_seq[-1].append(ImmRdInstruction_t0(fuzzerstate,"lui", 1, imm, imm, is_rd_nonpickable_ok=False))

    if is_design_64bit:
        curr_param_size = PARAM_SIZES_BITS_64[INSTRUCTION_IDS['addi']][-1]
    else:
        curr_param_size = PARAM_SIZES_BITS_32[INSTRUCTION_IDS['addi']][-1]
    if PARAM_IS_SIGNED[INSTRUCTION_IDS['addi']][-1]:
        imm =  2**(curr_param_size-1)-1
    else:
        imm =  2**(curr_param_size)-1

    fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction_t0(fuzzerstate,"addi", 1, 1, imm, imm, is_rd_nonpickable_ok=False))

    if is_design_64bit:
        curr_param_size = PARAM_SIZES_BITS_64[INSTRUCTION_IDS[test_instr_str]][-1]
    else:
        curr_param_size = PARAM_SIZES_BITS_32[INSTRUCTION_IDS[test_instr_str]][-1]
    if PARAM_IS_SIGNED[INSTRUCTION_IDS[test_instr_str]][-1]:
        imm =  2**(curr_param_size-1)-1
    else:
        imm =  2**(curr_param_size)-1

    if test_instr_str in RegImmInstruction.authorized_instr_strs:
        test_instr = RegImmInstruction_t0(fuzzerstate,test_instr_str, 0, 1, imm, imm, is_rd_nonpickable_ok=False)
    elif test_instr_str in ImmRdInstruction.authorized_instr_strs:
        test_instr = ImmRdInstruction_t0(fuzzerstate,test_instr_str, 0, imm, imm, is_rd_nonpickable_ok=False)
    elif test_instr_str in R12DInstruction.authorized_instr_strs:
        test_instr = R12DInstruction(fuzzerstate,test_instr_str, 0, 1, 1, is_rd_nonpickable_ok=False)
    
    fuzzerstate.instr_objs_seq[-1].append(test_instr)
    fuzzerstate.instr_objs_seq[-1].append(CSRImmInstruction(fuzzerstate,"csrrci", 1, 0, CSR_IDS.MCYCLE))
    fuzzerstate.instr_objs_seq[-1].append(IntStoreInstruction(fuzzerstate,"sd" if is_design_64bit else "sw", RDEP_MASK_REGISTER_ID, 1, 0, -1))
    fuzzerstate.instr_objs_seq[-1].append(SpecialInstruction(fuzzerstate,"fence"))

    # Quit the simulation
    lui_imm, addi_imm = li_into_reg(stopsig_addr)
    fuzzerstate.instr_objs_seq[-1].append(ImmRdInstruction(fuzzerstate,"lui", RDEP_MASK_REGISTER_ID, lui_imm, is_rd_nonpickable_ok=True))
    fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction(fuzzerstate,"addi", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, addi_imm, is_rd_nonpickable_ok=True))
    fuzzerstate.instr_objs_seq[-1].append(IntStoreInstruction(fuzzerstate,"sd" if is_design_64bit else "sw", RDEP_MASK_REGISTER_ID, 1, 0, -1))
    fuzzerstate.instr_objs_seq[-1].append(SpecialInstruction(fuzzerstate,"fence"))

    for instr in fuzzerstate.instr_objs_seq[-1]:
        instr.print()
        instr.paddr = fuzzerstate.curr_bb_start_addr + 4*len(fuzzerstate.instr_objs_seq[-1]) + SPIKE_STARTADDR
    return fuzzerstate



def __get_medeleg_mask(design_name: str):
    # The fuzzerstate contains the snippet that dumps a register value of 1 if an exception occurred, else a value of 0
    fuzzerstate = __gen_medeleg_profiling_snippet(design_name)
    rtl_elfpath = gen_elf_from_bbs(fuzzerstate, False, 'medelegprofiling', design_name, fuzzerstate.design_base_addr)
    return runtest_verilator_forprofiling(fuzzerstate, rtl_elfpath, 1)

def __get_asid_mask(design_name: str):
    # The fuzzerstate contains the snippet that dumps a register value of 1 if an exception occurred, else a value of 0
    fuzzerstate = __gen_asid_profiling_snippet(design_name)
    rtl_elfpath = gen_elf_from_bbs(fuzzerstate, False, 'asidprofiling', design_name, fuzzerstate.design_base_addr)
    return runtest_verilator_forprofiling(fuzzerstate, rtl_elfpath, 1)


def __check_instr_is_ct(design_name: str, test_instr_str):
    if "c.addi4spn" in test_instr_str:
        return False

    fuzzerstate = __gen_ct_profiling_snippet(design_name, test_instr_str)
    rtl_elfpath = gen_elf_from_bbs(fuzzerstate, False, f'ctprofiling_{test_instr_str}', design_name, fuzzerstate.design_base_addr)
    fuzzerstate.setup_env(rtl_elfpath, fuzzerstate.randseed)
    fuzzerstate.write_imm_t0_to_mem() # Write the immediate taints from the program code to the imem.
    fuzzerstate.dump_memview_t0()
    print(f"Profiling {test_instr_str}")
    _,regdumps,_ = run_rtl_and_load_regstream(fuzzerstate)
    print(regdumps)
    assert len(regdumps) == 1
    if int(regdumps[0]['value_t0'],16) == 0:
        print(f"instruction {test_instr_str} is CT.")
        return True

def __get_ct_instrs(design_name: str):
    is_design_64bit = not is_design_32bit(design_name)
    has_compressed = "c" in get_design_march_flags(design_name)
    for test_instr_str in ["lui"]:
        __check_instr_is_ct(design_name, test_instr_str)
    # ct_instrs = {}
    # for isa_class, instrs in INSTRUCTIONS_BY_ISA_CLASS.items():
    #     ct_instrs[isa_class] = []
    #     for test_instr_str in instrs:
    #         if 'and' not in test_instr_str:
    #             continue
    #         if test_instr_str not in INSTR_FUNCS:
    #             continue
    #         if test_instr_str not in (RegImmInstruction.authorized_instr_strs + ImmRdInstruction.authorized_instr_strs + R12DInstruction.authorized_instr_strs):
    #             continue
    #         if __check_instr_is_ct(design_name, test_instr_str):
    #             ct_instrs[isa_class] += [test_instr_str]
    #         if not has_compressed:
    #             continue
    #         if test_instr_str in COMPRESSED_INST_EQUIV.keys():
    #             if isinstance(COMPRESSED_INST_EQUIV[test_instr_str], list):
    #                 for test_instr_str_c in COMPRESSED_INST_EQUIV[test_instr_str]:
    #                     if __check_instr_is_ct(design_name, test_instr_str_c):
    #                         ct_instrs[isa_class] += [test_instr_str_c]
    #             else:
    #                 test_instr_str_c = COMPRESSED_INST_EQUIV[test_instr_str]
    #                 if __check_instr_is_ct(design_name, test_instr_str_c):
    #                     ct_instrs[isa_class] += [test_instr_str_c]
                


###
# Exposed functions
###

PROFILED_MEDELEG_MASK = None
PROFILED_ASID_MASK = None
PROFILED_CT_INSTRS = None

def profile_get_medeleg_mask(design_name: str):
    if "picorv32" in design_name:
        return 0 # This design does not support medeleg
    global PROFILED_MEDELEG_MASK
    PROFILED_MEDELEG_MASK = __get_medeleg_mask(design_name)

def profile_get_asid_mask(design_name: str):
    global PROFILED_ASID_MASK
    if is_design_32bit(design_name):
        PROFILED_ASID_MASK = __get_asid_mask(design_name) >> 21
    else:
        PROFILED_ASID_MASK = __get_asid_mask(design_name) >> 44

def profile_get_ct_instrs(design_name: str):
    global PROFILED_CT_INSTRS
    PROFILED_CT_INSTRS = __get_ct_instrs(design_name)

# @return the mask of medeleg bits that are supported by the design
def get_medeleg_mask(design_name: str):
    if PROFILED_MEDELEG_MASK is None:
        raise Exception("Error: get_medeleg_mask was called before profiling.")
    return PROFILED_MEDELEG_MASK

# @return the mask of asid bits that are supported by the design
def get_asid_mask(design_name: str):
    if PROFILED_ASID_MASK is None:
        raise Exception("Error: get_asid_mask was called before profiling.")
    if DEBUG_PRINT: print(f"ASID MASK: {PROFILED_ASID_MASK}")
    return PROFILED_ASID_MASK

def get_ct_instrs(design_name: str):
    if PROFILED_CT_INSTRS is None:
        raise Exception("Error: get_ct_instrs was called before profiling.")
    if DEBUG_PRINT: print(f"CT instructions: {PROFILED_CT_INSTRS}")
    return PROFILED_CT_INSTRS
