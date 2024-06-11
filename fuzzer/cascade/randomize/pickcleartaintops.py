# Copyright 2024 Tobias Kovats, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only


from cascade.cfinstructionclasses_t0 import R12DInstruction_t0, RegImmInstruction_t0, ImmRdInstruction_t0
from params.runparams import DO_ASSERT
from rv.util import INSTRUCTION_IDS, PARAM_SIZES_BITS_32, PARAM_SIZES_BITS_64, PARAM_IS_SIGNED
from cascade.util import ISAInstrClass, INSTRUCTIONS_BY_ISA_CLASS
from cascade.randomize.pickinstrtype import gen_next_instrstr_from_isaclass
import random
def clear_taints_with_random_instructions(fuzzerstate):
    instr_objs = []
    tainted_reg_ids = fuzzerstate.intregpickstate.get_tainted_free_regs()
    untainted_reg_ids = fuzzerstate.intregpickstate.get_untainted_free_regs()

    for tainted_reg_id in tainted_reg_ids:
        instr_str = gen_next_instrstr_from_isaclass(ISAInstrClass.ALU, fuzzerstate)
        assert instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.ALU]
        if fuzzerstate.is_design_64bit:
            curr_param_size = PARAM_SIZES_BITS_64[INSTRUCTION_IDS[instr_str]][-1]
        else:
            curr_param_size = PARAM_SIZES_BITS_32[INSTRUCTION_IDS[instr_str]][-1]
        if PARAM_IS_SIGNED[INSTRUCTION_IDS[instr_str]][-1]:
            imm = random.randint( -(1<<(curr_param_size-1)),1<<(curr_param_size-1))
        else:
            imm = random.randint(0,1<<(curr_param_size))
        if instr_str in R12DInstruction_t0.authorized_instr_strs:
            rs1 = random.choice(untainted_reg_ids)
            rs2 = random.choice(untainted_reg_ids)
            instr_objs += [R12DInstruction_t0(fuzzerstate, instr_str, tainted_reg_id, rs1, rs2)]
        elif instr_str in RegImmInstruction_t0.authorized_instr_strs:
            rs1 = random.choice(untainted_reg_ids)
            instr_objs += [RegImmInstruction_t0(fuzzerstate, instr_str, tainted_reg_id, rs1, imm)]
        elif instr_str in ImmRdInstruction_t0.authorized_instr_strs:
            instr_objs += [ImmRdInstruction_t0(fuzzerstate, instr_str, tainted_reg_id, imm)]
        else:
            assert False, f"{instr_str}"
        untainted_reg_ids += [tainted_reg_id]

    if DO_ASSERT:
        assert set(tainted_reg_ids) <= set(untainted_reg_ids), f"Not all tainted registers were overwritten."
    
    return instr_objs
