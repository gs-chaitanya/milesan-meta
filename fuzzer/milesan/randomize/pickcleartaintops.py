# Copyright 2024 Tobias Kovats, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only


from milesan.cfinstructionclasses_t0 import R12DInstruction_t0, RegImmInstruction_t0, ImmRdInstruction_t0
from params.runparams import DO_ASSERT
from params.fuzzparams import NUM_MIN_UNTAINTED_INTREGS
from rv.util import INSTRUCTION_IDS, PARAM_SIZES_BITS_32, PARAM_SIZES_BITS_64, PARAM_IS_SIGNED
from milesan.util import ISAInstrClass, INSTRUCTIONS_BY_ISA_CLASS, IntRegIndivState
from common.spike import SPIKE_STARTADDR
from milesan.randomize.pickinstrtype import gen_next_instrstr_from_isaclass
import random
def clear_taints_with_random_instructions(fuzzerstate, untaint_all: bool = False):
    instr_objs = []
    tainted_reg_ids = fuzzerstate.intregpickstate.get_tainted_free_regs()
    random.shuffle(tainted_reg_ids)
    untainted_reg_ids = fuzzerstate.intregpickstate.get_untainted_free_regs()
    random.shuffle(untainted_reg_ids)
    # print(f"Clearing taint from {len(untainted_reg_ids)}.")
    # fuzzerstate.intregpickstate.print()
    for tainted_reg_id in tainted_reg_ids:
        instr_str = gen_next_instrstr_from_isaclass(ISAInstrClass.ALU, fuzzerstate)
        if "auipc" in instr_str and SPIKE_STARTADDR != fuzzerstate.design_base_addr:
            fuzzerstate.intregpickstate.set_regstate(tainted_reg_id, IntRegIndivState.RELOCUSED, force=True)
        assert instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.ALU]
        if fuzzerstate.is_design_64bit:
            curr_param_size = PARAM_SIZES_BITS_64[INSTRUCTION_IDS[instr_str]][-1]
        else:
            curr_param_size = PARAM_SIZES_BITS_32[INSTRUCTION_IDS[instr_str]][-1]
        if PARAM_IS_SIGNED[INSTRUCTION_IDS[instr_str]][-1]:
            imm = random.randint(- (1<<(curr_param_size-2)),1<<(curr_param_size-2))
        else:
            imm = random.randint(0,1<<(curr_param_size-1))

        del curr_param_size
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
        if not ("auipc" in instr_str and SPIKE_STARTADDR != fuzzerstate.design_base_addr):
            untainted_reg_ids += [tainted_reg_id]
        if len(untainted_reg_ids) > NUM_MIN_UNTAINTED_INTREGS+1 and not untaint_all:
            # print([i.get_str() for i in instr_objs])
            return instr_objs
    return instr_objs
