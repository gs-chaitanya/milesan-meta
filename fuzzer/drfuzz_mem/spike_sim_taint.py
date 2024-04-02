import os, random, numpy as np
import shutil
import glob
import json

from params.runparams import PATH_TO_TMP, PATH_TO_COV
from cascade.fuzzfromdescriptor import NUM_MAX_BBS_UPPERBOUND, gen_fuzzerstate_elf_expectedvals_interm, gen_new_test_instance
from cascade.cfinstructionclasses import *
import subprocess, itertools
from common import designcfgs
from common.spike import SPIKE_STARTADDR
from cascade.randomize.pickbytecodetaints import CFINSTRCLASS_INJECT_PROBS
from cascade.registers import ABI_INAMES,MAX_32b
from cascade.spikeresolution import spike_resolution_return_interm

MAX_CYCLES_PER_INSTR = 30
SETUP_CYCLES = 1000 # Without this, we had issues with BOOM with very short programs (typically <20 instructions) not being able to finish in time.
def spike_sim_taint(fuzzerstate, expected_regvals):    
    # get fuzzerstate and expected regvals from program
    pc_reg_pairs_0 = {req[0] + SPIKE_STARTADDR:{} for req in expected_regvals[2]}
    for req, regval in zip(expected_regvals[2],expected_regvals[3]):
        pc_reg_pairs_0[req[0] + SPIKE_STARTADDR][req[2]] = regval


    # Chose some random injecable instruction and inject taint. Also flip the corresponding bit in the alternative cascade program
    # to derive the taints from the spike simulation
    injected_taint = False
    inject_addr = 0x0
    for bb_id ,(bb_start_addr, bb_instrs) in enumerate(zip(fuzzerstate.bb_start_addr_seq[:-1], fuzzerstate.instr_objs_seq[:-1])): # skip first and last bb
        if bb_id == 0: continue
        for instr_id_in_bb, instr_obj in enumerate(bb_instrs):
            curr_addr = SPIKE_STARTADDR+bb_start_addr+4*instr_id_in_bb
            if instr_obj.injectable:
                injected_taint = instr_obj.compute_taints()
                if injected_taint:
                    print(f"Injecting taint into instruction {instr_obj.get_str()}: {hex(instr_obj.gen_bytecode_int_t0(True))}")
                    # instr_obj.set_bytecode(instr_obj.gen_bytecode_int(True) ^ instr_obj.gen_bytecode_int_t0(True))
                    instr_obj.inject_taint()
                    inject_addr = curr_addr
                    print(f"Taint modifies to {instr_obj.get_str()}")
                    break    
        if injected_taint:
            break

    assert inject_addr,  "Did not inject taint."


    # Run spike with the modified cascade program and obtaint the register dumps
    expected_regvals, elfpath = spike_resolution_return_interm(fuzzerstate)

    pc_reg_pairs_1 = {req[0] + SPIKE_STARTADDR:{} for req in expected_regvals[2]}
    for req, regval in zip(expected_regvals[2],expected_regvals[3]):
        pc_reg_pairs_1[req[0] + SPIKE_STARTADDR][req[2]] = regval


    # Compute the taints from the diffs between the register dumps of the two spike simulations
    pc_reg_taint_pairs = {}
    for (pc0,rd0),(pc1,rd1) in zip(pc_reg_pairs_0.items(),pc_reg_pairs_1.items()):
        pc_reg_taint_pairs[pc0] = {}
        assert pc0 == pc1, f"pc mismatch for {pc0} != {pc1}"
        assert pc0 == inject_addr or len(rd0) == len(rd1), f"regdump length mismatch {len(rd0)} != {len(rd1)} at pc {hex(SPIKE_STARTADDR+pc0)}"
        for (reg0_id, reg0_val),(reg1_id,reg1_val) in zip(rd0.items(),rd1.items()):
            assert pc0 == inject_addr or reg0_id == reg1_id, f"mismatch in reg ids at {pc0}: {ABI_INAMES[reg0_id]}, {ABI_INAMES[reg1_id]}"
            if reg0_val^reg1_val and pc0 != inject_addr:
                print(f"(spike) Taint vector at pc {hex(pc0)} for reg(s) {set([ABI_INAMES[reg_id] for reg_id in [reg0_id,reg1_id]])}: {hex(reg0_val^reg1_val)} ({hex(reg0_val)} ^ {hex(reg1_val)})")
            # zero wont get tainted and at inject_addr the xor comes from the different registers being dumped, not taint
            pc_reg_taint_pairs[pc0][reg0_id] = reg0_val^reg1_val if reg0_id and pc0 != inject_addr else 0
        # if len(pc_reg_taint_pairs[pc0+SPIKE_STARTADDR]) == 0:
        #     del pc_reg_taint_pairs[pc0+SPIKE_STARTADDR]

    return pc_reg_taint_pairs, pc_reg_pairs_1

