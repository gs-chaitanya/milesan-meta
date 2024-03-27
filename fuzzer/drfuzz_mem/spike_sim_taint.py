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
def spike_sim_taint(fuzzerstate, expected_regvals, taint_bit_idx, inject_addr):    
    # get fuzzerstate and expected regvals from program
    pc_reg_pairs_0 = {req[0]:{} for req in expected_regvals[2]}
    for req, regval in zip(expected_regvals[2],expected_regvals[3]):
        pc_reg_pairs_0[req[0]][req[2]] = regval


    # flip a bit in first R12Dinstruction
    injected_taint = False
    bitflip_mask = (0x1)<<taint_bit_idx # flip bit at taint_bit_idx
    for bb_id ,(bb_start_addr, bb_instrs) in enumerate(zip(fuzzerstate.bb_start_addr_seq[:-1], fuzzerstate.instr_objs_seq[:-1])): # skip first and last bb
        if bb_id == 0: continue
        for instr_id_in_bb, instr_obj in enumerate(bb_instrs):
            curr_addr = SPIKE_STARTADDR+bb_start_addr+4*instr_id_in_bb
            if curr_addr != inject_addr: continue
            print(f"Injecting taint at addr: {hex(inject_addr)}: {hex(bitflip_mask)}")
            print(f"rd before inject: {ABI_INAMES[instr_obj.rd]}")
            instr_obj.set_bytecode(instr_obj.gen_bytecode_int(True)^bitflip_mask)
            print(f"rd after inject: {ABI_INAMES[instr_obj.rd]}")
            injected_taint = True
            break
        if injected_taint:
            break
    expected_regvals, elfpath = spike_resolution_return_interm(fuzzerstate)

    pc_reg_pairs_1 = {req[0]:{} for req in expected_regvals[2]}
    for req, regval in zip(expected_regvals[2],expected_regvals[3]):
        pc_reg_pairs_1[req[0]][req[2]] = regval


    pc_reg_taint_pairs = {}
    for (pc0,rd0),(pc1,rd1) in zip(pc_reg_pairs_0.items(),pc_reg_pairs_1.items()):
        pc_reg_taint_pairs[pc0] = {}
        assert pc0 == pc1, f"pc mismatch for {pc0} != {pc1}"
        assert pc0+SPIKE_STARTADDR == inject_addr or len(rd0) == len(rd1), f"regdump length mismatch {len(rd0)} != {len(rd1)} at pc {hex(SPIKE_STARTADDR+pc0)}"
        for (reg0_id, reg0_val),(reg1_id,reg1_val) in zip(rd0.items(),rd1.items()):
            assert pc0+SPIKE_STARTADDR == inject_addr or reg0_id == reg1_id, f"mismatch in reg ids at {pc0+SPIKE_STARTADDR}: {ABI_INAMES[reg0_id]}, {ABI_INAMES[reg1_id]}"
            if reg0_val^reg1_val:
                print(f"Taint vector at pc {hex(pc0)} for reg {set([ABI_INAMES[reg_id] for reg_id in [reg0_id,reg1_id]])}: {hex(reg0_val^reg1_val)}")
                pc_reg_taint_pairs[pc0][reg0_id] = reg0_val^reg1_val

        if len(pc_reg_taint_pairs[pc0]) == 0:
            del pc_reg_taint_pairs[pc0]

    return pc_reg_taint_pairs, pc_reg_pairs_1
