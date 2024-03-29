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

MAX_CYCLES_PER_INSTR = 30
SETUP_CYCLES = 1000 # Without this, we had issues with BOOM with very short programs (typically <20 instructions) not being able to finish in time.
def check_isa_sim(design_name: str,seed: int):    
    fuzzerstate, interm_elfpath, expected_regvals  = gen_fuzzerstate_elf_expectedvals_interm(*gen_new_test_instance(design_name, seed, True), True)
    ID = fuzzerstate.instance_to_str()
    ## temp dirs below
    env_dir = os.path.join(PATH_TO_TMP, 'envs')
    env_path = os.path.join(env_dir,f'{ID}.env.sh')

    env = os.environ.copy()
    env["SIMSRAMELF"] = interm_elfpath
    env["ID"] = str(ID)
    env["DESIGN"] = design_name
    env["SEED"] = str(seed)

    print(f"source {env_path}")
    with open(env_path, "w") as f:
        f.write(f"export SIMSRAMELF={env['SIMSRAMELF']}\n")
        f.write(f"export SIMSRAMELF_DUMP={env['SIMSRAMELF']}.dump\n")
        f.write(f"export SEED={env['SEED']}\n")
        f.write(f"export ID={env['ID']}\n")

    pc_rd_pairs = {req[0] + SPIKE_STARTADDR:{} for req in expected_regvals[2]}
    for req, regval in zip(expected_regvals[2],expected_regvals[3]):
        pc_rd_pairs[req[0] + SPIKE_STARTADDR][req[2]] = regval

    for i,reg_data_content in enumerate(fuzzerstate.initial_reg_data_content):
        fuzzerstate.intregpickstate.regs[i+1].set_val(reg_data_content) # skip reg 0
        # print(f"{fuzzerstate.intregpickstate.regs[i+1].abi_name}:{hex(fuzzerstate.intregpickstate.regs[i+1].get_val())}")
    
    fuzzerstate.intregpickstate.regs[RELOCATOR_REGISTER_ID].set_val(SPIKE_STARTADDR)
    fuzzerstate.intregpickstate.regs[RDEP_MASK_REGISTER_ID].set_val(MAX_32b)

    try:
        for bb_id ,(bb_start_addr, bb_instrs) in enumerate(zip(fuzzerstate.bb_start_addr_seq, fuzzerstate.instr_objs_seq)): # skip first and last bb
            for inst_idx,next_instr in enumerate(bb_instrs):
                if not isinstance(next_instr, CHECKABLE_INSTRUCTION_CLASSES): continue
                if next_instr.addr not in pc_rd_pairs:
                    print(f"Skipping check for {next_instr.get_str()}")
                    continue
                next_instr.check_regs(pc_rd_pairs[next_instr.addr]) # check value before executing instruction
                next_instr.execute(False)
                # next_instr.log(SPIKE_STARTADDR+curr_addr)

        expected_intregvals = expected_regvals[0]
        # print("*** CASCADE ***:")
        # fuzzerstate.intregpickstate.print()

        # print("*** SPIKE ***:")
        # for i,reg in enumerate(expected_intregvals): # skip reg 0
        #     print(f"{ABI_INAMES[i+1]}: {hex(reg)}")

        # print("*** VALIDATION ***:")
        for i,reg in fuzzerstate.intregpickstate.regs.items():
            if i == 0: continue  # skip reg 0
            if i == RELOCATOR_REGISTER_ID: continue
            if i == RDEP_MASK_REGISTER_ID: continue # is overwritten in final BB
            reg.check(expected_intregvals[i],fuzzerstate.curr_addr)
        # print("Ok.")
    except Exception as e:
        # os.removedirs(trace_dir)
        # if os.path.isfile(env_path): os.remove(env_path)
        # if os.path.isfile(interm_elfpath): os.remove(interm_elfpath)
        print(f"Failed for seed {seed}")
        raise e

    return True



