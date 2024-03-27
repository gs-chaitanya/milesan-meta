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
from drfuzz_mem.spike_sim_taint import spike_sim_taint

def check_isa_sim_taint(design_name: str,seed: int):    
    # get fuzzerstate and expected regvals from program
    fuzzerstate, interm_elfpath, expected_regvals  = gen_fuzzerstate_elf_expectedvals_interm(*gen_new_test_instance(design_name, seed, True), True)
    print(f"export SIMSRAMELF={interm_elfpath}")
    taint_bit_idx = 0x7
    inject_addr = 0x800ec620
    # expected regvals of the program where the bit was flipped, which is the one that will be executed
    pc_reg_taint_pairs, pc_reg_pairs = spike_sim_taint(fuzzerstate, expected_regvals, taint_bit_idx, inject_addr)


    ID = fuzzerstate.instance_to_str()
    ## temp dirs below
    env_dir = os.path.join(PATH_TO_TMP, 'envs')
    env_path = os.path.join(env_dir,f'{ID}.env.sh')

    env = os.environ.copy()
    env["SIMSRAMELF"] = interm_elfpath
    env["ID"] = str(ID)
    env["DESIGN"] = design_name
    env["SEED"] = str(seed)

    # print(f"source {env_path}")
    with open(env_path, "w") as f:
        f.write(f"export SIMSRAMELF={env['SIMSRAMELF']}\n")
        f.write(f"export SIMSRAMELF_DUMP={env['SIMSRAMELF']}.dump\n")
        f.write(f"export SEED={env['SEED']}\n")
        f.write(f"export ID={env['ID']}\n")

    for i,reg_data_content in enumerate(fuzzerstate.initial_reg_data_content):
        fuzzerstate.intregpickstate.regs[i+1].set_val(reg_data_content) # skip reg 0
        # print(f"{fuzzerstate.intregpickstate.regs[i+1].abi_name}:{hex(fuzzerstate.intregpickstate.regs[i+1].get_val())}")
    
    fuzzerstate.intregpickstate.regs[RELOCATOR_REGISTER_ID].set_val(SPIKE_STARTADDR)
    fuzzerstate.intregpickstate.regs[RDEP_MASK_REGISTER_ID].set_val(MAX_32b)

    try:
        for bb_id ,(bb_start_addr, bb_instrs) in enumerate(zip(fuzzerstate.bb_start_addr_seq, fuzzerstate.instr_objs_seq)): # skip first and last bb
            for inst_idx,next_instr in enumerate(bb_instrs):
                curr_addr = bb_start_addr + 4*inst_idx
                if not any([isinstance(next_instr,inst_type) for inst_type in CHECKABLE_INSTRUCTION_CLASSES]): continue
                next_instr.check_regs(pc_reg_pairs[curr_addr],SPIKE_STARTADDR+curr_addr) # check value before executing instruction
                next_instr.execute()
                # next_instr.log(SPIKE_STARTADDR+curr_addr)

        expected_intregvals = expected_regvals[0]
        # print("*** CASCADE ***:")
        # fuzzerstate.intregpickstate.print()

        # print("*** SPIKE ***:")
        # for i,reg in enumerate(expected_intregvals): # skip reg 0
        #     print(f"{ABI_INAMES[i+1]}:{hex(reg)}")

        # print("*** VALIDATION ***:")
        for i,reg in fuzzerstate.intregpickstate.regs.items():
            if i == 0: continue  # skip reg 0
            if i == RELOCATOR_REGISTER_ID: continue
            if i == RDEP_MASK_REGISTER_ID: continue # is overwritten in final BB
            reg.check(expected_intregvals[i],fuzzerstate.curr_addr)

    except Exception as e:
        # os.removedirs(trace_dir)
        # if os.path.isfile(env_path): os.remove(env_path)
        # if os.path.isfile(interm_elfpath): os.remove(interm_elfpath)
        print(f"Failed for seed {seed}")
        raise e

    return True



