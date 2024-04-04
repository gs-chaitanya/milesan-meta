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
    # Expected regvals of the program where bit was flipped are in in pc_reg_pairs1, which is the one that will be executed in the crossvalidation.
    # Initial program register dumps are in pc_reg_pairs_0, TODO: should this also be executed and checked?
    
    assert fuzzerstate.inject_taint_addr is not None, "Did not inject taint."

    ID = fuzzerstate.instance_to_str()
    ## temp dirs below
    env_dir = os.path.join(PATH_TO_TMP, 'envs')
    env_path = os.path.join(env_dir,f'{ID}.env.sh')

    env = os.environ.copy()
    env["SIMSRAMELF"] = interm_elfpath
    env["ID"] = str(ID)
    env["DESIGN"] = design_name
    env["SEED"] = str(seed)

    with open(env_path, "w") as f:
        f.write(f"export SIMSRAMELF={env['SIMSRAMELF']}\n")
        f.write(f"export SIMSRAMELF_DUMP={env['SIMSRAMELF']}.dump\n")
        f.write(f"export SEED={env['SEED']}\n")
        f.write(f"export ID={env['ID']}\n")

    print("*** ENVIRONMENT ***")
    print(f"source {env_path}")

    print("*** REGISTER STATES ***:")
    fuzzerstate.intregpickstate.print()


    
    try:
        if fuzzerstate.inject_taint_addr == -1:
            print("Register taint injection cannot yet be simulated with spike. Only checking values.")
            pc_reg_pairs1 = {req[0] + SPIKE_STARTADDR:{} for req in expected_regvals[2]}
            for req, regval in zip(expected_regvals[2],expected_regvals[3]):
                pc_reg_pairs1[req[0] + SPIKE_STARTADDR][req[2]] = regval

        else:
            print("*** TAINT PROPAGATION CHECK ***")
            pc_reg_taint_pairs, pc_reg_pairs0, pc_reg_pairs1 = spike_sim_taint(fuzzerstate, expected_regvals)


        for i,reg_data_content in enumerate(fuzzerstate.initial_reg_data_content):
            fuzzerstate.intregpickstate.regs[i+1].set_val(reg_data_content) # skip reg 0

        fuzzerstate.intregpickstate.set_initial_values(fuzzerstate)

        for bb_id ,(bb_start_addr, bb_instrs) in enumerate(zip(fuzzerstate.bb_start_addr_seq, fuzzerstate.instr_objs_seq)): # skip first and last bb
            for inst_idx,next_instr in enumerate(bb_instrs):
                if bb_id == 0 and inst_idx != len(bb_instrs)-1: continue
                if not isinstance(next_instr, CHECKABLE_INSTRUCTION_CLASSES): continue
                next_instr.check_regs(pc_reg_pairs1[next_instr.addr]) # check value before executing instruction
                if fuzzerstate.inject_taint_addr != -1:
                    next_instr.check_regs_t0(pc_reg_taint_pairs[next_instr.addr]) # check value before executing instruction
                next_instr.execute(taint_en = True)
                # next_instr.log(SPIKE_STARTADDR+curr_addr)

        expected_intregvals = expected_regvals[0]
        # print("*** CASCADE ***:")
        # fuzzerstate.intregpickstate.print()

        # print("*** SPIKE ***:")
        # for i,reg in enumerate(expected_intregvals): # skip reg 0
        #     print(f"{ABI_INAMES[i+1]}:{hex(reg)}")

        print("*** REGISTER VALIDATION ***:")
        for i,reg in fuzzerstate.intregpickstate.regs.items():
            if i == 0: continue  # skip reg 0
            if i == RELOCATOR_REGISTER_ID: continue
            if i == RDEP_MASK_REGISTER_ID: continue # is overwritten in final BB
            reg.check(expected_intregvals[i])
        print("Ok.")
    except Exception as e:
        # os.removedirs(trace_dir)
        # if os.path.isfile(env_path): os.remove(env_path)
        # if os.path.isfile(interm_elfpath): os.remove(interm_elfpath)
        print(f"Failed for seed {seed}")
        raise e

    return True



