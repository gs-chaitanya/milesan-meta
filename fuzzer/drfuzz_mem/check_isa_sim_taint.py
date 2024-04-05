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
    try:
        # get fuzzerstate and expected regvals from program
        print(f"Starting program generation and ad-hoc simulation.(FSM instructions are ignored.)")
        fuzzerstate, interm_elfpath, expected_regvals  = gen_fuzzerstate_elf_expectedvals_interm(*gen_new_test_instance(design_name, seed, True), True)
        # Expected regvals of the program where bit was flipped are in in pc_reg_pairs1, which is the one that will be executed in the crossvalidation.
        # Initial program register dumps are in pc_reg_pairs_0, TODO: should this also be executed and checked?

        ID = fuzzerstate.instance_to_str()
        ## temp dirs below
        env_dir = os.path.join(PATH_TO_TMP, 'envs')
        env_path = os.path.join(env_dir,f'{ID}.env.sh')
        regdump_path = os.path.join(PATH_TO_TMP, f"{ID}.regump.json")

        env = os.environ.copy()
        env["SIMSRAMELF"] = interm_elfpath
        env["ID"] = str(ID)
        env["DESIGN"] = design_name
        env["SEED"] = str(seed)
        env["REGDUMP_PATH"] = regdump_path
        env["SIMSRAMTAINT"] = os.path.join(PATH_TO_TMP, f"{ID}.memview.t0.json")

        with open(env_path, "w") as f:
            f.write(f"export SIMSRAMELF={env['SIMSRAMELF']}\n")
            f.write(f"export SIMSRAMELF_DUMP={env['SIMSRAMELF']}.dump\n")
            f.write(f"export SEED={env['SEED']}\n")
            f.write(f"export ID={env['ID']}\n")

        # print("*** ENVIRONMENT ***")
        # print(f"source {env_path}")

        # print("*** REGISTER STATES ***:")
        # fuzzerstate.intregpickstate.print()
    

        pc_reg_pairs1 = {req[0] + SPIKE_STARTADDR:{} for req in expected_regvals[2]}
        for req, regval in zip(expected_regvals[2],expected_regvals[3]):
            pc_reg_pairs1[req[0] + SPIKE_STARTADDR][req[2]] = regval

        # fuzzerstate.intregpickstate.set_initial_values(fuzzerstate)
        fuzzerstate.intregpickstate.reset()
        fuzzerstate.intregpickstate.set_spike_boot_values()
        fuzzerstate.memview.restore()
        # print(f"Starting spike cross-validation. (FSM instructions are accounted for.)")
        for bb_id ,(bb_start_addr, bb_instrs) in enumerate(zip(fuzzerstate.bb_start_addr_seq, fuzzerstate.instr_objs_seq)): # skip first and last bb
            for inst_idx,next_instr in enumerate(bb_instrs):
                if next_instr.addr not in pc_reg_pairs1:
                    # print(f"Skipping check for {next_instr.get_str()}")
                    continue
                next_instr.check_regs(pc_reg_pairs1[next_instr.addr]) # check value before executing instruction
                # if check_taint:
                #     next_instr.check_regs_t0(pc_reg_taint_pairs[next_instr.addr]) # check value before executing instruction
                next_instr.execute(fuzzerstate.taint_en)
                # next_instr.print()
                # next_instr.log(SPIKE_STARTADDR+curr_addr)

        expected_intregvals = expected_regvals[0]
        # print("*** CASCADE ***:")
        # fuzzerstate.intregpickstate.print()

        # print("*** SPIKE ***:")
        # for i,reg in enumerate(expected_intregvals): # skip reg 0
        #     print(f"{ABI_INAMES[i+1]}:{hex(reg)}")

        cmd = ["make","rerun_drfuzz_mem_notrace"]
        cascadedir = designcfgs.get_design_cascade_path(fuzzerstate.design_name)
        subprocess.run(cmd,cwd=cascadedir,env=env,capture_output=True,check=True)
        check_regs = False
        if check_regs:
            with open(regdump_path, "rb") as f:
                regdumps_rtl = json.load(f)

            print("*** REGISTER VALIDATION ***:")
            fuzzerstate.intregpickstate.print_and_compare(regdumps_rtl)
            for id in range(fuzzerstate.num_pickable_regs-1):
                value = int(regdumps_rtl[id]["value"],16)
                value_t0 = int(regdumps_rtl[id]["value_t0"],16)
                mismatch = fuzzerstate.intregpickstate.regs[id+1].check(value)
                assert not mismatch, f"Value mismatch for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n"
                mismatch = fuzzerstate.intregpickstate.regs[id+1].check(expected_intregvals[id])
                assert not mismatch, f"Value mismatch for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n"
                mismatch = fuzzerstate.intregpickstate.regs[id+1].check_t0(value_t0)
                assert not mismatch, f"Taint mismatch for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n"

            print("Ok.")


    except Exception as e:
        # os.removedirs(trace_dir)
        # if os.path.isfile(env_path): os.remove(env_path)
        # if os.path.isfile(interm_elfpath): os.remove(interm_elfpath)
        print(f"Failed for seed {seed}")
        raise e

    return True



