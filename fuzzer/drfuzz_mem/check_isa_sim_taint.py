import os, random, numpy as np
import shutil
import glob
import json

from params.runparams import PATH_TO_TMP, PATH_TO_COV, PRINT_INSTRUCTION_EXECUTION_FINAL, PRINT_ENVIRONMENT
from cascade.fuzzfromdescriptor import NUM_MAX_BBS_UPPERBOUND, gen_fuzzerstate_elf_expectedvals_interm, gen_fuzzerstate_elf_expectedvals, gen_new_test_instance
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
    # print(f"Starting program generation and ad-hoc simulation.(FSM instructions are ignored.)")
    # fuzzerstate, interm_elfpath, expected_regvals  = gen_fuzzerstate_elf_expectedvals_interm(*gen_new_test_instance(design_name, seed, True), True)
    fuzzerstate, rtl_elfpath, expected_regvals,_,_,_  = gen_fuzzerstate_elf_expectedvals(*gen_new_test_instance(design_name, seed, True), True)

    # Expected regvals of the program where bit was flipped are in in pc_reg_pairs1, which is the one that will be executed in the crossvalidation.
    # Initial program register dumps are in pc_reg_pairs_0, TODO: should this also be executed and checked?

    ID = fuzzerstate.instance_to_str()
    ## temp dirs below
    env_dir = os.path.join(PATH_TO_TMP, 'envs')
    env_path = os.path.join(env_dir,f'{ID}.env.sh')
    regdump_path = os.path.join(PATH_TO_TMP, f"{ID}.regump.json")
    simsramtaint_path = os.path.join(PATH_TO_TMP, f"{ID}.memview.t0.json")
    env = os.environ.copy()
    env["SIMSRAMELF"] = rtl_elfpath
    env["ID"] = str(ID)
    env["DESIGN"] = design_name
    env["SEED"] = str(seed)
    env["REGDUMP_PATH"] = regdump_path
    env["SIMSRAMTAINT"] = simsramtaint_path

    with open(env_path, "w") as f:
        f.write(f"export SIMSRAMELF={env['SIMSRAMELF']}\n")
        f.write(f"export SIMSRAMELF_DUMP={env['SIMSRAMELF']}.dump\n")
        f.write(f"export SIMSRAMTAINT={simsramtaint_path}\n")
        f.write(f"export SEED={env['SEED']}\n")
        f.write(f"export ID={env['ID']}\n")

    if PRINT_ENVIRONMENT:
        print("*** ENVIRONMENT ***")
        print(f"source {env_path}")

    # print("*** REGISTER STATES ***:")
    # fuzzerstate.intregpickstate.print()


    pc_reg_pairs1 = {req[0] + SPIKE_STARTADDR:{} for req in expected_regvals[2]}
    for req, regval in zip(expected_regvals[2],expected_regvals[3]):
        pc_reg_pairs1[req[0] + SPIKE_STARTADDR][req[2]] = regval

    # fuzzerstate.intregpickstate.set_initial_values(fuzzerstate)
    fuzzerstate.intregpickstate.setup_registers()
    fuzzerstate.memview.restore()
    # print(f"Starting spike cross-validation. (FSM instructions are accounted for.)")
    for bb_id ,(bb_start_addr, bb_instrs) in enumerate(zip(fuzzerstate.bb_start_addr_seq, fuzzerstate.instr_objs_seq)): # skip first and last bb
        for inst_idx,next_instr in enumerate(bb_instrs):
            if next_instr.addr not in pc_reg_pairs1:
                # print(f"Skipping check for {next_instr.get_str(True)}")
                continue
            if not is_placeholder(next_instr):
                next_instr.check_regs(pc_reg_pairs1[next_instr.addr]) # check value before executing instruction. Skip if placeholder as their values change between spikeresol and final elf.
            # if check_taint:
            #     next_instr.check_regs_t0(pc_reg_taint_pairs[next_instr.addr]) # check value before executing instruction
            next_instr.execute(fuzzerstate.taint_en, is_spike_resolution=False)
            if PRINT_INSTRUCTION_EXECUTION_FINAL:
                next_instr.print(False)
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

    with open(regdump_path, "rb") as f:
        regdumps_rtl = json.load(f)

    try:

        for (addr_spike,trace_spike),(addr_final, trace_final) in zip(fuzzerstate.intregpickstate.writeback_trace_spikeresol.items(),fuzzerstate.intregpickstate.writeback_trace_final.items()):
            assert addr_spike == addr_final
            assert trace_spike[0] == trace_final[0]
            assert trace_spike[1] == trace_final[1], f"Mismatch in trace: {hex(addr_final)}: {ABI_INAMES[trace_spike[0]]} <- {hex(trace_spike[1])}/{hex(trace_final[1])}"
            # else:
            #     print(f"{hex(addr_spike)}: {ABI_INAMES[trace_spike[0]]} <- {hex(trace_spike[1])}")


        # print("*** REGISTER VALIDATION ***:")
        # fuzzerstate.intregpickstate.print_and_compare(regdumps_rtl)
        for id in range(fuzzerstate.num_pickable_regs-1):
            value = int(regdumps_rtl[id]["value"],16)
            value_t0 = int(regdumps_rtl[id]["value_t0"],16)
            mismatch = fuzzerstate.intregpickstate.regs[id+1].check(value)
            assert not mismatch, f"Value mismatch for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n"
            mismatch = fuzzerstate.intregpickstate.regs[id+1].check(expected_intregvals[id])
            assert not mismatch, f"Value mismatch for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n"
            mismatch = fuzzerstate.intregpickstate.regs[id+1].check_t0(value_t0)
            assert not mismatch, f"Taint mismatch for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n\t Traceback: {filter_reg_traceback(id+1, None, fuzzerstate, None, False).get_str(False)}"

            # print("Ok.")





    except Exception as e:
        # os.removedirs(trace_dir)
        # if os.path.isfile(env_path): os.remove(env_path)
        # if os.path.isfile(interm_elfpath): os.remove(interm_elfpath)
        print("*** REGISTER VALIDATION ***:")
        fuzzerstate.intregpickstate.print_and_compare(regdumps_rtl)
        # fuzzerstate.intregpickstate.print()
        print(f"Failed for seed {seed}")
        raise e

    return True



