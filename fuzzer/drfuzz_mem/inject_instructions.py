import os, random, numpy as np

from params.runparams import PATH_TO_TMP, PATH_TO_COV
from cascade.fuzzfromdescriptor import NUM_MAX_BBS_UPPERBOUND, gen_fuzzerstate_elf_expectedvals_interm, gen_new_test_instance
from cascade.cfinstructionclasses import RegImmInstruction,R12DInstruction
import subprocess, itertools
from common import designcfgs
from cascade.randomize.pickbytecodetaints import CFINSTRCLASS_INJECT_PROBS
MAX_CYCLES_PER_INSTR = 30
SETUP_CYCLES = 1000 # Without this, we had issues with BOOM with very short programs (typically <20 instructions) not being able to finish in time.
def gen_elf_and_inject_instructions(design_name, max_n_insts_per_bb, en_taint,seed):    
    fuzzerstate, interm_elfpath  = gen_fuzzerstate_elf_expectedvals_interm(*gen_new_test_instance(design_name, seed, True), True)
    ID = fuzzerstate.instance_to_str()
    root_dir = os.path.join(PATH_TO_COV,fuzzerstate.design_name,"drfuzz" if en_taint else "rfuzz", ID)
    cov_dir = os.path.join(root_dir,"cov")
    q_dir = os.path.join(root_dir,"queues")
    ## temp dirs below
    mut_dir = os.path.join(PATH_TO_TMP, 'mut_insts')
    mut_inst_path = os.path.join(mut_dir, f'{ID}.mut_inst.json')
    trace_dir = os.path.join(PATH_TO_TMP, 'tracefiles')
    tracefile = os.path.join(trace_dir, f'{ID}.trace.vcd')
    env_dir = os.path.join(PATH_TO_TMP, 'envs')
    env_path = os.path.join(env_dir,f'{ID}.env.sh')

    insts = {}
    for bb_id ,(bb_start_addr, bb_instrs) in enumerate(zip(fuzzerstate.bb_start_addr_seq[:-1], fuzzerstate.instr_objs_seq[:-1])): # skip first and last bb
        if bb_id == 0: continue
        insts[bb_id] = []
        for instr_id_in_bb, instr_obj in enumerate(bb_instrs):
            p_pick = CFINSTRCLASS_INJECT_PROBS[instr_obj.instr_type]
            if np.random.choice([True,False],1,p=[p_pick,1-p_pick])[0]:
                addr = bb_start_addr + 4*instr_id_in_bb
                insts[bb_id] += [{"bytecode":instr_obj.gen_bytecode_int(is_spike_resolution=True),
                                "bytecode_t0":instr_obj.gen_bytecode_int_t0(is_spike_resolution=True),
                                "addr": addr,
                                "type":instr_obj.instr_type.name, 
                                "str": instr_obj.instr_str,
                                "bb_id":bb_id}]

    inst_str_blocks = []
    assert(len(insts)), "No instructions chosen for injection, exiting."
    for bb_start_addr, block_insts in insts.items():
        if len(block_insts) == 0: continue
        chosen_idxs = [] # keep track of chosen instructions so we dont have duplicates within a block
        for _ in range(min(max_n_insts_per_bb,len(block_insts))):
            idx = random.randint(0,len(block_insts)-1) if len(block_insts)>1 else 0
            while(idx in chosen_idxs):
                idx = random.randint(0,len(block_insts)-1) if len(block_insts)>1 else 0
            chosen_idxs += [idx]
            mut_inst = block_insts[idx]

            inst_str_b = "\t\t{\n"
            inst_str_b += f"\t\t\t" + "\"addr\":" + "\"" + hex(mut_inst["addr"]) + "\",\n" 
            inst_str_b += f"\t\t\t" + "\"bytecode\":" + "\"" + hex(mut_inst["bytecode"]) + "\",\n" 
            inst_str_b += f"\t\t\t" + "\"bytecode_t0\":" + "\"" + hex(mut_inst["bytecode_t0"]) + "\",\n"
            inst_str_b += f"\t\t\t" + "\"type\":" + "\"" + mut_inst["type"] + "\",\n"
            inst_str_b += f"\t\t\t" + "\"str\":" + "\"" + mut_inst["str"] + "\",\n"
            inst_str_b += f"\t\t\t" + "\"bb_id\":" + "\"" + hex(mut_inst["bb_id"]) + "\",\n"
            inst_str_b += f"\t\t\t" + "\"load\":true\n"
            inst_str_b += "\t\t}"
            inst_str_blocks += [inst_str_b]

    inst_str = f"[\n"
    for inst_str_b in inst_str_blocks[:-1]:
        inst_str += inst_str_b + ",\n"
    
    inst_str += inst_str_blocks[-1] + "\n]" 

    os.makedirs(mut_dir,exist_ok=True)
    with open(mut_inst_path, "w") as f:
        f.write(inst_str)


    num_instrs = len(list(itertools.chain.from_iterable(fuzzerstate.instr_objs_seq)))

    env = os.environ.copy()
    env["SIMSRAMELF"] = interm_elfpath
    env["ID"] = ID
    env["SIMLEN"] =str(num_instrs*MAX_CYCLES_PER_INSTR + SETUP_CYCLES)
    env["MUT_INST_PATH"] = mut_inst_path
    env["Q_DIR"] = q_dir
    env["COV_DIR"] = cov_dir
    env["TRACEFILE"] = tracefile
    cmd = ["make","rerun_drfuzz_mem_notrace" if en_taint else "rerun_rfuzz_mem_notrace"]
    os.makedirs(cov_dir,exist_ok=True)
    os.makedirs(q_dir,exist_ok=True)
    os.makedirs(trace_dir,exist_ok=True)
    os.makedirs(env_dir,exist_ok=True)

    print(f"source {env_path}")
    with open(env_path, "w") as f:
        f.write(f"export SIMSRAMELF={env['SIMSRAMELF']}\n")
        f.write(f"export SIMSRAMELF_DUMP={env['SIMSRAMELF']}.dump\n")
        f.write(f"export MUT_INST_PATH={env['MUT_INST_PATH']}\n")

    cascadedir = designcfgs.get_design_cascade_path(fuzzerstate.design_name)
    try:
        subprocess.run(cmd,cwd=cascadedir,env=env,capture_output=False)
    except Exception as e:
        os.removedirs(root_dir)
        os.removedirs(trace_dir)
        # os.removedirs(env_dir)
        raise e

