from params.runparams import PATH_TO_TMP, PATH_TO_COV, 
from cascade.fuzzfromdescriptor import NUM_MAX_BBS_UPPERBOUND, gen_fuzzerstate_elf_expectedvals_interm, gen_new_test_instance
import os, random
from cascade.cfinstructionclasses import RegImmInstruction,R12DInstruction
import subprocess, itertools
from common import designcfgs
MAX_CYCLES_PER_INSTR = 30
SETUP_CYCLES = 1000 # Without this, we had issues with BOOM with very short programs (typically <20 instructions) not being able to finish in time.

def gen_elf_and_inject_taints(design_name, max_n_insts_per_bb, seed):
    # fuzzerstate, rtl_elfpath, interm_elfpath, _, _, _, _  = gen_fuzzerstate_elf_expectedvals(*gen_new_test_instance(DESIGN_NAME, 0, True), True)
    
    fuzzerstate, interm_elfpath  = gen_fuzzerstate_elf_expectedvals_interm(*gen_new_test_instance(design_name, seed, True), True)
    ID = fuzzerstate.instance_to_str()
    cov_dir = os.path.join(PATH_TO_COV,fuzzerstate.design_name,'drfuzz_mem',ID,"cov")
    q_dir = os.path.join(PATH_TO_COV,fuzzerstate.design_name,'drfuzz_mem',ID,"queue")
    mut_inst_path = os.path.join(PATH_TO_TMP, f'{ID}.mut_inst.json')
    tracefile = os.path.join(PATH_TO_TMP, f'{ID}.trace.vcd')
    env_path = os.path.join(PATH_TO_TMP, f'{ID}.env.sh')
    exclude_regs = {0,1,2,3,4,5,8,9}
    # exclude_reg_imm_insts = {"slliw","srliw","sraiw","slli","srli","srai"} # #cycles for shifts depends on immediate value thus taints pc
    # exclude_insts |= {"addi","addiw"} # how do they influnce taint?
    # mut_insts = {"slliw","srliw","sraiw","slli","srli","srai"} 
    insts = {}
    for bb_id ,(bb_start_addr, bb_instrs) in enumerate(zip(fuzzerstate.bb_start_addr_seq[:-1], fuzzerstate.instr_objs_seq[:-1])): # skip first and last bb
        if bb_id == 0: continue
        insts[bb_id] = []
        for instr_id_in_bb, instr_obj in enumerate(bb_instrs):
            if isinstance(instr_obj, RegImmInstruction):
                # if instr_obj.instr_str not in mut_insts: continue
                if len({instr_obj.rs1, instr_obj.rd} & exclude_regs): continue  # dont taint rs1 if its tp, sp etc
                addr = bb_start_addr + 4*instr_id_in_bb
                insts[bb_id] += [{"bytecode":instr_obj.gen_bytecode_int(is_spike_resolution=True),
                                "bytecode_t0":instr_obj.gen_bytecode_int_t0(is_spike_resolution=True),
                                "addr": addr,
                                "type":"I", 
                                "str": instr_obj.instr_str,
                                "bb_id":bb_id}]
            # elif isinstance(instr_obj, R12DInstruction):
            #     if len({instr_obj.rs1, instr_obj.rs2, instr_obj.rd} & exclude_regs): continue # at 0x5 the temp regs start, below is tp, gp, sp, ra and zero which we dont want to mutate on
            #     bytecode = instr_obj.gen_bytecode_int(is_spike_resolution=True)
            #     addr = bb_start_addr + 4*instr_id_in_bb
            #     insts[bb_id] += [{"bytecode":bytecode,
            #                     "bytecode_t0": 0x1F<<20, 
            #                     "addr": addr,
            #                     "type":"R", 
            #                     "str": instr_obj.instr_str,
            #                     "bb_id":bb_id}] # dont taint rs2 if its tp, sp etc
            #     insts[bb_id] += [{"bytecode":bytecode,
            #                     "bytecode_t0": 0x1F<<15, 
            #                     "addr": addr,
            #                     "type":"R", 
            #                     "str": instr_obj.instr_str,
            #                     "bb_id":bb_id}] # same for rs1
            #     insts[bb_id] += [{"bytecode":bytecode,"bytecode_t0": 0x1F<<7, "addr": addr,"type":"R"}] # RD, might break CF

    inst_str_blocks = []
    assert(len(insts)), "No instructions chosen for injection."
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


    with open(mut_inst_path, "w") as f:
        f.write(inst_str)


    num_instrs = len(list(itertools.chain.from_iterable(fuzzerstate.instr_objs_seq)))

    env = os.environ.copy()
    env["SIMSRAMELF"] = interm_elfpath
    env["ID"] = ID
    env["SIMLEN"] = num_instrs*MAX_CYCLES_PER_INSTR + SETUP_CYCLES
    env["MUT_INST_PATH"] = mut_inst_path
    env["COV_DIR"] = cov_dir
    env["Q_DIR"] = q_dir
    env["TRACEFILE"] = tracefile
    cmd = ["make","rerun_drfuzz_mem_notrace"]
    os.makedirs(q_dir)
    os.makedirs(cov_dir)

    print(f"source {env_path}")
    with open(env_path, "w") as f:
        f.write(f"export SIMSRAMELF={env['SIMSRAMELF']}\n")
        f.write(f"export SIMSRAMELF_DUMP={env['SIMSRAMELF']}.dump\n")
        f.write(f"export MUT_INST_PATH={env['MUT_INST_PATH']}\n")

    cascadedir = designcfgs.get_design_cascade_path(fuzzerstate.design_name)
    subprocess.run(cmd,cwd=cascadedir,env=env,capture_output=False)

    

    # print(f"DrFUZZ: export COV_DIR={cov_dir_drfuzz}")
    # print(f"RFUZZ: export COV_DIR={cov_dir_rfuzz}")
    # print(f"FINAL: export SIMSRAMELF={rtl_elfpath}")
    # print(f"INTERMEDIATE: export SIMSRAMELF={interm_elfpath}")
    # print(f"export SIMSRAMTAINT={fuzzerstate.simsramtaint_path}")
    # print(f"export EXPECTED_REVAlS={fuzzerstate.expected_regvals_path}")
    # print(f"export MUT_INST_PATH={mut_inst_path}")