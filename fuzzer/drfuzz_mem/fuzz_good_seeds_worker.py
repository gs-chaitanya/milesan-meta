from drfuzz_mem.inject_instructions import gen_elf_and_inject_instructions
import multiprocessing as mp
import time
import threading
import numpy as np
import pandas as pd
from common.spike import calibrate_spikespeed
from common.profiledesign import profile_get_medeleg_mask
from milesan.randomize.pickbytecodetaints import MAX_N_INJECT_PER_BB
from milesan.util import CFInstructionClass
N_COV_PTS = 1517 # rocket
callback_lock = threading.Lock()
newly_finished_tests = 0
total_finished_tests = 0
cov_map = [0]*N_COV_PTS

def test_done_callback(ret):
    global newly_finished_tests
    global callback_lock
    global total_finished_tests
    global cov_map
    with callback_lock:
        newly_finished_tests += 1
        total_finished_tests += 1
        if(ret):
            q = ret[0]
            cov_map = [i or j for i,j in zip(cov_map,q["cov"])]
            print(f"Fuzzing {q['id']} in env {q['env']} finished:")
            print(f"Joint coverage: {np.count_nonzero(cov_map)}/{N_COV_PTS}.")
        else:
            print(f"Thread failed.")


def __fuzz_seed_worker(design_name, max_n_insts_per_bb, en_taint, seed, fuzz_only_this_inst_type = None):
    try:
        return gen_elf_and_inject_instructions(design_name, max_n_insts_per_bb, en_taint, seed, fuzz_only_this_inst_type)
    except Exception as e:
        print(f"__fuzz_seeds_worker failed for: {design_name}: seed {seed}: {e}")
        return 0


def fuzz_good_seeds(design_name: str, num_cores: int,seeds, en_taint: bool, can_authorize_priviles: bool):
    global newly_finished_tests
    global callback_lock
    global cov_map

    process_instance_id = 0
    num_workers = num_cores
    assert num_workers > 0
    calibrate_spikespeed()
    profile_get_medeleg_mask(design_name)
    if num_workers == 1:
        for seed in seeds:
            print(f"Starting serial fuzzing for `{design_name}`.")
            gen_elf_and_inject_instructions(design_name,MAX_N_INJECT_PER_BB,en_taint, seeds[process_instance_id], None)
            process_instance_id += 1
        return

    print(f"Starting parallel fuzzing with {len(seeds)} seeds for `{design_name}` on {num_workers} processes.")
    pool = mp.Pool(processes=num_workers)
    for _ in range(num_workers):
        if process_instance_id < len(seeds):
            print(f"Starting thread {process_instance_id}")
            pool.apply_async(__fuzz_seed_worker, args=(design_name, MAX_N_INJECT_PER_BB, en_taint, seeds[process_instance_id]),callback=test_done_callback)
            process_instance_id += 1

    
    while True:
        time.sleep(2)
        with callback_lock:
            if newly_finished_tests > 0:
                for _ in range(newly_finished_tests):
                    if process_instance_id < len(seeds):
                        print(f"Starting thread {process_instance_id}")
                        pool.apply_async(__fuzz_seed_worker, args=(design_name, MAX_N_INJECT_PER_BB, en_taint, seeds[process_instance_id]),callback=test_done_callback)
                        process_instance_id += 1
                newly_finished_tests = 0
            if total_finished_tests >= len(seeds):
                print(f"Finished {total_finished_tests} threads for {len(seeds)} seeds. Total coverage is {np.count_nonzero(cov_map)}/{N_COV_PTS}.")
                pool.terminate()
                return











