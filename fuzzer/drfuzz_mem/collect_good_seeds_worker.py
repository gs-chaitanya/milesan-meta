import multiprocessing as mp
import time
import threading
import numpy as np
import pandas as pd
import traceback
import shutil
import os
import glob
from drfuzz_mem.inject_instructions import gen_elf_and_inject_instructions
from milesan.fuzzfromdescriptor import gen_new_test_instance
from common.spike import calibrate_spikespeed
from common.profiledesign import profile_get_medeleg_mask
from milesan.randomize.pickbytecodetaints import MAX_N_INJECT_PER_BB
from milesan.util import CFInstructionClass
from params.runparams import PATH_TO_TMP, PATH_TO_COV

N_COV_PTS = 1517 # rocket
REMOVE_TMP_FILES = False

callback_lock = threading.Lock()
newly_finished_tests = 0
total_finished_tests = 0
seed_cov_map = [0]*N_COV_PTS
seed_cov_t0_map = [0]*N_COV_PTS
seed_corpus = []
tainted_and_untoggled = [0]*N_COV_PTS

def cleanup(design_name,en_taint,seeds):
    print("Killing remaning threads and cleaning up.")
    root_dir = os.path.join(PATH_TO_COV,design_name,"drfuzz" if en_taint else "rfuzz")
    dirs = glob.glob(f"{root_dir}/*")
    for dir in dirs:
        if int(dir.split("/")[-1].split("_")[-2]) not in seeds:
            print(f'removing {dir}: {dir.split("/")[-1].split("_")[-2]} not in {seeds}')
            shutil.rmtree(dir)

def test_done_callback(ret):
    global newly_finished_tests
    global total_finished_tests
    global callback_lock
    global seed_corpus
    global seed_cov_map
    global seed_cov_t0_map
    global tainted_and_untoggled
    with callback_lock:
        newly_finished_tests += 1
        total_finished_tests += 1
        if(ret):
            q = ret[0]
            seed = ret[1]
            en_taint = "cov_t0" in q
            # if en_taint:
            #     # interesting = [e for e,(i,j,k,l) in enumerate(zip(seed_cov_t0_map, seed_cov_map, q["cov_t0"], q["cov"])) if (k and not i and not j and not l) or (l and not j)]
            #     interesting = [e for e,(i,j) in enumerate(zip(seed_cov_t0_map, q["cov_t0"])) if j and not i]
            # else:
            #     # interesting = [e for e,(i,j) in enumerate(zip(seed_cov_map, q["cov"])) if (j and not i)]
            #     interesting = [1]
            # if len(interesting):
            if True:
                seed_cov_map = [i or j for i,j in zip(seed_cov_map,q["cov"])]
                if en_taint:
                    seed_cov_t0_map = [i or j for i,j in zip(seed_cov_t0_map,q["cov_t0"])]
                    tainted_and_untoggled = [i and not j for i,j in zip(seed_cov_t0_map,seed_cov_map)]
                seed_corpus += [seed]
                print(f"Collected {len(seed_corpus)} seed(s) that taint {np.count_nonzero(seed_cov_t0_map)}/{N_COV_PTS} and toggle {np.count_nonzero(seed_cov_map)}/{N_COV_PTS} coverage pts. {np.count_nonzero(tainted_and_untoggled)} are tainted and not toggled.")
            elif REMOVE_TMP_FILES:
                shutil.rmtree(q["root_dir"])
                os.remove(q["elf"])
                os.remove(q["env"])
                print(f"Seed does not contribute any new coverage pts to corpus of {len(seed_corpus)} seeds.")



def __collect_good_seeds_worker(design_name: str, max_n_insts_per_bb: int, en_taint: bool, seed: int, fuzz_only_this_inst_type = None):
    try:
        return gen_elf_and_inject_instructions(design_name, max_n_insts_per_bb, en_taint, seed, fuzz_only_this_inst_type)
    except Exception as e:
        print(f"__collect_good_seeds_worker failed for: {design_name},{max_n_insts_per_bb},{seed}: {e}")
        # print(traceback.format_exc())
        return 0


def collect_good_seeds(design_name: str, num_cores: int, total_tests: int, en_taint: bool, seed_offset: int, can_authorize_priviles: bool, max_n_seeds: int):
    global newly_finished_tests
    global callback_lock
    global seed_corpus
    global seed_cov_map
    global seed_cov_t0_map
    global tainted_and_untoggled
    global total_finished_tests

    process_instance_id = 0
    if seed_offset is not None: process_instance_id += seed_offset
    num_workers = num_cores
    assert num_workers > 0
    calibrate_spikespeed()
    profile_get_medeleg_mask(design_name)
    if num_workers == 1:
        for _ in range(total_tests):
            print(f"Starting serial collection of up to {max_n_seeds} seeds for `{design_name}`.")
            ret = gen_elf_and_inject_instructions(design_name,MAX_N_INJECT_PER_BB,en_taint, process_instance_id, None)
            q = ret[0]
            seed = ret[1]
            if en_taint:
                interesting = [e for e,(i,j,k,l) in enumerate(zip(seed_cov_t0_map, seed_cov_map, q["cov_t0"], q["cov"])) if (k or l) and not i and not j]
            else:
                interesting = [e for e,(i,j) in enumerate(zip(seed_cov_map, q["cov"])) if (j and not i)]
            if len(interesting):
                seed_cov_map = [i or j for i,j in zip(seed_cov_map,q["cov"])]
                if en_taint:
                    seed_cov_t0_map = [i or j for i,j in zip(seed_cov_map,q["cov_t0"])]
                seed_corpus += [seed]
                print(f"Collected {len(seed_corpus)} seed(s) that taint {np.count_nonzero(seed_cov_t0_map)}/{N_COV_PTS} coverage pts.")
        return seed_corpus

    print(f"Starting parallel collection of up to {max_n_seeds} seeds with {total_tests} total tests for `{design_name}` on {num_workers} processes.")
    pool = mp.Pool(processes=num_workers)
    for _ in range(num_workers):
        print(f"Starting thread {process_instance_id}")
        pool.apply_async(__collect_good_seeds_worker, args=(design_name, MAX_N_INJECT_PER_BB, en_taint, process_instance_id),callback=test_done_callback)
        process_instance_id += 1

    
    while True:
        time.sleep(2)
        with callback_lock:
            if newly_finished_tests > 0:
                for _ in range(newly_finished_tests):
                    print(f"Starting thread {process_instance_id}, collected {len(seed_corpus)} seeds.")
                    pool.apply_async(__collect_good_seeds_worker, args=(design_name, MAX_N_INJECT_PER_BB, en_taint, process_instance_id),callback=test_done_callback)
                    process_instance_id += 1
                newly_finished_tests = 0
            if total_finished_tests >= total_tests or np.count_nonzero(seed_cov_t0_map) >= N_COV_PTS or len(seed_corpus) >= max_n_seeds:
                print(f"Finished {total_finished_tests} threads. Collected {len(seed_corpus)} seeds that taint {np.count_nonzero(seed_cov_t0_map)}/{N_COV_PTS} coverage pts:\n {seed_corpus}")
                cleanup(design_name,en_taint,seed_corpus)
                pool.terminate()
                return seed_corpus












