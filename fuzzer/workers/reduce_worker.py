from milesan.reduce import reduce_program

from drfuzz_mem.check_isa_sim_taint import check_isa_sim_taint
from common.spike import calibrate_spikespeed
from common.profiledesign import profile_get_medeleg_mask
from milesan.randomize.pickbytecodetaints import MAX_N_INJECT_PER_BB
from milesan.util import CFInstructionClass
from params.runparams import PATH_TO_TMP
from milesan.fuzzfromdescriptor import gen_new_test_instance

import multiprocessing as mp
import time
import threading
import os
import sys

LOG_EXCEPTIONS = True
LOG_EN = True
PRINT_THREAD_STATUS = True
callback_lock = threading.Lock()
newly_finished_tests = 0
total_finished_tests = 0


def test_done_callback(ret):
    global newly_finished_tests
    global callback_lock
    global total_finished_tests
    with callback_lock:
        newly_finished_tests += 1
        if(ret):
            total_finished_tests += 1
            if PRINT_THREAD_STATUS:
                print(ret)
                print(f"Finished {total_finished_tests} threads.")
            
def __reduce_program_worker(design_name, seed):
    try:
        ret = reduce_program(*gen_new_test_instance(design_name,seed,True),check_pc_spike_again=True,quiet=False)
        if LOG_EN:
            logdir = os.path.join(PATH_TO_TMP, "logs")
            os.makedirs(logdir, exist_ok=True)
            with open(f"{logdir}/{design_name}.reduce.log", "a") as f:
                f.write(f"seed {seed}: {ret}\n")
        return ret

    except Exception as e:
        ret = f"reduce_program failed for {design_name} with seed {seed}: {e}"
        print(ret)
        if LOG_EXCEPTIONS:
            logdir = os.path.join(PATH_TO_TMP, "logs")
            os.makedirs(logdir, exist_ok=True)
            with open(f"{logdir}/{design_name}.reduce.failed.log", "a") as f:
                f.write(f"seed {seed}: {str(e)}\n")
        return ret
        
# Helps with suppressing the verbose outputs
def mute():
    sys.stdout = open(os.devnull, 'w')

def reduce_programs(design_name: str, num_cores: int, seeds, mute_output: bool = False):
    global newly_finished_tests
    global callback_lock

    process_instance_id = 0
    num_workers = num_cores
    assert num_workers > 0
    calibrate_spikespeed()
    profile_get_medeleg_mask(design_name)
    if num_workers == 1:
        print(f"Starting sequential reduction on `{design_name}` with {len(seeds)} total tests")
        for seed in seeds:
            __reduce_program_worker(design_name, seed)
            
        exit(0)
    print(f"Starting parallel reduction of `{design_name}` on {num_workers} processes for {len(seeds)} seeds.")
    pool = mp.Pool(processes=num_workers, initializer=mute if mute_output else None)

    for _ in range(min(num_workers,len(seeds))):
        if PRINT_THREAD_STATUS:
            print(f"Starting thread {process_instance_id}.")
        pool.apply_async(__reduce_program_worker, args=(design_name, seeds[process_instance_id]),callback=test_done_callback)
        process_instance_id += 1

    
    while True:
        time.sleep(2)
        with callback_lock:
            if newly_finished_tests > 0 and process_instance_id < len(seeds):
                for _ in range(newly_finished_tests):
                    if process_instance_id >= len(seeds):
                        break
                    if PRINT_THREAD_STATUS:
                        print(f"Starting thread {process_instance_id}.")
                    pool.apply_async(__reduce_program_worker, args=(design_name, seeds[process_instance_id]),callback=test_done_callback)
                    process_instance_id += 1
                newly_finished_tests = 0
            if total_finished_tests >= len(seeds):
                if PRINT_THREAD_STATUS:
                    print(f"Finished {total_finished_tests} threads for {len(seeds)} seeds. Exiting.")
                pool.terminate()
                return







