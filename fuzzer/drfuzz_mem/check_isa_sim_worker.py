from drfuzz_mem.check_isa_sim_taint import check_isa_sim_taint
from common.spike import calibrate_spikespeed
from common.profiledesign import profile_get_medeleg_mask
from cascade.randomize.pickbytecodetaints import MAX_N_INJECT_PER_BB
from cascade.util import CFInstructionClass
from params.runparams import PATH_TO_TMP

import multiprocessing as mp
import time
import threading
import os

LOG_EXCEPTIONS = True
PRINT_THREAD_STATUS = False
callback_lock = threading.Lock()
newly_finished_tests = 0
total_finished_tests = 0


def test_done_callback(ret):
    global newly_finished_tests
    global callback_lock
    global total_finished_tests
    with callback_lock:
        newly_finished_tests += 1
        # if(ret):
        total_finished_tests += 1
        if PRINT_THREAD_STATUS:
            print(f"Finished {total_finished_tests} threads.")


def __check_isa_sim_worker(design_name, seed, taint_en):
    try:
        check_isa_sim_taint(design_name,seed, taint_en=taint_en).remove_tmp_files()
        return True
    except Exception as e:
        print(f"check_isa_sim_worker failed for {design_name} with seed {seed}: {str(e)}")
        if LOG_EXCEPTIONS:
            if "(RTL) Taint mismatch" in str(e):
                logdir = os.path.join(PATH_TO_TMP, "logs")
                os.makedirs(logdir, exist_ok=True)
                with open(f"{logdir}/{design_name}.taint_mismatch.log", "a") as f:
                    f.write(f"seed {seed}: {str(e)}\n")
            elif "(RTL) Value mismatch" in str(e):
                logdir = os.path.join(PATH_TO_TMP, "logs")
                os.makedirs(logdir, exist_ok=True)
                with open(f"{logdir}/{design_name}.value_mismatch.log", "a") as f:
                    f.write(f"seed {seed}: {str(e)}\n")
            elif "Command" in str(e):
                logdir = os.path.join(PATH_TO_TMP, "logs")
                os.makedirs(logdir, exist_ok=True)
                with open(f"{logdir}/{design_name}.timeout.log", "a") as f:
                    f.write(f"seed {seed}: {str(e)}\n")
            else:
                logdir = os.path.join(PATH_TO_TMP, "logs")
                os.makedirs(logdir, exist_ok=True)
                with open(f"{logdir}/{design_name}.failed.log", "a") as f:
                    f.write(f"seed {seed}: {str(e)}\n")

        return False

def check_isa_sims(design_name: str, num_cores: int, total_tests: int, taint_en: bool, seed_offset: int):
    global newly_finished_tests
    global callback_lock

    process_instance_id = 0
    if seed_offset is not None:
        process_instance_id += seed_offset
    num_workers = num_cores
    assert num_workers > 0
    calibrate_spikespeed()
    profile_get_medeleg_mask(design_name)
    if num_workers == 1:
        print(f"Starting sequential ISA sim validation on `{design_name}` with {total_tests} total tests.")
        for _ in range(total_tests):
            check_isa_sim_taint(design_name,process_instance_id, taint_en=taint_en)
            process_instance_id += 1
        exit(0)
    if total_tests == -1:
        print(f"Starting parallel ISA sim validation of `{design_name}` on {num_workers} threads. No max number of tests given.")
    else:
        print(f"Starting parallel ISA sim validation on {total_tests} total tests of `{design_name}` on {num_workers} threads.")

    pool = mp.Pool(processes=num_workers)
    for _ in range(num_workers):
        if PRINT_THREAD_STATUS:
            print(f"Starting thread {process_instance_id}.")
        pool.apply_async(__check_isa_sim_worker, args=(design_name, process_instance_id,taint_en,),callback=test_done_callback)
        process_instance_id += 1

    
    while True:
        time.sleep(2)
        with callback_lock:
            if newly_finished_tests > 0:
                for _ in range(newly_finished_tests):
                    if PRINT_THREAD_STATUS:
                        print(f"Starting thread {process_instance_id}.")
                    pool.apply_async(__check_isa_sim_worker, args=(design_name, process_instance_id,taint_en),callback=test_done_callback)
                    process_instance_id += 1
                newly_finished_tests = 0
            if total_finished_tests >= total_tests and total_tests != -1:
                print(f"Finished {total_finished_tests} threads. Exiting.")
                pool.terminate()
                exit(0)







