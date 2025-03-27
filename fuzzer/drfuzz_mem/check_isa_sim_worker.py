from drfuzz_mem.check_isa_sim_taint import check_isa_sim_taint, FailTypeEnum, FuzzerStateException
from common.spike import calibrate_spikespeed
from common.profiledesign import profile_get_medeleg_mask
from workers.reduce_worker import reduce_programs
from milesan.util import CFInstructionClass
from params.runparams import PATH_TO_TMP, NO_REMOVE_TMPFILES, NO_REMOVE_TMPDIRS
import multiprocessing as mp
import time
import threading
import os
LOG_EXCEPTIONS = True
PRINT_THREAD_STATUS = False
ONLY_PRINT_LEAKAGE = True
callback_lock = threading.Lock()
newly_finished_tests = 0
total_finished_tests = 0
active_seeds = {}
seed_to_fail_type_dict = {
    FailTypeEnum.TAINT_MISMATCH: [],
    FailTypeEnum.VALUE_MISMATCH: [],
    FailTypeEnum.RTL_TIMEOUT: [],
    FailTypeEnum.SPIKE_TIMEOUT: []
}

def log_active_threads():
    global active_seeds
    now = time.time()
    seed_to_time = {seed:(lambda x:f"{int(x//60)}m{int(x%60)}s")(now-t) for seed, t in active_seeds.items()}
    if seed_to_time:
        max_key_len = max(len(str(seed)) for seed in seed_to_time.keys())
        max_val_len = max(len(str(time)) for time in seed_to_time.values())
        col_width = max(max_key_len, max_val_len) + 2
        header = "".join(f"{seed:<{col_width}}" for seed in seed_to_time.keys())
        values = "".join(f"{time:<{col_width}}" for time in seed_to_time.values())
        with open(os.path.join(PATH_TO_TMP,"active_threads.log"), "w") as f:
            f.write(header + "\n")
            f.write(values + "\n")

def test_done_callback(ret):
    global newly_finished_tests
    global callback_lock
    global total_finished_tests
    global seed_to_fail_type_dict
    global active_seeds
    with callback_lock:
        newly_finished_tests += 1
        total_finished_tests += 1
        if ret[0]:
            seed_to_fail_type_dict[ret[0]] += [ret[1]]
        total_time = time.time()-active_seeds[ret[1]]
        del active_seeds[ret[1]]
        if PRINT_THREAD_STATUS:
            print(f"Finished seed {ret[1]} after {int(total_time//60)}m{int(total_time%60)}s. {total_finished_tests} threads finished.")




def __check_isa_sim_worker(design_name, seed):
    try:
        fuzzerstate = check_isa_sim_taint(design_name,seed)
        if not NO_REMOVE_TMPDIRS:
            fuzzerstate.remove_tmp_dir()
        elif not NO_REMOVE_TMPFILES:
            fuzzerstate.remove_tmp_files()
        if PRINT_THREAD_STATUS:
            print(f"No mismatch detected for {design_name} with seed {seed}")
        return (None, seed)
    except Exception as e:
        if not ONLY_PRINT_LEAKAGE or "Taint mismatch" in str(e):
            print(f"check_isa_sim_worker failed for {design_name} with seed {seed}: {str(e)}")

        if isinstance(e, FuzzerStateException):
            if not NO_REMOVE_TMPDIRS:
                e.fuzzerstate.remove_tmp_dir()
            elif not NO_REMOVE_TMPFILES:
                e.fuzzerstate.remove_tmp_files()
                
        if LOG_EXCEPTIONS:
            if isinstance(e, FuzzerStateException):
                logdir = os.path.join(PATH_TO_TMP, "logs")
                os.makedirs(logdir, exist_ok=True)
                with open(f"{logdir}/{design_name}.{e.fail_type.name.lower()}.log", "a") as f:
                    f.write(f"seed {seed}: {str(e)}\n")
                    f.write(f"\ttimestamp: {e.timestamp}\n")
                return (e.fail_type, seed)

            else:
                logdir = os.path.join(PATH_TO_TMP, "logs")
                os.makedirs(logdir, exist_ok=True)
                with open(f"{logdir}/{design_name}.failed.log", "a") as f:
                    f.write(f"seed {seed}: {str(e)}\n")
        return (None,seed)







def check_isa_sims(design_name: str, num_cores: int, total_tests: int, seed_offset: int, timeout: int = None, seeds = None):
    global newly_finished_tests
    global callback_lock
    global active_seeds
    process_instance_id = 0
    if seed_offset is not None:
        process_instance_id += seed_offset
    if seeds is not None:
        assert seed_offset is None or seed_offset == 0
        total_tests = len(seeds)

    num_workers = num_cores
    assert num_workers > 0
    start_time = time.time()
    if num_workers == 1:
        print(f"Starting sequential ISA sim validation on `{design_name}` with {total_tests} total tests." + ("" if timeout is None else f" Timeout is {timeout}s."))
        if total_tests > 0:
            for _ in range(total_tests):
                check_isa_sim_taint(design_name,process_instance_id if seeds is None else seeds[process_instance_id])
                process_instance_id += 1
        else:
            while True:
                try:
                    check_isa_sim_taint(design_name,process_instance_id if seeds is None else seeds[process_instance_id])
                except Exception as e:
                    print(e)
                process_instance_id += 1
        return seed_to_fail_type_dict

    if total_tests == -1:
        print(f"Starting parallel ISA sim validation of `{design_name}` on {num_workers} threads. No max number of tests given." + ("" if timeout is None else f" Timeout is {timeout}s."))
    else:
        print(f"Starting parallel ISA sim validation on {total_tests} total tests of `{design_name}` on {num_workers} threads." + ("" if timeout is None else f" Timeout is {timeout}s."))
    
    pool = mp.Pool(processes=num_workers)
    for _ in range(min(num_workers, total_tests) if total_tests != -1 else num_workers):
        if PRINT_THREAD_STATUS:
            print(f"Starting thread {process_instance_id}" + (f" for seed {seeds[process_instance_id]}." if seeds is not None else "."))
        pool.apply_async(__check_isa_sim_worker, args=(design_name, process_instance_id if seeds is None else seeds[process_instance_id],),callback=test_done_callback)
        active_seeds[process_instance_id] = time.time()
        process_instance_id += 1

    while True:
        if timeout is not None and time.time()-start_time >= timeout:
            print(f"Timed out after {timeout}s. Exiting.")
            pool.terminate()
            return seed_to_fail_type_dict

        time.sleep(2)
        log_active_threads()
        with callback_lock:
            if newly_finished_tests > 0 and seeds is None or seeds is not None and process_instance_id < len(seeds):
                for _ in range(newly_finished_tests):
                    if PRINT_THREAD_STATUS:
                        print(f"Starting thread {process_instance_id}.")
                    pool.apply_async(__check_isa_sim_worker, args=(design_name, process_instance_id if seeds is None else seeds[process_instance_id]),callback=test_done_callback)
                    active_seeds[process_instance_id] = time.time()
                    process_instance_id += 1
                    if seeds is not None and process_instance_id >= len(seeds):
                        print(f"Finished {total_finished_tests} threads covering all provided seeds. Exiting.")
                        pool.terminate()
                        return seed_to_fail_type_dict
                newly_finished_tests = 0
            if total_finished_tests >= total_tests and total_tests != -1:
                print(f"Finished {total_finished_tests} threads. Exiting.")
                pool.terminate()
                return seed_to_fail_type_dict








