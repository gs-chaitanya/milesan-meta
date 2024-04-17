from drfuzz_mem.check_isa_sim import check_isa_sim
from drfuzz_mem.check_isa_sim_taint import check_isa_sim_taint
import multiprocessing as mp
import time
import threading
from common.spike import calibrate_spikespeed
from common.profiledesign import profile_get_medeleg_mask
from cascade.randomize.pickbytecodetaints import MAX_N_INJECT_PER_BB
from cascade.util import CFInstructionClass

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
        if(ret):
            total_finished_tests += 1
            if PRINT_THREAD_STATUS:
                print(f"Finished {total_finished_tests} threads.")
        # else:
        #     print(f"Thread failed.")



def __check_isa_sim_worker(design_name, seed, taint_en):
    try:
        if taint_en:
            return check_isa_sim_taint(design_name,seed)
        else:
            return check_isa_sim(design_name, seed)
    except Exception as e:
        print(f"check_isa_sim_worker failed for {design_name} with seed {seed}: {e}")
        return 0

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
            # try:
            if taint_en:
                check_isa_sim_taint(design_name,process_instance_id)
            else:
                check_isa_sim(design_name,process_instance_id)
            # except Exception as e:
            #     print(e)
            process_instance_id += 1
        exit(0)
    if total_tests != -1:
        print(f"Starting parallel ISA sim validation on {total_tests} total tests of `{design_name}` on {num_workers} processes.")
    print(f"Starting parallel ISA sim validation of `{design_name}` on {num_workers} processes. No max number of tests given.")

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
                if PRINT_THREAD_STATUS:
                    print(f"Finished {total_finished_tests} threads. Exiting.")
                pool.terminate()
                exit(0)







