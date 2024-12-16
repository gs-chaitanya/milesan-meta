from drfuzz_mem.inject_instructions import gen_elf_and_inject_instructions
import multiprocessing as mp
import time
import threading
from common.spike import calibrate_spikespeed
from common.profiledesign import profile_get_medeleg_mask
from milesan.randomize.pickbytecodetaints import MAX_N_INJECT_PER_BB
from milesan.util import CFInstructionClass
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
            print(f"Finished {total_finished_tests} threads.")
        else:
            print(f"Thread failed.")



def __gen_elf_and_inject_instructions_worker(design_name, max_n_insts_per_bb, en_taint, seed, fuzz_only_this_inst_type = None):
    try:
        return gen_elf_and_inject_instructions(design_name, max_n_insts_per_bb, en_taint, seed, fuzz_only_this_inst_type)
    except Exception as e:
        print(f"gen_elf_and_inject_taints_woker failed for: {design_name},{max_n_insts_per_bb},{seed}: {e}")
        return 0

def inject_instructions(design_name: str, num_cores: int, total_tests: int, en_taint: str, seed_offset: int, can_authorize_priviles: bool):
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
        for _ in range(total_tests):
            print(f"Starting instruction injection on `{design_name}`.")
            # try:
            gen_elf_and_inject_instructions(design_name,MAX_N_INJECT_PER_BB,en_taint, process_instance_id)
            # except Exception as e:
            #     print(e)
            process_instance_id += 1
        exit(0)

    print(f"Starting parallel instruction injection on {total_tests} total tests of `{design_name}` on {num_workers} processes.")
    pool = mp.Pool(processes=num_workers)
    for _ in range(num_workers):
        print(f"Starting thread {process_instance_id}")
        pool.apply_async(__gen_elf_and_inject_instructions_worker, args=(design_name, MAX_N_INJECT_PER_BB, en_taint, process_instance_id),callback=test_done_callback)
        process_instance_id += 1

    
    while True:
        time.sleep(2)
        with callback_lock:
            if newly_finished_tests > 0:
                for _ in range(newly_finished_tests):
                    print(f"Starting thread {process_instance_id}")
                    pool.apply_async(__gen_elf_and_inject_instructions_worker, args=(design_name, MAX_N_INJECT_PER_BB, en_taint, process_instance_id),callback=test_done_callback)
                    process_instance_id += 1
                newly_finished_tests = 0
            if total_finished_tests >= total_tests:
                print(f"Finished {total_finished_tests} threads. Exiting.")
                pool.terminate()
                exit(0)







