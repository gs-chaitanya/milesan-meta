from drfuzz_mem.inject_taints import gen_elf_and_inject_taints
import multiprocessing as mp
import time
import threading
from common.spike import calibrate_spikespeed
from common.profiledesign import profile_get_medeleg_mask

callback_lock = threading.Lock()
newly_finished_tests = 0
curr_round_id = 0
all_times_to_detection = []
N_WORKERS=1
DUT="rocket"
MAX_N_INJECT_PER_BB = 1

def test_done_callback(arg):
    global newly_finished_tests
    global callback_lock
    global curr_round_id
    global all_times_to_detection
    with callback_lock:
        newly_finished_tests += 1
        print(f"Finished {newly_finished_tests}/{N_WORKERS} threads.")


if __name__ == "__main__":
    process_instance_id = 0
    pool = mp.Pool(processes=N_WORKERS)


    calibrate_spikespeed()
    profile_get_medeleg_mask(DUT)

    if(N_WORKERS==1):
        gen_elf_and_inject_taints(DUT,MAX_N_INJECT_PER_BB,0)
        exit(0)

    for _ in range(N_WORKERS):
        print(f"Starting thread {process_instance_id}")
        pool.apply_async(gen_elf_and_inject_taints, args=(DUT, MAX_N_INJECT_PER_BB, process_instance_id),callback=test_done_callback)
        process_instance_id += 1

    while True:
        time.sleep(2)
        with callback_lock:
            if(newly_finished_tests == N_WORKERS): break







