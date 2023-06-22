# Copyright 2023 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This module is responsible to measure the time required to find a bug, given some behavior tolerances and a specific design name

from common.timeout import timeout
from common.profiledesign import profile_get_medeleg_mask
from common.spike import calibrate_spikespeed
from cascade.fuzzfromdescriptor import gen_new_test_instance, run_rtl

import traceback
import threading
import time

callback_lock = threading.Lock()
newly_finished_tests = 0
curr_round_id = 0
all_times_to_detection = []

def bug_detection_callback(ret):
    global newly_finished_tests
    global callback_lock
    global curr_round_id
    global all_times_to_detection
    with callback_lock:
        newly_finished_tests += 1
        if ret is not None:
            if len(all_times_to_detection) <= curr_round_id:
                all_times_to_detection.append(ret)

@timeout(seconds=60*60*2)
def run_rtl_single_for_timebugdetection(memsize: int, design_name: str, randseed: int, nmax_bbs: int, start_time: float, authorize_privileges: bool):
    try:
        run_rtl(memsize, design_name, randseed, nmax_bbs, authorize_privileges, False)
        return None
    except Exception as e:
        traceback.print_exc()
        print(f"Failed run_rtl_single_for_timebugdetection for params memsize: `{memsize}`, design_name: `{design_name}`, check_pc_spike_again: `{False}`, randseed: `{randseed}`, nmax_bbs: `{nmax_bbs}` -- ({memsize}, design_name, {randseed}, {nmax_bbs})")
        print(e)
        if start_time is None:
            start_time = 0
        time_to_detection = time.time() - start_time
        print(f"  Time to detection (seconds): {time.time() - start_time}")
        if start_time:
            return time_to_detection

def measure_time_to_bug(design_name: str, num_cores: int, num_reps: int):
    global newly_finished_tests
    global callback_lock
    global all_times_to_detection
    global curr_round_id

    newly_finished_tests = 0
    all_times_to_detection = []
    curr_round_id = 0

    import multiprocessing as mp

    num_workers = num_cores
    assert num_workers > 0

    calibrate_spikespeed()
    profile_get_medeleg_mask(design_name)

    print(f"Starting timing of bug detection on `{design_name}` on {num_workers} processes.")

    assert num_reps > 0, "num_reps must be > 0, may it be for bug detection timing or just normal fuzzing"

    for global_iter_id in range(num_reps):
        print(f"Starting global iteration {global_iter_id}.")

        newly_finished_tests = 0
        exit_curr_global_rep = False

        start_time = time.time()

        pool = mp.Pool(processes=num_workers)
        process_instance_id = 0
        # First, apply the function to all the workers. We do not use map because some instances, rarely, seem to be stuck for unexplained reasons.
        for process_id in range(num_workers):
            memsize, _, _, num_bbs, authorize_privileges = gen_new_test_instance(design_name, process_instance_id, True)
            pool.apply_async(run_rtl_single_for_timebugdetection, args=(memsize, design_name, process_instance_id+50000*global_iter_id, num_bbs, start_time, authorize_privileges), callback=bug_detection_callback)
            process_instance_id += 1

        while not exit_curr_global_rep:
            time.sleep(2)
            # Check whether we received new coverage paths
            with callback_lock:
                if newly_finished_tests > 0:
                    assert len(all_times_to_detection) <= curr_round_id + 1
                    if len(all_times_to_detection) == curr_round_id + 1:
                        exit_curr_global_rep = True
                        curr_round_id += 1
                        print(f"Curr all times to detection: {all_times_to_detection}")
                        break

                    for new_process_id in range(newly_finished_tests):
                        memsize, _, _, num_bbs, authorize_privileges = gen_new_test_instance(design_name, process_instance_id, True)
                        pool.apply_async(run_rtl_single_for_timebugdetection, args=(memsize, design_name, process_instance_id+50000*global_iter_id, num_bbs, start_time, authorize_privileges), callback=bug_detection_callback)
                        process_instance_id += 1
                    newly_finished_tests = 0

        # This code is only reached if we are measuring the time to bug detection
        pool.close()
        pool.terminate()

    # This code is only reached if we are measuring the time to bug detection
    print(f"Times to bug detection (seconds): {all_times_to_detection}")
    return all_times_to_detection
