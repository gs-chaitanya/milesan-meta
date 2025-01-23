# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

from params.runparams import PATH_TO_TMP, DO_ASSERT
from common.timeout import timeout
from common.spike import calibrate_spikespeed
from common.sim.coverageutil import merge_and_extract_coverages_modelsim
from difuzzrtl.countinstrs import countinstrs_difuzzrtl, countinstrs_milesan
from milesan.fuzzsim import runsim_modelsim, MAX_CYCLES_PER_INSTR, SETUP_CYCLES
from common.profiledesign import profile_get_medeleg_mask

import json
import multiprocessing as mp
import os
import shutil
import threading
import time
import traceback
from tqdm import tqdm

# This helps tracking how many new processes to spawn
modelsim_coverage_lock = threading.Lock()
newly_collected_coveragepaths_size = 0
collected_coveragepaths = []
collected_numinstrs = []
collected_durations = []
newly_treated = 0

def run_rtl_fordifuzzrtl_modelsim(is_difuzzrtl, instance_id, rtl_elfpath, num_cycles):
    if is_difuzzrtl:
        coveragepath = os.path.join(PATH_TO_TMP, f"coverage_modelsim_difuzzrtl{instance_id}.ucdb")
    else:
        coveragepath = os.path.join(PATH_TO_TMP, f"coverage_modelsim_milesan{instance_id}.ucdb")
    is_stop_successful, _ = runsim_modelsim('rocket', num_cycles, rtl_elfpath, 0, 0, coveragepath)
    return is_stop_successful, coveragepath

# @return a pair (path to coverage file, duration in seconds)
@timeout(seconds=60*60)
def __measure_coverage_modelsim_difuzzrtl(is_difuzzrtl: int, elf_id: int):
    design_name = 'rocket'
    try:
        if is_difuzzrtl:
            does_elf_exist = replace_write_to_host(elf_id)
            if not does_elf_exist:
                return None, -1, 0
            elfpath = os.path.join(PATH_TO_TMP, 'difuzzrtl_elfs_patched', f"id_{elf_id}.elf")
            num_instrs = countinstrs_difuzzrtl(elf_id)
        else:
            elfpath = os.path.join(PATH_TO_TMP, 'manyelfs_modelsim', f"{design_name}_{elf_id}.elf")
            num_instrs = countinstrs_milesan(elf_id)
        start_time = time.time()
        is_stop_successful, coveragepath = run_rtl_fordifuzzrtl_modelsim(is_difuzzrtl, elf_id, elfpath, num_instrs*MAX_CYCLES_PER_INSTR + SETUP_CYCLES)
        # Check successful stop
        if not is_stop_successful:
            raise Exception(f"Timeout during modelsim testing.")

        # print(f"  __measure_coverage_modelsim finished for tuple: ({memsize}, design_name, {randseed}, {nmax_bbs})", flush=True)
        return coveragepath, num_instrs, time.time() - start_time
    except Exception as e:
        traceback.print_exc()
        print(f"Exception in __measure_coverage_modelsim_difuzzrtl: {e}", flush=True)
        print(f"Ignored failed instance {elf_id}", flush=True)
        return None, -1, 0


def callback_collectmodelsim(collected_coveragepath_numinstrs_tuple: str):
    global collected_coveragepaths
    global collected_numinstrs
    global collected_durations
    global newly_collected_coveragepaths_size
    global modelsim_coverage_lock
    global newly_treated

    with modelsim_coverage_lock:
        newly_treated += 1
        if collected_coveragepath_numinstrs_tuple is None:
            return
        collected_coveragepath, collected_numinstr, collected_duration = collected_coveragepath_numinstrs_tuple
        if collected_coveragepath is not None:
            collected_coveragepaths.append(collected_coveragepath)
            collected_numinstrs.append(collected_numinstr)
            collected_durations.append(collected_duration)
            newly_collected_coveragepaths_size += 1

def series_to_process_id(is_difuzzrtl: bool, series_id: int, instance_id: int):
    if is_difuzzrtl:
        return series_id * 2000 + instance_id
    else:
        return series_id * 400 + instance_id

# Each worker must reach the total desired duration divided by the number of workers.
def collect_coverage_modelsim_difuzzrtl_nomerge(is_difuzzrtl: bool, series_id: int, design_name: str, num_cores: int, target_num_instrs: int = None, target_duration_seconds: int = None, calibrate_spike_speed_and_medeleg: bool = True):
    assert design_name == 'rocket', "Only rocket is supported for now."
    assert target_num_instrs is None or target_duration_seconds is None, "Only one of target_num_instrs and target_duration_seconds can be specified."
    assert target_num_instrs is not None or target_duration_seconds is not None, "One of target_num_instrs and target_duration_seconds must be specified."

    global collected_coveragepaths
    global newly_collected_coveragepaths_size
    global collected_numinstrs
    global collected_durations
    global newly_treated

    # Very important because we should not keep them between two runs
    collected_coveragepaths = []
    collected_numinstrs.clear()
    collected_durations.clear()
    newly_collected_coveragepaths_size = 0

    num_workers = num_cores
    del num_cores
    assert num_workers > 0

    if calibrate_spike_speed_and_medeleg:
        calibrate_spikespeed()
        profile_get_medeleg_mask(design_name)

    print(f"Starting coverage testing with modelsim of `{design_name}` on {num_workers} processes.")

    pool = mp.Pool(processes=num_workers)
    process_instance_id = 0
    # First, apply the function to all the workers. We do not use map because some instances, rarely, seem to be stuck for unexplained reasons.
    for process_id in range(num_workers):
        pool.apply_async(__measure_coverage_modelsim_difuzzrtl, args=(is_difuzzrtl, series_to_process_id(is_difuzzrtl, series_id, process_instance_id),), callback=callback_collectmodelsim)
        process_instance_id += 1

    curr_num_collected_instrs = 0
    curr_collected_durations = 0

    # Respawn processes until we received the desired number of coverage paths
    with tqdm(total=target_num_instrs) as pbar:
        while target_num_instrs is not None and curr_num_collected_instrs < target_num_instrs \
            or target_duration_seconds is not None and sum(collected_durations) < target_duration_seconds:
            # Yield the executiont
            time.sleep(1)
            # Check whether we received new coverage paths
            with modelsim_coverage_lock:
                if newly_treated > 0:
                    if target_num_instrs is not None and sum(collected_numinstrs) - curr_num_collected_instrs > 0:
                        pbar.update(sum(collected_numinstrs) - curr_num_collected_instrs)
                        curr_num_collected_instrs = sum(collected_numinstrs)
                    elif target_duration_seconds is not None and sum(collected_durations) - curr_collected_durations > 0:
                        pbar.update(sum(collected_durations) - curr_collected_durations)
                        curr_collected_durations = sum(collected_durations)
                    if target_num_instrs is not None and curr_num_collected_instrs >= target_num_instrs \
                        or target_duration_seconds is not None and curr_collected_durations >= target_duration_seconds:
                        print(f"Received enough coverage paths. Stopping.")
                        break
                    for new_process_id in range(newly_treated):
                        pool.apply_async(__measure_coverage_modelsim_difuzzrtl, args=(is_difuzzrtl, series_to_process_id(is_difuzzrtl, series_id, process_instance_id),), callback=callback_collectmodelsim)
                        process_instance_id += 1
                    newly_treated = 0

    # Kill all remaining processes
    pool.close()
    pool.terminate()

    print(f"Parallel section complete, proceeding to merging.")

    all_coverage_paths = collected_coveragepaths
    all_numinstrs = collected_numinstrs
    all_durations = collected_durations

    out_path = os.path.join(PATH_TO_TMP, f'coveragepaths_{design_name}_series{series_id}_isdifuzz{int(is_difuzzrtl)}.json')
    with open(out_path, 'w') as f:
        json.dump({'all_coverage_paths': all_coverage_paths, 'all_numinstrs': all_numinstrs, 'all_durations': all_durations}, f)
    print(f"Saved coverage paths to {out_path}")


def import_difuzzrtl_elfs(num_elfs: int):
    path_to_origin_elfdir = '/data/flsolt/savedifuzz/out_rocket_state/illegal/elf'
    path_to_destination_elfdir = os.path.join(PATH_TO_TMP, 'difuzzrtl_elfs_prepatch')
    # mkdir -p path_to_destination_elfdir
    os.makedirs(path_to_destination_elfdir, exist_ok=True)
    # There can be some rare occurrences of missing elfs, so we do the while loop
    curr_elf_id = -1
    num_elfs_copied = 0
    while num_elfs_copied < num_elfs:
        curr_elf_id += 1
        try:
            # Copy the elf
            shutil.copyfile(os.path.join(path_to_origin_elfdir, f"id_{curr_elf_id}.elf"), os.path.join(path_to_destination_elfdir, f"id_{num_elfs_copied}.elf"))
            num_elfs_copied += 1
        except:
            print(f"Failed to copy elf: id_{curr_elf_id}.elf. Moving to the next.")

# Only for difuzzrtl. Patches the ELFs to write to the suitable address to stop the testbench
# @return True iff the ELF existed
def replace_write_to_host(elf_id: int):
    mountpath = os.getenv('MILESAN_DOCKER_MNT_DIR')
    path_to_origin_elf = os.path.join(mountpath, 'Fuzzer', 'outdir1000', 'illegal', 'elf', f"id_{elf_id}.elf")
    path_to_patched_elf = os.path.join(PATH_TO_TMP, 'difuzzrtl_elfs_patched', f"id_{elf_id}.elf")

    if not os.path.exists(path_to_origin_elf):
        return False

    # Read the object file as binary
    with open(path_to_origin_elf, 'rb') as file:
        content = file.read()

    pattern = b'\x93\x01\x10\x00\x17\x1f\x00\x00\x23\x26\x3f\xc6'
    pattern_head = b'\x93\x01\x10\x00\x17\x1f\x00\x00\x23'
    assert pattern_head in content, f"Pattern {pattern_head} not found in the ELF {path_to_origin_elf}"
    assert content.count(pattern_head) == 1, f"Pattern {pattern_head} found more than once in the ELF."
    replacement = b'\x37\x05\x00\x60\x23\x20\x05\x00\x6f\x00\x00\x00'
    assert len(pattern) == len(replacement), f"Pattern and replacement have different lengths: {len(pattern)} vs {len(replacement)}"

    # Perform the replacements
    index_of_pattern = content.index(pattern_head)
    content = content[:index_of_pattern] + replacement + content[index_of_pattern + len(pattern):]

    # Write the modified content back to the file
    with open(path_to_patched_elf, 'wb') as file:
        file.write(content)
    
    return True

def merge_coverage_modelsim_difuzzrtl(is_difuzzrtl: bool, series_id: int, target_num_instrs: int):
    design_name = 'rocket'

    try:
        json_path = os.path.join(PATH_TO_TMP, f'coveragepaths_{design_name}_series{series_id}_isdifuzz{int(is_difuzzrtl)}.json')

        with open(json_path, 'r') as f:
            json_data = json.load(f)
            all_coverage_paths = json_data['all_coverage_paths']
            all_num_instrs = json_data['all_numinstrs']

        last_merged_coverage_filepath = None
        coverages_sequence = []
        for coverage_path_id, coverage_path in enumerate(tqdm(all_coverage_paths)):
            if is_difuzzrtl:
                merged_coverage_filepath = os.path.join(PATH_TO_TMP, f"merged_difuzzrtl_modelsim{design_name}_{coverage_path_id}.dat")
            else:
                merged_coverage_filepath = os.path.join(PATH_TO_TMP, f"merged_milesan_modelsim{design_name}_{coverage_path_id}.dat")

            if last_merged_coverage_filepath is not None:
                local_coverage_paths = [last_merged_coverage_filepath, coverage_path]
                new_coverages = merge_and_extract_coverages_modelsim(design_name, local_coverage_paths, merged_coverage_filepath, absolute=True)
            else:
                local_coverage_paths = [coverage_path]
                new_coverages = merge_and_extract_coverages_modelsim(design_name, local_coverage_paths, merged_coverage_filepath, absolute=True)
            last_merged_coverage_filepath = merged_coverage_filepath
            coverages_sequence.append(new_coverages)

        # Export a json with coverages_sequence and all_num_instrs
        if is_difuzzrtl:
            json_filepath = os.path.join(PATH_TO_TMP, f"modelsim_coverages_{target_num_instrs}_series{series_id}_isdifuzz{int(is_difuzzrtl)}.json")
        else:
            json_filepath = os.path.join(PATH_TO_TMP, f"modelsim_coverages_{target_num_instrs}_series{series_id}_isdifuzz{int(is_difuzzrtl)}.json")

        with open(json_filepath, 'w') as f:
            json.dump({'coverages_sequence': coverages_sequence, 'all_num_instrs': all_num_instrs}, f)

        print('Results saved in', json_filepath)
    except Exception as e:
        print('Error merging coverage files:', e)
        traceback.print_exc()
