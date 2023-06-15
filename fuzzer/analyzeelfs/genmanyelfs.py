# Copyright 2023 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This module is typically used to generate a lot of Cascade programs

from common.profiledesign import profile_get_medeleg_mask
from common.spike import calibrate_spikespeed
from cascade.fuzzfromdescriptor import LOG2_MEMSIZE_UPPERBOUND, NUM_MAX_BBS_UPPERBOUND, gen_fuzzerstate_elf_expectedvals, gen_new_test_instance

import os
import random
import shutil
import multiprocessing as mp

def __gen_elf_worker(instance_id: int, memsize: int, design_name: str, check_pc_spike_again: bool, randseed: int, nmax_bbs: int, outdir_path: str):
    fuzzerstate, elfpath, _, _, _, _ = gen_fuzzerstate_elf_expectedvals(memsize, design_name, check_pc_spike_again, randseed, nmax_bbs)
    # Move the file from elfpath to outdir_path, and name it after the design name and instance id.
    shutil.move(elfpath, os.path.join(outdir_path, f"{design_name}_{instance_id}.elf"))

    # Write the end address (where spike will fail), for further analysis.
    with open(os.path.join(outdir_path, f"{design_name}_{instance_id}_finaladdr.txt"), "w") as f:
        f.write(hex(fuzzerstate.final_bb_base_addr))

    print('Elf generation done for instance', instance_id, flush=True)

def gen_many_elfs(design_name: str, num_cores: int, num_elfs: int, outdir_path):
    random.seed(0)

    # Ensure that the output directory exists.
    os.makedirs(outdir_path, exist_ok=True)

    # Gen the program descriptors.
    memsizes, _, randseeds, num_bbss = tuple(zip(*[gen_new_test_instance(design_name, i) for i in range(num_elfs)]))
    workloads = [(i, memsizes[i], design_name, False, randseeds[i], num_bbss[i], outdir_path) for i in range(num_elfs)]

    calibrate_spikespeed()
    profile_get_medeleg_mask(design_name)

    print(f"Starting ELF generation on {num_cores} cores.")
    with mp.Pool(num_cores) as pool:
        pool.starmap(__gen_elf_worker, workloads)
