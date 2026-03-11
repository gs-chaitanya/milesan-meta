# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This module is typically used to generate a lot of Cascade programs

from common.profiledesign import profile_get_medeleg_mask
from common.spike import calibrate_spikespeed
from milesan.fuzzfromdescriptor import gen_fuzzerstate_elf_expectedvals, gen_new_test_instance

import multiprocessing as mp
import os
import random
import shutil
from tqdm import tqdm


# @param in_tuple: instance_id: int, memsize: int, design_name: str, randseed: int, nmax_bbs: int, authorize_privileges: bool, check_pc_spike_again: bool, outdir_path: str, force_taint_value: int|None
def __gen_elf_worker(in_tuple):
    instance_id, memsize, design_name, randseed, nmax_bbs, authorize_privileges, check_pc_spike_again, outdir_path, force_taint_value = in_tuple
    try:
        fuzzerstate, elfpath, interm_elfpath, _, _, _, _ = gen_fuzzerstate_elf_expectedvals(memsize, design_name, randseed, nmax_bbs, authorize_privileges, check_pc_spike_again)
    except Exception as e:
        print(f"Skipping seed {randseed} (taint={force_taint_value}): {e}")
        return

    force_taint_str = str(force_taint_value) if force_taint_value is not None else "none"
    basename = f"{force_taint_str}_{design_name}_{randseed}"

    # Move the RTL ELF from elfpath to outdir_path.
    shutil.move(elfpath, os.path.join(outdir_path, f"{basename}.elf"))

    # Write the end address (where spike will fail), for further analysis.
    with open(os.path.join(outdir_path, f"{basename}_finaladdr.txt"), "w") as f:
        f.write(hex(fuzzerstate.final_bb_base_addr))

    # Count the instructions
    num_instrs = len(fuzzerstate.final_bb)
    for bb in fuzzerstate.instr_objs_seq:
        num_instrs += len(bb)
    with open(os.path.join(outdir_path, f"{basename}_numinstrs.txt"), "w") as f:
        f.write(hex(num_instrs))

    # Save the tuple for debug purposes
    with open(os.path.join(outdir_path, f"{basename}_tuple.txt"), "w") as f:
        f.write('(' + ', '.join(map(str, [memsize, design_name, randseed, nmax_bbs, authorize_privileges])) + ')')

    # Clean up the tmp dir (removes spike ELF and any other intermediates).
    if fuzzerstate.tmp_dir and os.path.isdir(fuzzerstate.tmp_dir):
        shutil.rmtree(fuzzerstate.tmp_dir)


def gen_many_elfs(design_name: str, num_cores: int, num_elfs: int, outdir_path, force_taint_value=None, verbose: bool = True):
    random.seed(0)

    # Ensure that the output directory exists.
    os.makedirs(outdir_path, exist_ok=True)

    # Gen the program descriptors.
    memsizes, _, randseeds, num_bbss, authorize_privilegess = tuple(zip(*[gen_new_test_instance(design_name, i, True) for i in range(num_elfs)]))
    workloads = [(i, memsizes[i], design_name, randseeds[i], num_bbss[i], authorize_privilegess[i], False, outdir_path, force_taint_value) for i in range(num_elfs)]

    calibrate_spikespeed()
    # profile_get_medeleg_mask(design_name)
    from common.profiledesign import PROFILED_MEDELEG_MASK
    if PROFILED_MEDELEG_MASK is None:
        profile_get_medeleg_mask(design_name)

    print(f"Starting ELF generation on {num_cores} processes.")
    progress_bar = tqdm(total=num_elfs)
    with mp.Pool(num_cores) as pool:
        results = pool.imap(__gen_elf_worker, workloads)

        for result in results:
            if verbose:
                progress_bar.update(1)

    progress_bar.close()
