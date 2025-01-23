# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script measures the simulator coverage of Cascade and DifuzzRTL.

from params.runparams import PATH_TO_TMP
from analyzeelfs.genmanyelfs import gen_many_elfs
from difuzzrtl.difuzzmodelsim import collect_coverage_modelsim_difuzzrtl_nomerge, merge_coverage_modelsim_difuzzrtl
from difuzzrtl.gendifuzzelfs import gen_many_difuzzrtl_elfs
from common.profiledesign import profile_get_medeleg_mask
from common.spike import calibrate_spikespeed

import multiprocessing as mp
import os

if __name__ == '__main__':
    if "MILESAN_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

    num_workers = max(int(os.getenv('MILESAN_JOBS', 160)) // 4, 1)
    path_to_milesan_elfs = os.path.join(PATH_TO_TMP, 'manyelfs_modelsim')

    num_elfs_to_produce = 10000 # Heuristic, should ensure that we have enough to cover all instructions / durations

    target_numinstrs = 1_100_000

    calibrate_spikespeed()
    profile_get_medeleg_mask('rocket')

    # Cascade

    # Generate enough ELFs
    # gen_many_elfs('rocket', 250, num_elfs_to_produce, path_to_milesan_elfs) # TODO Uncomment
    collect_coverage_modelsim_difuzzrtl_nomerge(False, 0, 'rocket', num_workers, target_numinstrs, None)

    # DifuzzRTL

    # Generate the DifuzzRTL ELFs
    # gen_many_difuzzrtl_elfs() # TODO Uncomment
    collect_coverage_modelsim_difuzzrtl_nomerge(True, 0, 'rocket', num_workers, target_numinstrs, None)

    # Run merging the coverage
    workloads = [(False, 0, target_numinstrs), (True, 0, target_numinstrs)]
    with mp.Pool(2) as pool:
        pool.starmap(merge_coverage_modelsim_difuzzrtl, workloads)

    # benchmark_collect_construction_performance(int(sys.argv[1]))
    # plot_construction_performance()

else:
    raise Exception("This module must be at the toplevel.")
