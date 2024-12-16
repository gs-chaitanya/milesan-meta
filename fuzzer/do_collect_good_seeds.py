# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script executes the fuzzer on a given design to find faulting programs.

# sys.argv[1]: design name
# sys.argv[2]: num of cores allocated to fuzzing
# sys.argv[3]: offset for seed (to avoid running the fuzzing on the same instances over again)
# sys.argv[4]: number of total tests that should be completed successfully
# sys.argv[5]: authorize privileges (by default 1)

from drfuzz_mem.collect_good_seeds_worker import collect_good_seeds
from drfuzz_mem.fuzz_good_seeds_worker import fuzz_good_seeds
from drfuzz_mem.recompile_design import recompile_design
import glob, json
import os
import sys

if __name__ == '__main__':
    if "MILESAN_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

    if len(sys.argv) < 4:
        raise Exception("Usage: python3 do_fuzz_good_seeds.py <design_name> <num_cores> <n_total_tests> [<max_n_seeds> <enable_taint> <seed_offset>] [<authorize_privileges>]")


    design_name = sys.argv[1]
    num_cores = int(sys.argv[2])
    n_total_tests = int(sys.argv[3])

    if len(sys.argv) > 4:
        max_n_seeds = int(sys.argv[4])
    else:
        max_n_seeds = n_total_tests
    if len(sys.argv) > 5:
        en_taint = sys.argv[5]=="1"
    else:
        en_taint = True
    if len(sys.argv) > 6:
        seed_offset = int(sys.argv[6])
    else:
        seed_offset = 0
    if len(sys.argv) > 7:
        authorize_privileges = int(sys.argv[7])
    else:
        authorize_privileges = 1
        
    recompile_design(design_name,en_taint,single_fuzz=True)
    good_seeds = collect_good_seeds(design_name, num_cores, n_total_tests, en_taint, seed_offset, authorize_privileges, max_n_seeds)
    print(f"***GOOD SEEDS***:\n {good_seeds}\n***********")
    print(f"Collected {len(good_seeds)} good seeds.")
