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
import numpy as np

if __name__ == '__main__':
    if "MILESAN_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

    if len(sys.argv) < 4:
        raise Exception("Usage: python3 do_fuzz_good_seeds.py <design_name> <num_cores> <seeds_dir> [<enable_taint> <authorize_privileges>]")


    design_name = sys.argv[1]
    num_cores = int(sys.argv[2])
    seeds_dir = sys.argv[3]
    en_taint = False
    authorize_privileges = True
    if len(sys.argv) > 4:
        en_taint = int(sys.argv[4]) == 1
    if len(sys.argv) > 5:
        authorize_privileges  = int(sys.argv[5]) == 1
        

    seeds = []
    for p in glob.glob(f'{seeds_dir}/**/*.json',recursive=True):
        with open(p, "rb") as f:
            seeds += [json.load(f)[0]["seed"]]
            if len(seeds) == 10: 
                break

    recompile_design(design_name,en_taint,single_fuzz=False)
    print(f"Loaded {len(seeds)} seeds, starting fuzzing.")

    fuzz_good_seeds(design_name, num_cores, seeds,en_taint, authorize_privileges)
    print(f"Finished fuzzing on {len(seeds)} seeds.")
