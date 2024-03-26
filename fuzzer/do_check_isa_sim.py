# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script executes the fuzzer on a given design to find faulting programs.

# sys.argv[1]: design name
# sys.argv[2]: num of cores allocated to fuzzing
# sys.argv[3]: offset for seed (to avoid running the fuzzing on the same instances over again)
# sys.argv[4]: number of total tests that should be completed successfully
# sys.argv[5]: authorize privileges (by default 1)

from drfuzz_mem.check_isa_sim_worker import check_isa_sims
from common.spike import calibrate_spikespeed
from common.profiledesign import profile_get_medeleg_mask


import os
import sys

if __name__ == '__main__':
    if "CASCADE_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

    if len(sys.argv) < 4:
        raise Exception("Usage: python3 do_check_isa_sims.py <design_name> <num_cores> <n_total_tests> [seed_offset]")


    design_name = sys.argv[1]
    n_cores = int(sys.argv[2])
    n_total_tests = int(sys.argv[3])

    seed_offset = 0
    if len(sys.argv) > 4:
        seed_offset = int(sys.argv[4])
    calibrate_spikespeed()
    profile_get_medeleg_mask(design_name)
    check_isa_sims(design_name,n_cores,n_total_tests,seed_offset)
    
else:
    raise Exception("This module must be at the toplevel.")
