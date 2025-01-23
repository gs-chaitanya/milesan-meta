# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script executes a single program.

# sys.argv[1]: design name
# sys.argv[2]: num of cores allocated to fuzzing
# sys.argv[3]: offset for seed (to avoid running the fuzzing on the same instances over again)

from workers.reduce_worker import reduce_programs
from common.profiledesign import profile_get_medeleg_mask, profile_get_asid_mask
from common.spike import calibrate_spikespeed
import sys
import os
import re
MUTE_OUTPUT=False
def _parse_logfile(path, design_name):
    if path.endswith("reduce.log"):
        is_reduction_log = True
        print("Detected reduction log. Parsing seeds for cross-privilege leakage.")
    else:
        is_reduction_log = False
    with open(path, "r") as f:
        logs = f.read()
    seeds = []
    cross_privilege = []
    for line in logs.split("\n"):
        fuzz_id = re.findall(f"[0-9]+_{design_name}_[0-9]+_[0-9]+",line)
        if len(fuzz_id):
            assert len(fuzz_id) == 1 or is_reduction_log
            seeds += [int(fuzz_id[0].split("_")[2])]
            cross_privilege += [False]
        if "Detected leakage" in line:
            cross_privilege[-1] = True
    if is_reduction_log:
        return [seed for i,seed in enumerate(seeds) if cross_privilege[i]]
    return seeds

if __name__ == '__main__':
    if "MILESAN_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

    if len(sys.argv) < 4:
        raise Exception("Usage: python3 do_reducemany.py <design_name> <num_cores> [--seeds=seed0,seed1,seed2,...,seedN] [--log-file=path_to_log-file] [--max-seed=seedN]")

    design_name = sys.argv[1]
    num_cores = int(sys.argv[2])
    if "seeds" in sys.argv[3]:
        seeds = [int(i) for i in sys.argv[3].split("=")[-1].split(',')]
    elif "log-file" in sys.argv[3]:
        logfile = sys.argv[3].split("=")[-1]
        seeds = _parse_logfile(logfile,design_name)
        print(f"Found {len(seeds)} seeds in logfile: {seeds}")
    elif "max-seed" in sys.argv[3]:
        seeds = range(0, int(sys.argv[3].split("=")[-1]))
    else:
        print("One of '--seeds', '--log-file' or '--max-seed' need to be provided.")

    if num_cores > len(seeds):
        num_cores = len(seeds)

    calibrate_spikespeed()
    profile_get_medeleg_mask(design_name)
    profile_get_asid_mask(design_name)

    reduce_programs(design_name,num_cores,seeds,mute_output=MUTE_OUTPUT)


else:
    raise Exception("This module must be at the toplevel.")

        
