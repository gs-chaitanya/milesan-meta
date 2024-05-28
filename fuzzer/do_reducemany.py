# Copyright 2023 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script executes a single program.

# sys.argv[1]: design name
# sys.argv[2]: num of cores allocated to fuzzing
# sys.argv[3]: offset for seed (to avoid running the fuzzing on the same instances over again)

from workers.reduce_worker import reduce_programs
from cascade.toleratebugs import tolerate_bug_for_eval_reduction
from common.profiledesign import profile_get_medeleg_mask
from common.spike import calibrate_spikespeed
import sys
import os
import re

def _parse_logfile(path, design_name):
    with open(path, "r") as f:
        logs = f.read()
    seeds = []
    for line in logs.split("\n"):
        fuzz_id = re.findall(f"[0-9]+_{design_name}_[0-9]+_[0-9]+",line)
        if len(fuzz_id):
            assert len(fuzz_id) == 1
            seeds += [int(fuzz_id[0].split("_")[2])]
    return seeds

if __name__ == '__main__':
    if "CASCADE_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

    if len(sys.argv) < 4:
        raise Exception("Usage: python3 do_reducemany.py <design_name> <num_cores> [--seeds=seed0,seed1,seed2,...,seedN] [--log-file=path_to_log-file] ")

    design_name = sys.argv[1]
    num_cores = int(sys.argv[2])
    if "seeds" in sys.argv[3]:
        seeds = [int(i) for i in sys.argv[3].split("=")[-1].split(',')]
    elif "log-file" in sys.argv[3]:
        logfile = sys.argv[3].split("=")[-1]
        seeds = _parse_logfile(logfile,design_name)
        print(f"Found {len(seeds)} seeds in logfile: {seeds}")

    # 346864, 'rocket', 232, 75
    # 230898, 'rocket', 673, 991
    # 754911, 'rocket', 1220, 812
    # 265291, 'rocket', 2231, 740
    # 493247, 'rocket', 1745, 936
    # 526858, 'rocket', 2170, 531
    # 269239, 'rocket', 1921, 707
    # descriptor = (747222, design_name, 576, 97, True)

    # tolerate_bug_for_eval_reduction(design_name)

    calibrate_spikespeed()
    profile_get_medeleg_mask(design_name)
    reduce_programs(design_name,num_cores,seeds)


else:
    raise Exception("This module must be at the toplevel.")

        
