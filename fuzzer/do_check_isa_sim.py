# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script executes the fuzzer on a given design to find faulting programs.

# sys.argv[1]: design name
# sys.argv[2]: num of cores allocated to fuzzing
# sys.argv[3]: number of total tests that should be completed successfully
# sys.argv[4]: offset for seed (to avoid running the fuzzing on the same instances over again)
# sys.argv[5]: timeout
# sys.argv[6]: logfile for seeds

from drfuzz_mem.check_isa_sim_worker import check_isa_sims
from common.spike import calibrate_spikespeed
from common.profiledesign import profile_get_medeleg_mask, profile_get_asid_mask, profile_get_ct_instrs
from milesan.toleratebugs import tolerate_bug_for_bug_timing
from params.runparams import NO_REMOVE_TMPFILES, NO_REMOVE_TMPDIRS, TRACE_EN
import os
import sys
import re

MAX_N_THREADS = 100

def _parse_logfile(path, design_name):
    with open(path, "r") as f:
        logs = f.read()
    seeds = []
    for line in logs.split("\n"):
        fuzz_id = re.findall(f"[0-9]+_{design_name}_[0-9]+_[0-9]+",line)
        if len(fuzz_id) == 1:
            assert len(fuzz_id) == 1, f"Multiple fuzz ids found in line: {line}"
            seeds += [int(fuzz_id[0].split("_")[2])]
    return seeds

if __name__ == '__main__':
    if "MILESAN_ENV_SOURCED" not in os.environ:
        raise Exception("The Milesan environment must be sourced prior to running the Python recipes.")

    if len(sys.argv) < 2:
        raise Exception("Usage: python3 do_check_isa_sims.py <design_name> [<num_cores> <n_total_tests> <seed_offset> <timeout> <log-file>]")

    if NO_REMOVE_TMPDIRS:
        print("NO_REMOVE_TMPDIRS is enabled. This might eat up a lot of memory.")

    if NO_REMOVE_TMPFILES:
        print("NO_REMOVE_TMPFILES is enabled. This might eat up a lot of memory.")

    if TRACE_EN:
        print("TRACE_EN is enabled. This might eat up a lot of memory.")

    design_name = sys.argv[1]
    n_cores = 40
    if len(sys.argv) > 2:
        n_cores = int(sys.argv[2])
    
    assert n_cores <= MAX_N_THREADS
    n_total_tests = -1
    if len(sys.argv) > 3:
        n_total_tests = int(sys.argv[3])
    
    seed_offset = 0
    if len(sys.argv) > 4:
        seed_offset = int(sys.argv[4])

    timeout = None
    if len(sys.argv) > 5:
        timeout = int(sys.argv[5])

    seeds = None
    if len(sys.argv) > 6:
        seeds = _parse_logfile(sys.argv[6], design_name)
        print(f"Parsed {len(seeds)} seeds from log file: {seeds}.")


    calibrate_spikespeed()
    profile_get_medeleg_mask(design_name)
    profile_get_asid_mask(design_name)

    check_isa_sims(design_name,n_cores,n_total_tests,seed_offset,timeout,seeds)
    
else:
    raise Exception("This module must be at the toplevel.")
