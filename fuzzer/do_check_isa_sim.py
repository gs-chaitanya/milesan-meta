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
from common.profiledesign import profile_get_medeleg_mask, profile_get_asid_mask
from cascade.toleratebugs import tolerate_bug_for_bug_timing
from params.runparams import NO_REMOVE_TMPFILES, NO_REMOVE_TMPDIRS, PRINT_INSTRUCTION_EXECUTION_IN_SITU, PRINT_INSTRUCTION_EXECUTION_FINAL
import os
import sys
MAX_N_THREADS = 60
BUG_NAME_TO_ID = {
    #### b3 ####
    # The random values loaded into the registers map to the same cache line as some program code. It is thus loaded into
    # the instruction cache and subsequently influences branch prediction.
    "boom_ras0": "b3",

    ### b4 ####
    # The non-taken cascade branches point to the random data block, thus some of the random data can be loaded into the instruction
    # cache. Now if there is data that can be decoded to a jump instruction (i.e. any JAL, JAR, C.J etc), then the subsequent address
    # is placed into the return address stack (RAS). The icache fetches contents from memory that the RAS points to (if it is not already in the 
    # icache because of a shared cache line). If an entry points to tainted data, the branch (target) prediction 
    # processes the tainted data and thus return a tainted result, subequently tainting the PC during speculative execution subsquent to a return.
    # This bug can only be discovered when "b5" is also allowed. See below.
    # Triggered quickly.
    "boom_ras1": "b4",

    ### b5 ###
    # Similar to "b4", the non-taken branches point to the random data block. If they point to an address that shares a cache line with
    # tainted data, the tainted data is loaded into the instruction cache. The contents of the instruction cache are analyzed for branch (target)
    # prediction, thus if it is tainted, the result of the branch (addresss) preduction unit (BPU) will be tainted. Then the pc gets tainted when
    # the result is used during speculative execution i.e. when an unresolved branch or indirect jump is encountered.
    # Triggered by seed 943.
    "boom_branchpred": "b5",
    
    "rocket_ras0": "r2"
}


if __name__ == '__main__':
    if "CASCADE_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

    if len(sys.argv) < 2:
        raise Exception("Usage: python3 do_check_isa_sims.py <design_name> [<num_cores> <n_total_tests> <seed_offset> <timeout>]")

    if NO_REMOVE_TMPDIRS:
        print("NO_REMOVE_TMPDIRS is enabled. This might eat up a lot of memory.")

    if NO_REMOVE_TMPFILES:
        print("NO_REMOVE_TMPFILES is enabled. This might eat up a lot of memory.")

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



    calibrate_spikespeed()
    profile_get_medeleg_mask(design_name)
    profile_get_asid_mask(design_name)

    check_isa_sims(design_name,n_cores,n_total_tests,seed_offset,timeout)
    
else:
    raise Exception("This module must be at the toplevel.")
