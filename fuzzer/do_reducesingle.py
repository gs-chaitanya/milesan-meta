# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script executes a single program.

# sys.argv[1]: design name
# sys.argv[2]: num of cores allocated to fuzzing
# sys.argv[3]: offset for seed (to avoid running the fuzzing on the same instances over again)

from milesan.reduce import reduce_program
from params.fuzzparams import IGNORE_TAINT_MISMATCH, IGNORE_VALUE_MISMATCH, IGNORE_RTL_TIMEOUT, IGNORE_SPIKE_TIMEOUT
from milesan.toleratebugs import tolerate_bug_for_eval_reduction
from common.profiledesign import profile_get_medeleg_mask, profile_get_asid_mask
from common.spike import calibrate_spikespeed
from milesan.fuzzfromdescriptor import gen_new_test_instance
import sys
import os

if __name__ == '__main__':
    if "MILESAN_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

    if len(sys.argv) < 3:
        raise Exception("Usage: python3 do_check_isa_sims.py <design_name> <seed> [hint_left_bound_bb, hint_right_bound_bb, hint_left_bound_instr, hint_right_bound_instr, hint_left_bound_pillar_bb, hint_right_bound_pillar_bb, hint_left_bound_pillar_instr, hint_right_bound_pillar_instr] ")

    design_name = sys.argv[1]
    seed = int(sys.argv[2])
    
    hint_left_bound_bb = None
    hint_right_bound_bb = None
    hint_left_bound_pillar_bb = None
    hint_right_bound_pillar_bb = None
    hint_left_bound_instr = None
    hint_right_bound_instr = None
    hint_left_bound_pillar_instr = None
    hint_right_bound_pillar_instr = None

    if len(sys.argv) > 3:
        hint_left_bound_bb = int(sys.argv[3])
    if len(sys.argv) > 4:
        hint_right_bound_bb = int(sys.argv[4])
    if len(sys.argv) > 5:
        hint_left_bound_instr = int(sys.argv[5])
    if len(sys.argv) > 6:
        hint_right_bound_instr = int(sys.argv[6])
    if len(sys.argv) > 7:
        hint_left_bound_pillar_bb= int(sys.argv[7])
    if len(sys.argv) > 8:
        hint_right_bound_pillar_bb= int(sys.argv[8])
    if len(sys.argv) > 9:
        hint_left_bound_pillar_instr = int(sys.argv[9])
    if len(sys.argv) > 10:
        hint_right_bound_pillar_instr = int(sys.argv[10])


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
    profile_get_asid_mask(design_name)

    print(f"Reducing single program for {design_name} with seed {seed}.")
    if IGNORE_VALUE_MISMATCH:
        print(f"Ingoring value mismatches.")
    if IGNORE_SPIKE_TIMEOUT:
        print(f"Ignoring spike timeouts.")
    if IGNORE_RTL_TIMEOUT:
        print(f"Ignoring RTL timeouts.")
    if IGNORE_TAINT_MISMATCH:
        print(f"Ignoring taint mismatches.")
        
    reduce_program(*gen_new_test_instance(design_name,seed,True),
                    check_pc_spike_again=True,
                    hint_left_bound_bb=hint_left_bound_bb, 
                    hint_right_bound_bb=hint_right_bound_bb,
                    hint_left_bound_pillar_bb=hint_left_bound_pillar_bb,
                    hint_right_bound_pillar_bb=hint_right_bound_pillar_bb,
                    hint_left_bound_instr=hint_left_bound_instr,
                    hint_right_bound_instr=hint_right_bound_instr,
                    hint_left_bound_pillar_instr=hint_left_bound_pillar_instr,
                    hint_right_bound_pillar_instr=hint_right_bound_pillar_instr
                    )

else:
    raise Exception("This module must be at the toplevel.")
