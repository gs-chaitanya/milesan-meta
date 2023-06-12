# Copyright 2023 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script executes a single program.

# sys.argv[1]: design name
# sys.argv[2]: num of cores allocated to fuzzing
# sys.argv[3]: offset for seed (to avoid running the fuzzing on the same instances over again)

from cascade.reduce import reduce_program
from common.profiledesign import profile_get_medeleg_mask
from common.spike import calibrate_spikespeed

import os

if __name__ == '__main__':
    if "CASCADE_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

    design_name = 'vexriscv'
    descriptor = (652835, design_name, 41, 23, False)

    calibrate_spikespeed()
    profile_get_medeleg_mask(design_name)

    reduce_program(*descriptor, True, check_pc_spike_again=True, hint_left_bound_bb=13, hint_right_bound_bb=14, hint_left_bound_instr=49) #, hint_left_bound_instr=229, hint_right_bound_instr=231, hint_left_bound_pillar_bb=18, hint_left_bound_pillar_instr=229)

else:
    raise Exception("This module must be at the toplevel.")
