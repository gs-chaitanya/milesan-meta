# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script executes a single program.

# sys.argv[1]: design name
# sys.argv[2]: num of cores allocated to fuzzing
# sys.argv[3]: offset for seed (to avoid running the fuzzing on the same instances over again)

from milesan.debug.debugreduce import debug_top
from common.profiledesign import profile_get_medeleg_mask
from common.spike import calibrate_spikespeed
from milesan.toleratebugs import tolerate_bug_for_eval_reduction

import os

if __name__ == '__main__':
    if "MILESAN_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

    design_name = 'rocket'
    descriptor = (346864, design_name, 232, 75, True)

    tolerate_bug_for_eval_reduction(design_name)
    calibrate_spikespeed()
    profile_get_medeleg_mask(design_name)

    debug_top(*descriptor, 52, 0, 0x41020)

else:
    raise Exception("This module must be at the toplevel.")
