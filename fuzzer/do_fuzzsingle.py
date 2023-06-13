# Copyright 2023 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script executes a single program.

# sys.argv[1]: design name
# sys.argv[2]: num of cores allocated to fuzzing
# sys.argv[3]: offset for seed (to avoid running the fuzzing on the same instances over again)

from cascade.fuzzfromdescriptor import fuzz_single_from_descriptor
from common.profiledesign import profile_get_medeleg_mask
from common.spike import calibrate_spikespeed

import os
import sys

if __name__ == '__main__':
    if "CASCADE_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

    design_name = 'vexriscv-v8-9-v15'
    descriptor = (16837, design_name, 1301, 134, False)

    calibrate_spikespeed()
    profile_get_medeleg_mask(design_name)

    fuzz_single_from_descriptor(*descriptor, check_pc_spike_again=True)

else:
    raise Exception("This module must be at the toplevel.")
