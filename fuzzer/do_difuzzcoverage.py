# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script runs the control register coverage experiment.

from difuzzrtl.collectctlregcoverage import collect_control_register_coverage
from params.runparams import PATH_TO_TMP
from analyzeelfs.genmanyelfs import gen_many_elfs

import os
import subprocess

if __name__ == '__main__':
    if "MILESAN_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

    # First, generate enough ELF files from Cascade into the Docker mount
    NUM_ELFS = 50000
    # gen_many_elfs('rocket', 250, NUM_ELFS, os.path.join(os.environ['MILESAN_DOCKER_MNT_DIR'], 'manyelfs_fordifuzzcoverage')) # TODO Uncomment

    # Run the experiment for Cascade and DifuzzRTL
    # TODO Parallelize
    collect_control_register_coverage(True)
    



else:
    raise Exception("This module must be at the toplevel.")
