# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script executes a single program.

from benchmarking.timereduction import eval_reduction, plot_eval_reduction
from benchmarking.findnfailinginstances import find_n_failing_descriptors
from milesan.toleratebugs import tolerate_bug_for_eval_reduction

import os

if __name__ == '__main__':
    if "MILESAN_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

    num_failing_programs_to_consider = 100
    num_cores = max(int(os.getenv('MILESAN_JOBS', 160)) // 4, 1)

    design_names = [
        'picorv32',
        'kronos',
        'vexriscv',
        'rocket',
        'cva6',
        'boom',
    ]

    for design_name in design_names:
        tolerate_bug_for_eval_reduction(design_name)
        find_n_failing_descriptors(design_name, num_failing_programs_to_consider*2, num_cores, 0, True)
        eval_reduction(design_name, num_failing_programs_to_consider, num_cores)

    plot_eval_reduction(design_names, num_failing_programs_to_consider)

else:
    raise Exception("This module must be at the toplevel.")
