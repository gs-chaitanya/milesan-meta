# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script measures the program construction performance.

from benchmarking.fuzzperf import benchmark_collect_construction_performance, plot_construction_performance

import os
import sys

# sys.argv[1]: Number of workers. More workers measure faster but slightly favor shorter runs.

if __name__ == '__main__':
    if "MILESAN_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

    benchmark_collect_construction_performance(int(sys.argv[1]))
    plot_construction_performance()

else:
    raise Exception("This module must be at the toplevel.")
