# Copyright 2023 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script measures the simulator coverage of Cascade and DifuzzRTL.

from params.runparams import PATH_TO_TMP
from fuzzer.analyzeelfs.genmanyelfs import gen_many_elfs
from difuzzrtl.difuzzmodelsim import collect_coverage_modelsim_difuzzrtl_nomerge, merge_and_extract_coverages_modelsim

import os
import sys

# sys.argv[1]: Design name.
# sys.argv[2]: Number of workers.

if __name__ == '__main__':
    if "CASCADE_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

    num_workers = int(sys.argv[2])
    path_to_cascade_elfs = os.path.join(PATH_TO_TMP, 'manyelfs_modelsim')

    num_elfs_to_produce = 10000

    # Cascade
    # Generate enough ELFs
    gen_many_elfs(sys.argv[1], num_workers, num_elfs_to_produce, path_to_cascade_elfs)

    all_coverage_paths_numinstrs_tuples = collect_coverage_modelsim_difuzzrtl_nomerge(True, 0, 'rocket', num_workers, TARGET_NUM_INSTRS)
    
    # Run merging the coverage
    test_merge_coverage_modelsim_difuzzrtl(True, 0, TARGET_NUM_INSTRS, all_coverage_paths_numinstrs_tuples[0], all_coverage_paths_numinstrs_tuples[1])


    # benchmark_collect_construction_performance(int(sys.argv[1]))
    # plot_construction_performance()

else:
    raise Exception("This module must be at the toplevel.")
