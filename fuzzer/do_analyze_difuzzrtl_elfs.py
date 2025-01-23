# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script analyzes the properties of the Cascade-generated ELFs.

from analyzeelfs.analyze import analyze_elf_prevalence, analyze_elf_dependencies, analyze_elf_symbols
from analyzeelfs.plot import plot_difuzzrtl_completions, plot_difuzzrtl_prevalences, plot_difuzzrtl_instrages

import os

if __name__ == '__main__':
    if "MILESAN_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

    NUM_ELFS = 50

    num_cores_for_elf_generation = int(os.getenv('MILESAN_JOBS', 160))

    prevalence_json = analyze_elf_prevalence(True, NUM_ELFS)
    dependencies_json = analyze_elf_dependencies(True, 'rocket', NUM_ELFS)
    symbols_json = analyze_elf_symbols(NUM_ELFS)

    plot_difuzzrtl_prevalences(prevalence_json)
    plot_difuzzrtl_instrages(dependencies_json)
    plot_difuzzrtl_completions(symbols_json)

else:
    raise Exception("This module must be at the toplevel.")
