# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script generates many Cascade ELFs.

from analyzeelfs.genmanyelfs import gen_many_elfs
from params.runparams import PATH_TO_TMP

import os

if __name__ == '__main__':
    if "MILESAN_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

    gen_many_elfs('rocket', 5, 5, os.path.join(PATH_TO_TMP, 'manyelfs'))

else:
    raise Exception("This module must be at the toplevel.")
