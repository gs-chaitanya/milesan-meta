# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script generates many Cascade ELFs.

from analyzeelfs.genmanyelfs import gen_many_elfs
from params.runparams import PATH_TO_TMP

import os

DESIGN_NAME = 'boom'  # 'rocket' or 'boom'

if __name__ == '__main__':
    if "MILESAN_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

    # Bypass profiling ELF creation by directly setting values
    # Both Rocket and BOOM use Sv39 with msu privlevs, so same masks apply
    import common.profiledesign as profiledesign
    profiledesign.PROFILED_MEDELEG_MASK = 0xb3ff
    profiledesign.PROFILED_ASID_MASK = 0xFFFF

    import params.fuzzparams
    import milesan.basicblock
    import milesan.memview
    import milesan.randomize.createcfinstr

    for force_taint_value in [0, 1]:
        # Patch before forking so all worker processes inherit the correct value.
        params.fuzzparams.FORCE_TAINT_VALUE = force_taint_value
        milesan.basicblock.FORCE_TAINT_VALUE = force_taint_value
        milesan.memview.FORCE_TAINT_VALUE = force_taint_value
        milesan.randomize.createcfinstr.FORCE_TAINT_VALUE = force_taint_value

        gen_many_elfs(DESIGN_NAME, 10, 1000, os.path.join(PATH_TO_TMP, 'manyelfs'), force_taint_value=force_taint_value)

else:
    raise Exception("This module must be at the toplevel.")
