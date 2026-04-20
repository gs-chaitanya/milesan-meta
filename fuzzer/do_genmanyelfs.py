# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script generates many Cascade ELFs.

from analyzeelfs.genmanyelfs import gen_many_elfs
from params.runparams import PATH_TO_TMP

import os
import sys

DESIGN_NAME = sys.argv[1] if len(sys.argv) > 1 else 'boom'
NUM_ELFS    = int(sys.argv[2]) if len(sys.argv) > 2 else 50000
NUM_CORES   = int(sys.argv[3]) if len(sys.argv) > 3 else 72

if __name__ == '__main__':
    if "MILESAN_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

    # Bypass profiling ELF creation by directly setting values.
    import common.profiledesign as profiledesign
    if DESIGN_NAME == 'xiangshan':
        # Values derived from XiangShan RTL sources (no profiling run needed):
        # MedelegBundle (MachineLevel.scala:593): all ExceptionBundle bits RW except EX_MCALL(11), EX_DBLTRP(16)
        # writable bits {0..10, 12, 13, 15, 18, 19, 20..23} = 0xFCB7FF
        # ASIDLEN = 16 (NewCSR.scala:29, Parameters.scala:82)
        profiledesign.PROFILED_MEDELEG_MASK = 0xFCB7FF
        profiledesign.PROFILED_ASID_MASK    = 0xFFFF
    else:
        # Rocket / BOOM: Sv39, msu, no H-extension — narrower medeleg
        profiledesign.PROFILED_MEDELEG_MASK = 0xb3ff
        profiledesign.PROFILED_ASID_MASK    = 0xFFFF

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

        gen_many_elfs(DESIGN_NAME, NUM_CORES, NUM_ELFS, os.path.join(PATH_TO_TMP, 'manyelfs'), force_taint_value=force_taint_value)

else:
    raise Exception("This module must be at the toplevel.")
