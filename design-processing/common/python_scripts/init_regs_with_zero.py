# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# sys.argv[1]: source template core file
# sys.argv[2]: destination template core file

import os
import re
import sys

if __name__ == "__main__":
    src_filename = sys.argv[1]
    tgt_filename = sys.argv[2]

    with open(src_filename, "r") as f:
        content = f.read()

    new_content = ''

    # Find registers and initialize them with zero. This is necessary to avoid ambiguity between Verilator and Modelsim traces.
    for line in content.split("\n"):
        if len(re.findall("reg\s\[[0-9]+:0\][^\[^\]]+;", line)):
            if re.findall("\[[0-9]+:0\]",line):
                bitwidth = int(re.findall("\[[0-9]+:0\]",line)[0][1:-2].split(":")[0])+1
                new_line = f"{line[:-1]} = {bitwidth}'h0;"
            else:
                new_line = f"{line[:-1]} = 1'h0;"
        else:
            new_line = line
        new_content += new_line + "\n"

    with open(tgt_filename, "w") as f:
        f.write(new_content)

