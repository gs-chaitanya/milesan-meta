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
    new_scope = False
    for line in content.split("\n"):
        if "module" in line:
            new_scope = True
        if len(re.findall("reg\s\[[0-9]+:0\][^\[^\]]+\s\[[0-9]+:[0-9]+\];", line)):
            brackets = re.findall("\[[0-9]+:[0-9]+\]",line)
            assert len(brackets) == 2, brackets
            width = int(max(brackets[0][1:-1].split(":")))+1
            depth = int(max(brackets[1][1:-1].split(":")))+1
            name = re.findall("[^\[^\]]+",line)[2].strip()
            new_line = line + "\n"
            if new_scope:
                new_line += f"\tinteger initvar;\n"
                new_scope = False
            new_line += f"\tinitial begin\n"
            new_line += f"\tfor (initvar = 0; initvar < {depth}; initvar = initvar+1)\n"
            new_line += f"\t\t{name}[initvar] = {width}'h0;\n"
            new_line += "\tend // initial begin"
        else:
            new_line = line
        new_content += new_line + "\n"

    with open(tgt_filename, "w") as f:
        f.write(new_content)

