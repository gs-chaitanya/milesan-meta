# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script cleans all designs listed in the design_repos json file.

import json
import multiprocessing
import subprocess
import os

if "MILESAN_ENV_SOURCED" not in os.environ:
    raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

DESIGN_CFGS_BASENAME = "design_repos.json"
PATH_TO_DESIGN_CFGS = os.path.join(os.getenv("MILESAN_DESIGN_PROCESSING_ROOT"), DESIGN_CFGS_BASENAME)

# Ask confirmation before cleaning all designs.
confirmation_str = input("This will clean all the design repositories listed in {}. Continue (yes|NO)?".format(DESIGN_CFGS_BASENAME))
if confirmation_str.lower() not in ["y","yes"]:
    print("Aborted.")

# Read the list of paths to the design milesan directories.
with open(PATH_TO_DESIGN_CFGS, "r") as f:
    design_json_content = json.load(f)
design_milesan_paths = list(design_json_content.values())

# Run cleaning in parallel.
num_processes = int(os.getenv("MILESAN_JOBS"))
def worker(design_milesan_path):
    cmdline = ["make", "-C", design_milesan_path, "clean"]
    subprocess.check_call(cmdline)
my_pool = multiprocessing.Pool(num_processes)
my_pool.map(worker, design_milesan_paths)
