# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script cleans all designs listed in the design_repos json file.

# Each design is built in a separate process group.
# Each design is first run until the beginning of the instrumentation once (this is a critical section). Then, all the instrumentations are run in parallel.

# Command-line arguments:
#     --no-notrace
#     --no-trace
#     --do-trace_fst
#     --exclude-designs <list_of_designs>
#     --single-threaded
#     --verilator
#     --modelsim

import argparse
import json
import multiprocessing
import subprocess
import os
import sys
from collections import defaultdict

if "MILESAN_ENV_SOURCED" not in os.environ:
    raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

DESIGN_CFGS_BASENAME = "design_repos.json"
PATH_TO_DESIGN_CFGS = os.path.join(os.getenv("MILESAN_DESIGN_PROCESSING_ROOT"), DESIGN_CFGS_BASENAME)

####
# Parse the command-line argumens
####

parser = argparse.ArgumentParser(description='Make all the designs.')
parser.add_argument('--no-notrace',      action='store_true', help='Do not build the *_notrace target')
parser.add_argument('--no-trace',        action='store_true', help='Do not build the *_trace target')
parser.add_argument('--do-trace_fst',    action='store_false', help='Also build the *_trace_fst target')
parser.add_argument('--exclude-designs', nargs='*', type=str, default=[], help='Exclude a list of designs, for example --exclude-designs ibex cva6')
parser.add_argument('--single-threaded', action='store_true', help='Run the script in single-threaded mode. This can help in preventing spurious segmentation faults')
parser.add_argument('--verilator',       action='store_true', help='Build the designs for Verilator')
parser.add_argument('--modelsim',        action='store_true', help='Build the designs for Modelsim')

args = parser.parse_args()

# Exclude trace targets if requested.
build_target_notrace = not args.no_notrace
build_target_trace = not args.no_trace
build_target_trace_fst = not args.do_trace_fst
force_single_threaded = args.single_threaded
if not (build_target_notrace or build_target_trace or build_target_trace_fst):
    raise ValueError("No target to build: all targets were excluded with --no-notrace, --no-trace, --no-trace_fst simultaneously")

# Exclude designs if requested.
exclude_designs = args.exclude_designs
if exclude_designs:
    print("Exclude designs", exclude_designs)

# Run in parallel on given number of processes.
if force_single_threaded:
    tot_num_processes = 1
else:
    tot_num_processes = int(os.getenv("MILESAN_JOBS"))

####
# Prepare configurations to build
####

with open(PATH_TO_DESIGN_CFGS, "r") as f:
    design_json_content = json.load(f)
design_names = list(design_json_content.keys())

# Check that all the designs to be excluded are present in the design names.
if set(exclude_designs)-set(design_names):
    raise ValueError("Requested to exclude design(s) {} that are not among the present designs: {}.".format(', '.join(list(set(exclude_designs)-set(design_names))), ', '.join(design_names)))

# Remove designs requested to remove.
for design_to_exclude in set(exclude_designs):
    design_names.remove(design_to_exclude)

# Generate the pairs (design_name, instrumentation method <as a string>).
# These pairs are to be used in a later stage of the multiprocessing pool.
instrumentation_methods = ["vanilla_mem", "vanilla_nomem", "rfuzz", "rfuzz_mem", "drfuzz", "drfuzz_mem"] # no drfuzz for now

design_instrumentation_pairs = []
for design_name in design_names:
    design_instrumentation_pairs += [(design_name, im) for im in instrumentation_methods]

# For the last multiprocessing stage, add suffixes to specify whether to use traces or not.
design_instrumentation_extended_pairs = []
for design_name in design_names:

    # Generate the instrumentation methods *_trace and *_notrace
    instrumentation_methods_with_suffix = []
    if build_target_notrace:
        instrumentation_methods_with_suffix += list(map(lambda s: s+"_notrace", instrumentation_methods))
    if build_target_trace:
        instrumentation_methods_with_suffix += list(map(lambda s: s+"_trace", instrumentation_methods))
    if build_target_trace_fst:
        instrumentation_methods_with_suffix += list(map(lambda s: s+"_trace_fst", instrumentation_methods))

    # Generate the return pairs
    design_instrumentation_extended_pairs += [(design_name, im) for im in instrumentation_methods_with_suffix]

#####
# Three auxiliary functions
#####

cached_configs = defaultdict(dict)
cached_start_addrs = defaultdict(dict)

def get_design_milesan_path(design_name):
    # 1. Find the designs folder.
    designs_folder = os.getenv("MILESAN_DESIGN_PROCESSING_ROOT")
    if not designs_folder:
        raise Exception("Please re-source env.sh first, in the meta repo, and run from there, not this repo. See README.md in the meta repo")
    # 2. Find the repo name.
    with open(PATH_TO_DESIGN_CFGS, "r") as f:
        read_dict = json.load(f)
    try:
        repo_name = read_dict[design_name]
    except:
        candidate_names = read_dict.keys()
        raise ValueError("Design name not in design_repos.json: {}. Candidates are: {}.".format(design_name, ', '.join(candidate_names)))
    return os.path.join(designs_folder, repo_name)

# @param design_name: must be one of the keys of the design_repos.json dict.
# @return the design config of the relevant repo.
def get_design_cfg(design_name):
    if not cached_configs[design_name]:
        with open(os.path.join(get_design_milesan_path(design_name), "meta", "cfg.json"), "r") as f:
            cached_configs[design_name] = json.load(f)
    return cached_configs[design_name]

# For Verilator
# @param design_name: must be one of the keys of the design_repos.json dict.
# @param extended_target a stringified pair (instrumentation_method, trace_type). For instance vanilla_trace 
# @return the HSB path relative to the given milesan dir.
def get_design_hsb_path(design_name, extended_target):
    toplevel_name = get_design_cfg(design_name)["toplevel"]
    return "build/run_{}_0.1/default-verilator/V{}".format(extended_target, toplevel_name)
# For Modelsim. Not used.
# @param design_name: must be one of the keys of the design_repos.json dict.
# @param extended_target a stringified pair (instrumentation_method, trace_type). For instance vanilla_trace 
# @return the worklib path relative to the given milesan dir.
def get_design_worklib_path(extended_target):
    return "modelsim/work_{}".format(extended_target)

#####
# Workers for the three stages
#####

# First-stage worker, called only once per design.
def pre_instrumentation_worker(design_name):
    design_milesan_path = get_design_milesan_path(design_name)
    cmdline = ["make", "-C", design_milesan_path, "before_instrumentation"]
    subprocess.check_call(cmdline)

# Second-stage worker, called once per (design, instrumentation_type) pair.
# @param instrumentation_method: "vanilla"
def instrumentation_worker(design_name, instrumentation_method):
    design_milesan_path = get_design_milesan_path(design_name)
    cmdline = ["make", "-C", design_milesan_path, "generated/out/{}.sv".format(instrumentation_method)]
    subprocess.check_call(cmdline)

# Last-stage worker, called for each (design, extended_target) pair.
# @param extended_target a stringified pair (instrumentation_method, trace_type). For instance vanilla_trace 
def synthesis_worker_verilator(design_name, extended_target):
    design_milesan_path = get_design_milesan_path(design_name)
    cmdline = ["make", "-C", design_milesan_path, get_design_hsb_path(design_name, extended_target)]
    subprocess.check_call(cmdline)
# @param extended_target a stringified pair (instrumentation_method, trace_type). For instance vanilla_trace 
def synthesis_worker_modelsim(design_name, extended_target):
    design_milesan_path = get_design_milesan_path(design_name)
    cmdline = ["make", "-C", design_milesan_path, f"build_{extended_target}_modelsim"]
    subprocess.check_call(cmdline)


#####
# Run the workers
#####

# Run in parallel.
# First stage: per-design critical section. This must be done sequentially, else we get segmentation faults in some tools.
worker_params = design_names
for worker_param in worker_params:
    pre_instrumentation_worker(worker_param)
# my_pool.map(pre_instrumentation_worker, worker_params) Do not parallelize this stage.
# Second stage: run the instrumentation of all the designs with all instrumentation methods.
my_pool_second = multiprocessing.Pool(tot_num_processes)
worker_params = design_instrumentation_pairs
my_pool_second.starmap(instrumentation_worker, worker_params)
my_pool_second.close()
my_pool_second.join()

# Third stage: run the syntheses.
my_pool_third = multiprocessing.Pool(tot_num_processes)
worker_params = design_instrumentation_extended_pairs
if args.verilator:
    my_pool_third.starmap(synthesis_worker_verilator, worker_params)
if args.modelsim:
    my_pool_third.starmap(synthesis_worker_modelsim, worker_params)
my_pool_third.close()
my_pool_third.join()

print("Success! All design simulation binaries are synthesized and ready to run.")
