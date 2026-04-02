# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# Entry point for one-zero VPC-based reduction.
# Finds the first basic block whose inclusion causes s1_vpc trace divergence
# between FORCE_TAINT_VALUE=0 and =1 program variants on VpcPrint BOOM.
#
# Usage:
#   python do_reduce_onezero.py <design_name> <seed> [--hint-left N] [--hint-right N]
#                                                     [--timeout SECS] [--workdir DIR]

import argparse
import json
import os
import sys
import time

if __name__ == '__main__':
    if "MILESAN_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

    parser = argparse.ArgumentParser(
        description="One-zero VPC reduction: find the failing basic block"
    )
    parser.add_argument("design_name", help="Target design (e.g., boom)")
    parser.add_argument("seed", type=int, help="Random seed for the test program")
    parser.add_argument("--hint-left", type=int, default=None,
                        help="Left bound hint for binary search (no divergence at this BB count)")
    parser.add_argument("--hint-right", type=int, default=None,
                        help="Right bound hint for binary search (diverges at this BB count)")
    parser.add_argument("--timeout", type=int, default=600,
                        help="Per-simulation timeout in seconds (default: 600)")
    parser.add_argument("--workdir", type=str, default=None,
                        help="Output directory (default: /mnt/milesan-data/onezero_reduce/<design>_<seed>)")
    args = parser.parse_args()

    # Bypass profiling ELF creation by directly setting values.
    # Both Rocket and BOOM use Sv39 with msu privlevs, so same masks apply.
    import common.profiledesign as profiledesign
    profiledesign.PROFILED_MEDELEG_MASK = 0xb3ff
    profiledesign.PROFILED_ASID_MASK = 0xFFFF

    from common.spike import calibrate_spikespeed
    from milesan.fuzzfromdescriptor import gen_new_test_instance
    from onezero.reduce_onezero import find_failing_bb

    # Spike resolution is needed during program generation
    calibrate_spikespeed()

    # Generate the program descriptor from the seed
    memsize, design_name, randseed, nmax_bbs, authorize_privileges = \
        gen_new_test_instance(args.design_name, args.seed, True)

    # Set up output directory
    workdir = args.workdir or f"/mnt/milesan-data/onezero_reduce/{args.design_name}_{args.seed}"
    os.makedirs(workdir, exist_ok=True)

    print(f"One-zero VPC reduction for {args.design_name}, seed {args.seed}")
    print(f"  Program descriptor: memsize={memsize}, nmax_bbs={nmax_bbs}, privs={authorize_privileges}")
    print(f"  Timeout: {args.timeout}s per sim")
    print(f"  Output:  {workdir}")
    print()

    t_start = time.time()
    failing_bb, total_bbs = find_failing_bb(
        design_name, args.seed, authorize_privileges, memsize, nmax_bbs,
        timeout=args.timeout,
        workdir=workdir,
        hint_left=args.hint_left,
        hint_right=args.hint_right,
    )
    elapsed = time.time() - t_start

    if failing_bb == -1:
        print("\nReduction failed: full program does not diverge.")
        sys.exit(1)

    # Write result summary
    result = {
        "design": args.design_name,
        "seed": args.seed,
        "memsize": memsize,
        "nmax_bbs": nmax_bbs,
        "total_bbs": total_bbs,
        "failing_bb_id": failing_bb,
        "elapsed_s": round(elapsed, 1),
        "workdir": workdir,
    }
    result_path = os.path.join(workdir, "result.json")
    with open(result_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\nResult: failing BB = {failing_bb} (out of {total_bbs})")
    print(f"Total time: {elapsed:.1f}s")
    print(f"Summary written to: {result_path}")

else:
    raise Exception("This module must be at the toplevel.")
