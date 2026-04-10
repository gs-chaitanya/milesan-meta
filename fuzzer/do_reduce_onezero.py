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
#                                                     [--phase bb|instr|all]

import argparse
import json
import os
import sys
import time

if __name__ == '__main__':
    if "MILESAN_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

    parser = argparse.ArgumentParser(
        description="One-zero VPC reduction: find the failing basic block and instruction"
    )
    parser.add_argument("design_name", help="Target design (e.g., boom)")
    parser.add_argument("seed", type=int, help="Random seed for the test program")
    parser.add_argument("--hint-left", type=int, default=None,
                        help="Left bound hint for binary search (no divergence at this BB count)")
    parser.add_argument("--hint-right", type=int, default=None,
                        help="Right bound hint for binary search (diverges at this BB count)")
    parser.add_argument("--timeout", type=int, default=900,
                        help="Per-simulation timeout in seconds (default: 900)")
    parser.add_argument("--workdir", type=str, default=None,
                        help="Output directory (default: /mnt/milesan-data/onezero_reduce/<design>_<seed>)")
    parser.add_argument("--phase", choices=["bb", "instr", "pillar", "all"], default="all",
                        help="Reduction phases to run: bb=Phase 1, instr=Phase 1+2, pillar=Phase 1+2+3, all=Phase 1+2+3 (default: all)")
    parser.add_argument("--full-context", action="store_true", default=False,
                        help="Include full per-instruction listings of intermediate BBs in context.json")
    args = parser.parse_args()

    # Bypass profiling ELF creation by directly setting values.
    # Both Rocket and BOOM use Sv39 with msu privlevs, so same masks apply.
    import common.profiledesign as profiledesign
    profiledesign.PROFILED_MEDELEG_MASK = 0xb3ff
    profiledesign.PROFILED_ASID_MASK = 0xFFFF

    from common.spike import calibrate_spikespeed
    from milesan.fuzzfromdescriptor import gen_new_test_instance
    from onezero.reduce_onezero import find_failing_bb, find_failing_instr, find_pillar_bb

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
    print(f"  Phase:   {args.phase}")
    print(f"  Output:  {workdir}")
    print()

    t_start = time.time()
    failing_bb, total_bbs, fs0, fs1 = find_failing_bb(
        design_name, args.seed, authorize_privileges, memsize, nmax_bbs,
        timeout=args.timeout,
        workdir=workdir,
        hint_left=args.hint_left,
        hint_right=args.hint_right,
    )
    elapsed_bb = time.time() - t_start

    if failing_bb == -1:
        print("\nReduction failed: full program does not diverge.")
        sys.exit(1)

    result = {
        "design": args.design_name,
        "seed": args.seed,
        "memsize": memsize,
        "nmax_bbs": nmax_bbs,
        "total_bbs": total_bbs,
        "failing_bb_id": failing_bb,
        "failing_instr_id": None,
        "fault_from_prev_bb": None,
        "elapsed_bb_s": round(elapsed_bb, 1),
        "workdir": workdir,
    }

    # Phase 2: find failing instruction
    if args.phase in ("instr", "pillar", "all"):
        print()
        t2_start = time.time()
        failing_instr = find_failing_instr(
            fs0, fs1, failing_bb,
            timeout=args.timeout,
            workdir=workdir,
        )
        elapsed_instr = time.time() - t2_start

        if failing_instr is None:
            fault_bb = failing_bb - 1
            fault_instr = len(fs0.instr_objs_seq[fault_bb]) - 1
            print(f"Leaker = BB{fault_bb} last instruction (fault from previous BB's CF)")
            result["failing_instr_id"] = fault_instr
            result["fault_from_prev_bb"] = True
        else:
            print(f"Leaker = BB{failing_bb} instruction {failing_instr}")
            result["failing_instr_id"] = failing_instr
            result["fault_from_prev_bb"] = False
        result["elapsed_instr_s"] = round(elapsed_instr, 1)

    # Phase 3: find pillar (primer) BB
    result["pillar_bb_id"] = None
    if args.phase in ("pillar", "all") and result.get("failing_instr_id") is not None:
        # Determine the (bb, instr) end-truncation point for the pillar oracle.
        # When fault_from_prev_bb=True, Phase 2 proved is_mismatch(failing_bb, instr_id=0)=True.
        # We use that as the oracle rather than the out-of-range (fault_bb, last_instr) form.
        if result["fault_from_prev_bb"]:
            p3_bb    = failing_bb
            p3_instr = 0
        else:
            p3_bb    = failing_bb
            p3_instr = result["failing_instr_id"]
        print()
        t3_start = time.time()
        pillar_bb = find_pillar_bb(
            fs0, fs1, p3_bb, p3_instr,
            timeout=args.timeout,
            workdir=workdir,
        )
        elapsed_pillar = time.time() - t3_start
        result["pillar_bb_id"] = pillar_bb
        result["elapsed_pillar_s"] = round(elapsed_pillar, 1)
        print(f"Pillar BB: {pillar_bb}")

    # ---------------------------------------------------------------------------
    # Assemble diagnostic context (post-reduction, read-only, no simulation)
    # ---------------------------------------------------------------------------
    if fs0 is not None and result.get("failing_instr_id") is not None:
        try:
            from onezero.context import (
                assemble_context, generate_reduced_artifacts, render_summary
            )
            print("\nAssembling diagnostic context...")

            context = assemble_context(
                fs0,
                memsize, nmax_bbs, authorize_privileges,
                failing_bb,
                result["failing_instr_id"],
                result["pillar_bb_id"],
                result["fault_from_prev_bb"],
                workdir,
                full_context=args.full_context,
            )

            # Inline high-signal fields into result.json
            result["leaker"]    = context.get("leaker")
            result["divergence"] = context.get("divergence")
            result["flags"]     = context.get("flags")
            result["meta"]      = context.get("meta")

            # Generate reduced ELFs + objdump
            print("Generating reduced ELF artifacts...")
            artifacts = generate_reduced_artifacts(
                fs0, fs1,
                failing_bb,
                result["failing_instr_id"],
                result["pillar_bb_id"],
                result["fault_from_prev_bb"],
                workdir,
            )
            result["artifacts"] = artifacts

            # Write context.json (full detail, potentially large)
            context_path = os.path.join(workdir, "context.json")
            with open(context_path, "w") as f:
                json.dump(context, f, indent=2)
            print(f"Context written to: {context_path}")

            # Write summary.txt (human-readable digest)
            summary_path = os.path.join(workdir, "summary.txt")
            with open(summary_path, "w") as f:
                f.write(render_summary(context, result))
            print(f"Summary written to: {summary_path}")

        except Exception as e:
            print(f"WARNING: Context assembly failed: {e}")
            result["context_error"] = str(e)

    result_path = os.path.join(workdir, "result.json")
    with open(result_path, "w") as f:
        json.dump(result, f, indent=2)

    elapsed_total = time.time() - t_start
    print(f"\nResult: failing BB = {failing_bb} (out of {total_bbs})")
    if result["failing_instr_id"] is not None:
        prev = " (fault from prev BB's CF)" if result["fault_from_prev_bb"] else ""
        print(f"        failing instr = {result['failing_instr_id']}{prev}")
    if result["pillar_bb_id"] is not None:
        print(f"        pillar BB     = {result['pillar_bb_id']}")
    print(f"Total time: {elapsed_total:.1f}s")
    print(f"Summary written to: {result_path}")

else:
    raise Exception("This module must be at the toplevel.")
