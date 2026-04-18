# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# Entry point for one-zero VPC-based reduction.
# Finds the first basic block whose inclusion causes s1_vpc trace divergence
# between FORCE_TAINT_VALUE=0 and =1 program variants on VpcPrint BOOM.
#
# Usage:
#   python onezero/do_reduce.py <design_name> <seed> [--hint-left N] [--hint-right N]
#                                                    [--timeout SECS] [--workdir DIR]
#                                                    [--phase bb|instr|all]

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
    parser.add_argument("--phase", choices=["bb", "instr", "pillar", "nopize", "all"], default="all",
                        help="Reduction phases to run: bb=Phase 1, instr=Phase 1+2, pillar=Phase 1+2+3, nopize=Phase 1+2+3+4, all=Phase 1+2+3+4+forensic (default: all)")
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
    from onezero.reduce_onezero import find_failing_bb, find_failing_instr, find_pillar_bb, nopize_gadget

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

    result_path = os.path.join(workdir, "result.json")

    def _flush_result():
        """Write result.json atomically so partial progress survives PBS kills."""
        tmp = result_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(result, f, indent=2)
        os.replace(tmp, result_path)

    _flush_result()  # Phase 1 checkpoint

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
        _flush_result()  # Phase 2 checkpoint

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
            fault_from_prev_bb=result["fault_from_prev_bb"],
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

    # ---------------------------------------------------------------------------
    # Phase 4 — NOPize (gadget minimization, the forensic smoking gun)
    # ---------------------------------------------------------------------------
    result["nopize"] = None
    if args.phase in ("nopize", "all") and \
       result.get("failing_instr_id") is not None and \
       result.get("pillar_bb_id") is not None and fs0 is not None and fs1 is not None:
        try:
            t4_start = time.time()
            n_nops, gadget_size, cap_hit, minimal_t0, minimal_t1, sanity_ok, reason = \
                nopize_gadget(
                    fs0, fs1,
                    result["pillar_bb_id"], failing_bb,
                    result["failing_instr_id"],
                    result["fault_from_prev_bb"],
                    timeout=args.timeout, workdir=workdir,
                )
            elapsed_nopize = time.time() - t4_start
            result["nopize"] = {
                "n_nops_added": n_nops,
                "gadget_size": gadget_size,
                "cap_hit": cap_hit,
                "sanity_check_ok": sanity_ok,
                "reason": reason,
                "minimal_t0_elf": minimal_t0,
                "minimal_t1_elf": minimal_t1,
                "elapsed_s": round(elapsed_nopize, 1),
            }
            # objdump the minimal ELFs
            if minimal_t0 and os.path.isfile(minimal_t0):
                import subprocess
                from onezero.context import OBJDUMP, OBJDUMP_FLAGS
                for tval, elf in [(0, minimal_t0), (1, minimal_t1)]:
                    if elf and os.path.isfile(elf):
                        dump_path = elf + ".dump"
                        try:
                            with open(dump_path, "w") as f:
                                subprocess.run([OBJDUMP] + OBJDUMP_FLAGS + [elf],
                                               stdout=f, stderr=subprocess.DEVNULL,
                                               timeout=60)
                        except Exception as e:
                            print(f"WARNING: minimal dump failed (t{tval}): {e}")
        except Exception as e:
            import traceback
            print(f"WARNING: Phase 4 NOPize failed: {e}")
            traceback.print_exc()
            result["nopize_error"] = str(e)

    # ---------------------------------------------------------------------------
    # Forensic report (uses minimal ELFs when available, else reduced ELFs)
    # ---------------------------------------------------------------------------
    if args.phase == "all" and result.get("failing_instr_id") is not None and fs0 is not None:
        try:
            from onezero.forensic import build_forensic
            from onezero.forensic_render import render as render_forensic
            print("\nBuilding forensic report...")
            forensic = build_forensic(workdir, fs0=fs0, fs1=fs1, result=result)
            forensic_json_path = os.path.join(workdir, "forensic.json")
            with open(forensic_json_path, "w") as f:
                json.dump(forensic, f, indent=2, default=str)
            forensic_md_path = os.path.join(workdir, "forensic_report.md")
            with open(forensic_md_path, "w") as f:
                f.write(render_forensic(forensic))
            result["forensic"] = {
                "json": forensic_json_path,
                "report": forensic_md_path,
                "n_gadget_instrs": forensic.get("gadget", {}).get("n_instrs"),
            }
            print(f"Forensic: {forensic_md_path}")
        except Exception as e:
            import traceback
            print(f"WARNING: Forensic assembly failed: {e}")
            traceback.print_exc()
            result["forensic_error"] = str(e)

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
