# Copyright 2026 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only
#
# Single-seed forensic CLI: (re-)produce forensic.json + forensic_report.md for an
# existing reduction workdir.  Use this to iterate on the report format without
# re-running reductions, or to analyze a single seed in depth.
#
#   python onezero/do_forensic.py <workdir>
#   python onezero/do_forensic.py <workdir> --with-nopize --timeout 600

import argparse
import json
import os
import sys

if __name__ == "__main__":
    if "MILESAN_ENV_SOURCED" not in os.environ:
        raise Exception("The MileSan environment must be sourced first: "
                        "source /mnt/milesan-meta/env.sh")

    parser = argparse.ArgumentParser(
        description="Post-hoc forensic report for a one-zero reduction workdir"
    )
    parser.add_argument("workdir", help="Path to the per-seed reduction workdir")
    parser.add_argument("--with-nopize", action="store_true", default=False,
                        help="Run Phase 4 (NOPize) first if minimal_*.elf is missing "
                             "(requires regenerating the fuzzerstate — expensive).")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Per-simulation timeout for optional --with-nopize (default: 300s)")
    parser.add_argument("--max-nopize-attempts", type=int, default=60)
    parser.add_argument("--early-stop-after-k-failures", type=int, default=10)
    args = parser.parse_args()

    workdir = os.path.abspath(args.workdir)
    if not os.path.isdir(workdir):
        print(f"ERROR: workdir not found: {workdir}", file=sys.stderr)
        sys.exit(2)

    result_path = os.path.join(workdir, "result.json")
    if not os.path.isfile(result_path):
        print(f"ERROR: result.json missing in {workdir}; cannot proceed.", file=sys.stderr)
        sys.exit(2)
    with open(result_path) as f:
        result = json.load(f)

    design = result.get("design")
    seed = result.get("seed")
    if design is None or seed is None:
        print(f"ERROR: result.json missing design/seed.", file=sys.stderr)
        sys.exit(2)

    # Bypass profiling ELF creation (same as do_reduce.py)
    import common.profiledesign as profiledesign
    profiledesign.PROFILED_MEDELEG_MASK = 0xb3ff
    profiledesign.PROFILED_ASID_MASK = 0xFFFF

    from common.spike import calibrate_spikespeed
    from milesan.fuzzfromdescriptor import gen_new_test_instance
    from onezero.reduce_onezero import (
        patch_force_taint_value, generate_program, nopize_gadget,
    )

    calibrate_spikespeed()

    memsize, design_name, randseed, nmax_bbs, authorize_privileges = \
        gen_new_test_instance(design, seed, True)

    print(f"Regenerating fs0/fs1 for {design} seed {seed}...")
    patch_force_taint_value(0)
    fs0 = generate_program(design, seed, authorize_privileges, memsize, nmax_bbs)
    patch_force_taint_value(1)
    fs1 = generate_program(design, seed, authorize_privileges, memsize, nmax_bbs)

    # Optional: run Phase 4 if minimal ELFs are missing
    minimal_t0 = os.path.join(workdir, "minimal_t0.elf")
    minimal_t1 = os.path.join(workdir, "minimal_t1.elf")
    if args.with_nopize and (not os.path.isfile(minimal_t0) or not os.path.isfile(minimal_t1)):
        failing_bb = result.get("failing_bb_id")
        failing_instr = result.get("failing_instr_id")
        pillar_bb = result.get("pillar_bb_id")
        fault_from_prev_bb = bool(result.get("fault_from_prev_bb"))
        if failing_bb is None or failing_instr is None or pillar_bb is None:
            print("WARNING: incomplete result.json for --with-nopize, skipping Phase 4.")
        else:
            print("Running Phase 4 NOPize...")
            n_nops, gadget_size, cap_hit, mt0, mt1, sanity_ok, reason = nopize_gadget(
                fs0, fs1, pillar_bb, failing_bb, failing_instr, fault_from_prev_bb,
                timeout=args.timeout, workdir=workdir,
                max_attempts=args.max_nopize_attempts,
                early_stop_after_k_failures=args.early_stop_after_k_failures,
            )
            result["nopize"] = {
                "n_nops_added": n_nops, "gadget_size": gadget_size,
                "cap_hit": cap_hit, "sanity_check_ok": sanity_ok, "reason": reason,
                "minimal_t0_elf": mt0, "minimal_t1_elf": mt1,
            }
            # Persist back
            with open(result_path, "w") as f:
                json.dump(result, f, indent=2)

    # Build forensic
    from onezero.forensic import build_forensic
    from onezero.forensic_render import render as render_forensic
    print("Building forensic...")
    forensic = build_forensic(workdir, fs0=fs0, fs1=fs1, result=result)

    forensic_json = os.path.join(workdir, "forensic.json")
    with open(forensic_json, "w") as f:
        json.dump(forensic, f, indent=2, default=str)
    forensic_md = os.path.join(workdir, "forensic_report.md")
    with open(forensic_md, "w") as f:
        f.write(render_forensic(forensic))

    print(f"forensic.json        -> {forensic_json}")
    print(f"forensic_report.md   -> {forensic_md}")
else:
    raise Exception("This module must be at the toplevel.")
