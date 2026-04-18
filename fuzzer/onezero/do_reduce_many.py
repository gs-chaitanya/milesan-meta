# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# Parallel one-zero VPC reduction over many seeds.
#
# Each seed runs as an independent subprocess (onezero/do_reduce.py), so there is
# no shared mutable Python state between workers.  Designed for PBS job arrays on
# the Vanda cluster: each array task calls this script with --shard I/N to handle
# its stride of the seed list.
#
# Usage:
#   python onezero/do_reduce_many.py boom --jsonl /mnt/results_boom_vpclog.jsonl --workers 36
#   python onezero/do_reduce_many.py boom --jsonl /mnt/results_boom_vpclog.jsonl --shard 0/4 --workers 36
#   python onezero/do_reduce_many.py boom --seeds 34,77,103 --workers 2

import argparse
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from concurrent.futures.process import BrokenProcessPool

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
ENTRY_POINT = os.path.join(THIS_DIR, "do_reduce.py")
DEFAULT_WORKDIR_BASE = "/mnt/milesan-data/onezero_reduce"


def load_diverging_seeds(jsonl_path):
    seeds = []
    with open(jsonl_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec.get("status") == "diverge":
                seeds.append(int(rec["seed"]))
    seeds.sort()
    return seeds


def _reduce_one_seed(design_name, seed, phase, timeout, workdir, full_context):
    """Worker: invoke do_reduce_onezero.py for one seed as a subprocess.

    Returns (seed, exit_code, elapsed_s, result_dict_or_None).
    """
    t0 = time.time()
    os.makedirs(workdir, exist_ok=True)

    cmd = [
        sys.executable, ENTRY_POINT,
        design_name, str(seed),
        "--phase", phase,
        "--timeout", str(timeout),
        "--workdir", workdir,
    ]
    if full_context:
        cmd.append("--full-context")

    log_path = os.path.join(workdir, "stdout.log")
    with open(log_path, "w") as log_f:
        proc = subprocess.run(cmd, stdout=log_f, stderr=subprocess.STDOUT)

    elapsed = time.time() - t0

    result = None
    result_path = os.path.join(workdir, "result.json")
    if os.path.isfile(result_path):
        try:
            with open(result_path) as f:
                result = json.load(f)
        except Exception:
            pass

    return seed, proc.returncode, round(elapsed, 1), result


if __name__ == "__main__":
    if "MILESAN_ENV_SOURCED" not in os.environ:
        raise Exception(
            "The MileSan environment must be sourced first: source /mnt/milesan-meta/env.sh"
        )

    parser = argparse.ArgumentParser(
        description="Parallel one-zero VPC reduction over many seeds"
    )
    parser.add_argument("design_name", help="Target design (e.g., boom)")

    seed_group = parser.add_mutually_exclusive_group(required=True)
    seed_group.add_argument(
        "--jsonl", type=str,
        help="Path to results JSONL; seeds with status='diverge' are selected",
    )
    seed_group.add_argument(
        "--seeds", type=str,
        help="Comma-separated list of seeds (e.g., 34,77,103)",
    )

    parser.add_argument(
        "--shard", type=str, default=None,
        help="Stride shard I/N: process seeds[I::N]. For PBS: --shard $PBS_ARRAY_INDEX/$N_TASKS",
    )
    parser.add_argument(
        "--workers", type=int, default=36,
        help="Parallel reductions per node (default: 36, i.e. 72 cores / 2 CPUs per reduction)",
    )
    parser.add_argument(
        "--timeout", type=int, default=300,
        help="Per-simulation timeout in seconds (default: 300)",
    )
    parser.add_argument(
        "--phase", choices=["bb", "instr", "pillar", "nopize", "all"], default="all",
        help="Reduction phases (default: all)",
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Process only the first N diverging seeds (applied before sharding).",
    )
    parser.add_argument(
        "--workdir-base", type=str, default=DEFAULT_WORKDIR_BASE,
        help=f"Base output directory (default: {DEFAULT_WORKDIR_BASE})",
    )
    parser.add_argument(
        "--full-context", action="store_true", default=False,
        help="Include full per-instruction listings in context.json",
    )
    parser.add_argument(
        "--summary", type=str, default=None,
        help="Path to write a JSON summary of all results",
    )
    args = parser.parse_args()

    # ── Build seed list ──────────────────────────────────────────────────────
    if args.jsonl:
        all_seeds = load_diverging_seeds(args.jsonl)
    else:
        all_seeds = sorted(int(s.strip()) for s in args.seeds.split(",") if s.strip())

    # ── Apply --limit (before sharding, so shards slice the limited set) ─────
    if args.limit is not None and args.limit > 0:
        all_seeds = all_seeds[: args.limit]

    # ── Apply sharding ───────────────────────────────────────────────────────
    if args.shard is not None:
        shard_idx, n_shards = (int(x) for x in args.shard.split("/"))
        seeds = all_seeds[shard_idx::n_shards]
        shard_label = f" (shard {shard_idx}/{n_shards})"
    else:
        seeds = all_seeds
        shard_label = ""

    # ── Resume mode: skip seeds whose result.json already exists ─────────────
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

    pre_seeds = list(seeds)
    skipped_seeds = []
    todo_seeds = []
    for s in pre_seeds:
        rj = os.path.join(args.workdir_base, f"{args.design_name}_{s}", "result.json")
        if os.path.isfile(rj):
            skipped_seeds.append(s)
        else:
            todo_seeds.append(s)
    seeds = todo_seeds

    if not seeds:
        print(f"No seeds to reduce{shard_label} (all {len(skipped_seeds)} already done). Exiting.")
        sys.exit(0)

    n_seeds = len(seeds)
    n_workers = min(args.workers, n_seeds)

    print("=" * 60)
    print(f" One-zero parallel reduction{shard_label}")
    print(f" Design:   {args.design_name}")
    print(f" Seeds:    {n_seeds} to reduce, {len(skipped_seeds)} already done (of {len(all_seeds)} total diverging)")
    print(f" Workers:  {n_workers}")
    print(f" Phase:    {args.phase}")
    print(f" Timeout:  {args.timeout}s per sim")
    print(f" Workdir:  {args.workdir_base}/<design>_<seed>/")
    print(f" Started:  {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print()

    t_wall = time.time()
    all_results = {}

    # Remaining seeds that never produced a final result (tracked so we can
    # detect silent kills: e.g. BrokenProcessPool).  Initially every seed is
    # "pending"; we remove each one when it either succeeds, fails cleanly, or
    # raises in fut.result().
    pending = set(seeds)
    n_broken_retries = 0
    MAX_BROKEN_RETRIES = 3

    # Use 1-element lists as mutable counters (nonlocal/global would require
    # module-level scope; cleaner to just pass by reference via list).
    counters = {"ok": 0, "fail": 0}

    def _drain(executor, futures):
        """Drain a pool, tolerating BrokenProcessPool.  Returns True if pool broke."""
        try:
            for fut in as_completed(futures):
                seed_id = futures[fut]
                try:
                    seed_out, exit_code, elapsed_s, result = fut.result()
                except BrokenProcessPool as e:
                    print(f"  seed {seed_id:5d}:  POOL-BROKEN ({e})", flush=True)
                    return True
                except Exception as e:
                    print(f"  seed {seed_id:5d}:  ERROR   {e}", flush=True)
                    all_results[seed_id] = {"exit_code": -1, "error": str(e)}
                    counters["fail"] += 1
                    pending.discard(seed_id)
                    continue

                if exit_code == 0 and result is not None:
                    fb = result.get("failing_bb_id", "?")
                    fi = result.get("failing_instr_id", "?")
                    pb = result.get("pillar_bb_id", "?")
                    print(f"  seed {seed_out:5d}:  OK      {elapsed_s:6.1f}s  bb={fb} instr={fi} pillar={pb}", flush=True)
                    counters["ok"] += 1
                else:
                    print(f"  seed {seed_out:5d}:  FAILED  {elapsed_s:6.1f}s  exit={exit_code}", flush=True)
                    counters["fail"] += 1

                all_results[seed_out] = {
                    "exit_code": exit_code,
                    "elapsed_s": elapsed_s,
                    "result": result,
                }
                pending.discard(seed_out)
        except BrokenProcessPool as e:
            print(f"  POOL-BROKEN during drain: {e}", flush=True)
            return True
        return False

    while pending and n_broken_retries <= MAX_BROKEN_RETRIES:
        submit_seeds = list(pending)
        print(f"  Submitting {len(submit_seeds)} seed(s) to pool (retry {n_broken_retries})", flush=True)
        try:
            with ProcessPoolExecutor(max_workers=min(n_workers, len(submit_seeds))) as executor:
                futures = {}
                for seed in submit_seeds:
                    workdir = os.path.join(args.workdir_base, f"{args.design_name}_{seed}")
                    # Resume safety: if a prior retry finished this seed, skip
                    rj = os.path.join(workdir, "result.json")
                    if os.path.isfile(rj):
                        pending.discard(seed)
                        continue
                    fut = executor.submit(
                        _reduce_one_seed,
                        args.design_name, seed, args.phase, args.timeout, workdir,
                        args.full_context,
                    )
                    futures[fut] = seed

                broke = _drain(executor, futures)
        except BrokenProcessPool as e:
            print(f"  POOL-BROKEN at shutdown: {e}", flush=True)
            broke = True
        except Exception as e:
            print(f"  UNEXPECTED pool exception: {type(e).__name__}: {e}", flush=True)
            broke = True

        if not broke:
            break
        n_broken_retries += 1
        print(f"  Pool broke; retry {n_broken_retries}/{MAX_BROKEN_RETRIES}, {len(pending)} seed(s) still pending", flush=True)

    # Any seeds still in `pending` after all retries: record as unfinished
    for s in pending:
        all_results[s] = {"exit_code": -2, "error": "unfinished after broken-pool retries"}
        counters["fail"] += 1
        print(f"  seed {s:5d}:  UNFINISHED", flush=True)

    n_ok = counters["ok"]
    n_fail = counters["fail"]
    wall_elapsed = time.time() - t_wall

    print()
    print("=" * 60)
    print(f" Done: {n_ok}/{n_seeds} succeeded, {n_fail} failed")
    print(f" Wall time: {wall_elapsed:.1f}s ({wall_elapsed/60:.1f} min)")
    print(f" Finished:  {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    if args.summary:
        summary_dir = os.path.dirname(os.path.abspath(args.summary))
        if summary_dir:
            os.makedirs(summary_dir, exist_ok=True)
        with open(args.summary, "w") as f:
            json.dump({
                "design": args.design_name,
                "n_total_diverging": len(all_seeds),
                "shard": args.shard,
                "seeds": seeds,
                "n_seeds": n_seeds,
                "n_ok": n_ok,
                "n_fail": n_fail,
                "wall_elapsed_s": round(wall_elapsed, 1),
                "phase": args.phase,
                "timeout": args.timeout,
                "per_seed": {str(k): v for k, v in all_results.items()},
            }, f, indent=2)
        print(f"Summary written to: {args.summary}")

else:
    raise Exception("This module must be at the toplevel.")
