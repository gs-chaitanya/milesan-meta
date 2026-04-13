# One-Zero VPC-Based Reduction

## Overview

This module implements a VPC-trace-based reduction approach for MileSan's information flow detection. Instead of relying on CellIFT taint-instrumented RTL (the existing MileSan approach), it detects information leakage by:

1. Generating two ELF variants per seed: one with tainted data forced to **0**, one forced to **1**
2. Running both on a **VpcPrint BOOM** simulator (`VpcPrintMediumBoomV3Config`) that logs `s1_vpc` (speculative fetch PC) changes via `$fwrite` injected into `BoomFrontend.sv`
3. Diffing the `s1_vpc` traces -- if they diverge, the secret data influenced speculative fetch = **information flow violation**

This is called the "one-zero" approach because the only difference between the two program variants is whether bits under the taint mask are forced to 0 or 1.

## Motivation

- The CellIFT taint-instrumented BOOM design is complex to build and maintain
- The one-zero VPC approach works on a much simpler custom Chipyard config (just `$fwrite` on `s1_vpc` changes)
- It can detect the same class of speculative side-channel leaks (secret influences PC/fetch)
- Reduction is needed to isolate which basic block and instruction causes the divergence

## Implemented Phases

Three reduction phases are implemented:

| Phase | Name | Purpose | Typical time |
|-------|------|---------|-------------|
| 1 | Find Failing BB | Binary search for the first BB whose inclusion causes VPC divergence | ~2-5 min |
| 2 | Find Failing Instruction | Binary search within the failing BB for the exact instruction | ~2-3 min |
| 3 | Find Pillar BB | Binary search from the front for the first "primer" BB required for the leak | ~1-3 min |

After all three phases, a **diagnostic context** is assembled with leaker details, divergence info, exploit-class flags, and reduced ELF artifacts.

Future phases (to be added incrementally):
- Phase 4: NOPize sandwich instructions (plan exists: `plans/phase4_nopize.md`)
- Phase 5-9: Reduce dead code, reduce taint, etc.

## Files

| File | Purpose |
|---|---|
| `onezero/__init__.py` | Package init (empty) |
| `onezero/reduce_onezero.py` | Core reduction logic: program generation, ELF truncation, VPC simulation, binary search (Phases 1-3) |
| `onezero/context.py` | Post-reduction diagnostic context assembly (no simulation, read-only) |
| `do_reduce_onezero.py` | Entry point script with argparse, profiling bypass, spike calibration |
| `onezero/plans/` | Implementation plans for each phase (self-contained design docs) |

## Environment Setup

### Prerequisites

**Every shell that runs the reducer MUST source the MileSan env first:**
```bash
source /mnt/milesan-meta/env.sh
```
This sets `MILESAN_ENV_SOURCED=1` (checked at entry), `PYTHONPATH`, RISC-V toolchain paths, and Chipyard vars.

For RISC-V disassembly tools (`riscv64-unknown-elf-objdump`, etc.):
```bash
source /mnt/chipyard/env.sh
```

### Required Binaries

| Binary | Path | Purpose |
|--------|------|---------|
| VpcPrint BOOM simulator | `/mnt/chipyard/sims/verilator/simulator-chipyard.harness-VpcPrintMediumBoomV3Config` | Runs ELFs and produces VPC logs |
| Spike ISA sim | On `$PATH` after `env.sh` | Used during `spike_resolution()` in program generation |
| RISC-V toolchain | `riscv32-unknown-elf-*` on `$PATH` | ELF generation (`as`, `ld`, `objcopy`) |
| RISC-V objdump | `/mnt/chipyard/.conda-env/riscv-tools/bin/riscv64-unknown-elf-objdump` | Disassembly of reduced ELFs |

### Python Dependencies

All from the MileSan fuzzer (`milesan-meta/fuzzer/`); no external pip packages needed beyond what's in the env. Key imports: `milesan.fuzzerstate`, `milesan.basicblock`, `milesan.genelf`, `milesan.spikeresolution`, `milesan.contextreplay`, `milesan.finalblock`, `milesan.gen_ctxt_final_block`.

**Cannot import `milesan/reduce.py`** — it transitively pulls the entire CellIFT taint-instrumentation chain via `drfuzz_mem.check_isa_sim_taint`. All needed functions from `reduce.py` are inlined into `reduce_onezero.py`.

## Usage

### Basic Usage

```bash
cd /mnt/milesan-meta/fuzzer
source /mnt/milesan-meta/env.sh

# Run all implemented phases (BB → instruction → pillar → context)
python do_reduce_onezero.py boom 34

# Run specific phases
python do_reduce_onezero.py boom 34 --phase bb       # Phase 1 only
python do_reduce_onezero.py boom 34 --phase instr    # Phases 1+2
python do_reduce_onezero.py boom 34 --phase pillar   # Phases 1+2+3
python do_reduce_onezero.py boom 34 --phase all      # Phases 1+2+3 + context (default)

# With hints to narrow search range (skip sanity checks, faster)
python do_reduce_onezero.py boom 34 --hint-left 5 --hint-right 15

# Custom timeout (per simulation) and output directory
python do_reduce_onezero.py boom 34 --timeout 300 --workdir /tmp/test_reduce

# Include full per-instruction listings of intermediate BBs in context.json
python do_reduce_onezero.py boom 34 --full-context
```

### CLI Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `design_name` | positional | required | Target design (e.g., `boom`) |
| `seed` | positional int | required | Random seed for the test program |
| `--phase` | choice | `all` | `bb`, `instr`, `pillar`, `all` |
| `--hint-left` | int | None | Left bound hint for BB binary search |
| `--hint-right` | int | None | Right bound hint for BB binary search |
| `--timeout` | int | 900 | Per-simulation timeout in seconds |
| `--workdir` | str | auto | Output directory |
| `--full-context` | flag | False | Include full instruction listings in context.json |

### Output

Artifacts are stored in `--workdir` (default: `/mnt/milesan-data/onezero_reduce/<design>_<seed>/`):

| File pattern | Phase | Description |
|---|---|---|
| `bbALL_t0.elf` / `bbALL_t1.elf` | 1 | Full (untruncated) program variants |
| `bb<N>_t0.elf` / `bb<N>_t1.elf` | 1 | BB-level truncated ELFs |
| `bb<N>i<M>_t0.elf` / `bb<N>i<M>_t1.elf` | 2 | Instruction-level truncated ELFs |
| `bb<N>i<M>_from<P>_t0.elf` / `_t1.elf` | 3 | Pillar-trimmed ELFs (front BBs removed) |
| `*_vpc.txt` | 1-3 | VPC trace logs per ELF |
| `*_sim.log` | 1-3 | Simulator stdout/stderr logs per ELF |
| `reduced_t0.elf` / `reduced_t1.elf` | ctx | Final reduced ELFs (most-reduced form) |
| `reduced_t0.elf.dump` / `reduced_t1.elf.dump` | ctx | Disassembly of reduced ELFs |
| `context.json` | ctx | Full diagnostic context (leaker, divergence, flags, BBs) |
| `summary.txt` | ctx | Human-readable reduction summary |
| `divergence_window.txt` | ctx | VPC log window around the divergence point |
| `result.json` | all | Summary with all phase results, timing, and inlined context |

### result.json Schema

```json
{
  "design": "boom",
  "seed": 77,
  "memsize": 472809,
  "nmax_bbs": 139,
  "total_bbs": 135,
  "failing_bb_id": 62,
  "failing_instr_id": 48,
  "fault_from_prev_bb": false,
  "elapsed_bb_s": 146.9,
  "elapsed_instr_s": 117.1,
  "pillar_bb_id": 16,
  "elapsed_pillar_s": 91.3,
  "workdir": "/mnt/milesan-data/onezero_reduce/boom_77",
  "leaker": {
    "fault_from_prev_bb": false,
    "str": "(U/0): 0x8003c7b0/0xfffffff80803c7b0: bltu gp, gp, -668",
    "mnemonic": "bltu",
    "class": "BranchInstruction_t0",
    "bytecode_hex": "d631e2e3",
    "paddr": "0x8003c7b0",
    "priv_level": "USER",
    "bb_id": 62
  },
  "divergence": {
    "vpc_log_label": "bb62i48_from16",
    "diverge_line_no": 17762,
    "cycle_t0": 36559,
    "vpc_t0": "f808049790",
    "cycle_t1": 36559,
    "vpc_t1": "0000000000",
    "total_lines_t0": 18302,
    "total_lines_t1": 18256
  },
  "flags": {
    "cross_priv": false,
    "cross_layout": false,
    "leaker_priv": "USER",
    "pillar_priv": "USER"
  },
  "meta": { "total_bbs": 135, "total_instrs": 2965, "use_mmu": true },
  "artifacts": {
    "t0": { "elf": "reduced_t0.elf", "dump": "reduced_t0.elf.dump", "elf_size": 473632 },
    "t1": { "elf": "reduced_t1.elf", "dump": "reduced_t1.elf.dump", "elf_size": 473632 }
  }
}
```

## Architecture

### Program Generation

Programs are generated using MileSan's exact machinery to ensure byte-identical ELFs:

```
gen_new_test_instance(design, seed)     # get descriptor (memsize, nmax_bbs, privs)
    |
    v
generate_program(design, seed, ...)     # per taint value (0 or 1):
    random.seed(seed)                   #   seed matches gen_fuzzerstate_elf_expectedvals()
    FuzzerState(...)                    #   same construction
    gen_basicblocks(fuzzerstate)        #   same BB generation
    spike_resolution(fuzzerstate, ...)  #   CRITICAL: resolves branch opcodes + producer offsets
    return fuzzerstate                  #   spike-resolved state ready for ELF generation
```

**Key design decision:** Spike resolution is included despite the overhead because `gen_fuzzerstate_elf_expectedvals()` (used by `do_genmanyelfs.py`) includes it. Without spike resolution, branch instructions get wrong opcodes and producer-consumer chains get wrong immediates, producing different ELFs. Verified: our ELFs are **byte-identical** to MileSan's.

### FORCE_TAINT_VALUE Patching

The taint forcing value must be patched in 4 module-level globals before generation:
- `params.fuzzparams.FORCE_TAINT_VALUE`
- `milesan.basicblock.FORCE_TAINT_VALUE`
- `milesan.memview.FORCE_TAINT_VALUE`
- `milesan.randomize.createcfinstr.FORCE_TAINT_VALUE`

This mirrors the pattern in `do_genmanyelfs.py` (lines 31-34). Done by `patch_force_taint_value()`.

### Random Seeding

Only `random.seed(seed)` matters for program generation. All `np.random` usage during `gen_basicblocks()` creates **local** `np.random.RandomState` objects seeded from `random.randrange()`. The global `np.random` state is irrelevant.

### Phase 1: Find Failing BB (Binary Search)

```
find_failing_bb():
    fs0 = generate_program(seed, taint=0)   # spike resolution, runs ONCE
    fs1 = generate_program(seed, taint=1)   # spike resolution, runs ONCE

    verify full program diverges (sanity check)

    binary search [0, total_bbs]:
        gen_truncated_elf(fs0, candidate)   # deepcopy + truncate, fast
        gen_truncated_elf(fs1, candidate)   # deepcopy + truncate, fast
        run_vpc_sim(elf_0) }                # parallel via ThreadPoolExecutor
        run_vpc_sim(elf_1) }
        compare VPC logs -> diverges?

    return (failing_bb_id, total_bbs, fs0, fs1)
```

**Invariant:** `is_mismatch(left_bound) = False`, `is_mismatch(right_bound) = True`. Binary search until `right_bound - left_bound == 1`. Returns `right_bound`.

### Phase 2: Find Failing Instruction (Binary Search)

Within the failing BB, binary search for the exact instruction whose inclusion triggers divergence.

```
find_failing_instr(fs0, fs1, failing_bb_id):
    if is_mismatch(failing_bb_id, instr_id=0):
        return None  # fault from prev BB's CF instruction

    binary search [0, len(bb)-1]:
        gen_truncated_elf_instr(fs, max_bb_id, max_instr_id)
        ... compare ...

    return failing_instr_id (or None if fault_from_prev_bb)
```

**Invariant:** Same as Phase 1 but within instruction indices. `gen_truncated_elf_instr()` keeps instructions `[0..max_instr_id]` and replaces `max_instr_id+1` with JAL to the final block.

### Phase 3: Find Pillar (Primer) BB

The pillar BB is the first BB from the front of the program that must remain for the leak to occur. BBs before it can be removed (replaced by a context-setter that restores the architectural state via Spike snapshot).

```
find_pillar_bb(fs0, fs1, failing_bb_id, failing_instr_id):
    binary search [0, failing_bb_id+1]:
        candidate = first BB to keep
        gen_truncated_elf_pillar(fs, max_bb_id, max_instr_id, first_bb=candidate)
        ... compare ...

    return pillar_bb_id  (= right_bound - 1)
```

**Invariant (opposite of Phase 1!):**
- `left_bound` = largest candidate with `mismatch=True` (primer present, leaks)
- `right_bound` = smallest candidate with `mismatch=False` (primer removed, no leak)
- Returns `right_bound - 1` = the pillar BB index

**Context save/restore:** When `first_bb > 1`, the pillar path runs `_save_ctx_and_jump_to_pillar_specific_instr_oz()` which:
1. Generates a Spike ELF, runs it to the target BB, snapshots all architectural state
2. Creates a `SavedContext` (registers, memory stores, CSRs, privilege level)
3. Generates a context-setter block at the start that restores this state
4. Redirects the initial block's jump to the context-setter, which jumps to the target BB

### ELF Generation Functions

| Function | Phase | What it does |
|----------|-------|-------------|
| `gen_truncated_elf(fs, max_bb_id, path)` | 1 | deepcopy + truncate at BB boundary + JAL to final |
| `gen_truncated_elf_instr(fs, max_bb_id, max_instr_id, path)` | 2 | truncate within BB at instruction boundary |
| `gen_truncated_elf_pillar(fs, max_bb_id, max_instr_id, first_bb, path)` | 3 | instruction-level truncation + context-save + front-trim |
| `_gen_full_elf(fs, path)` | 1 | full (untruncated) program for sanity check |

All ELF generation functions use `deepcopy(fuzzerstate)` to preserve the originals for reuse across binary search iterations.

### VPC Simulation

Uses `make -C /mnt/chipyard/sims/verilator run-binary` for consistency with the rest of the infrastructure:

```bash
make -C /mnt/chipyard/sims/verilator run-binary \
    CONFIG=VpcPrintMediumBoomV3Config \
    BINARY=<elf> VERILATOR_THREADS=1 LOADMEM=1 \
    EXTRA_SIM_FLAGS=+vpcfile=<path>
```

The Chipyard Makefile adds `+max-cycles=10000000` (from `TIMEOUT_CYCLES` in `variables.mk:334`).

**Termination handling:** `run_vpc_sim()` returns `True` if a non-empty VPC log was produced, regardless of how the sim ended (clean `$finish`, max-cycles `$stop`, watchdog hang, or Python timeout). Partial VPC traces are sufficient for divergence detection.

**VPC log format:**
```
<cycle> <s1_vpc_hex_40bit>
```
One line per `s1_vpc` change on posedge clock.

### Diagnostic Context Assembly (`context.py`)

After all reduction phases complete, `assemble_context()` builds a rich diagnostic dict from `fs0` (the full spike-resolved fuzzerstate). No simulations are run — everything comes from in-memory instruction objects and existing VPC log files.

Context includes:
- **Leaker instruction** details (mnemonic, bytecode, address, privilege, layout)
- **Leaker BB** full instruction listing
- **Pillar BB** full instruction listing
- **Intermediate BBs** summaries (between pillar and leaker)
- **VPC divergence** point (cycle, VPC values, log window)
- **Exploit-class flags** (cross-priv, cross-layout)
- **Reduced ELF artifacts** (regenerated via `gen_truncated_elf_pillar`)

## Parallelization for HPC

### Resource Profile Per Seed

Understanding the resource profile is critical for scheduling on HPC:

| Resource | Per seed | Notes |
|----------|----------|-------|
| **CPU cores** | 2 concurrent (during sim) | Each `is_mismatch_onezero` runs 2 Verilator sims in parallel via `ThreadPoolExecutor(max_workers=2)`. Each sim is single-threaded (`VERILATOR_THREADS=1`). |
| **Memory** | ~400-800 MB peak | ~200-400 MB per Verilator sim process + ~100-200 MB Python for fuzzerstate + spike |
| **Disk** | ~5-50 MB per seed (all artifacts) | ELFs ~500 KB each, VPC logs ~1-5 MB, logs ~1 MB. Sims also write to `/tmp` briefly. |
| **Wall time** | 5-15 min typical (all phases) | Phase 1: ~2-5 min, Phase 2: ~2-3 min, Phase 3: ~1-3 min, context: <1 min |
| **Sim time per iteration** | ~30-60s | Each binary search step runs 2 sims × ~30s. Early-diverging seeds may finish much faster. |
| **Program generation** | ~10-30s (one-time) | Two calls to `generate_program()` with spike resolution. Runs once at the start. |

### Independence Between Seeds

**Seeds are fully independent.** Each reduction:
- Generates its own FuzzerState from a unique `random.seed(seed)`
- Writes to its own `--workdir` directory
- Spawns its own Verilator processes
- Has no shared mutable state with other seeds

This means seed-level parallelism is trivially safe — the only shared resource is the simulator binary (read-only) and system resources (CPU, memory, `/tmp`).

### HPC Parallelization Strategy

#### Option A: Simple shell parallelism (recommended for small batches)

```bash
#!/bin/bash
# reduce_batch.sh — run N seeds in parallel
# Usage: ./reduce_batch.sh <design> <seed_start> <seed_end> <max_parallel>

DESIGN=$1
SEED_START=$2
SEED_END=$3
MAX_PARALLEL=${4:-4}

source /mnt/milesan-meta/env.sh

for seed in $(seq $SEED_START $SEED_END); do
    # Wait if at max parallel jobs
    while [ $(jobs -rp | wc -l) -ge $MAX_PARALLEL ]; do
        sleep 5
    done

    echo "[$(date +%H:%M:%S)] Starting seed $seed"
    python /mnt/milesan-meta/fuzzer/do_reduce_onezero.py "$DESIGN" "$seed" \
        --timeout 300 \
        --workdir "/mnt/milesan-data/onezero_reduce/${DESIGN}_${seed}" \
        > "/mnt/milesan-data/onezero_reduce/${DESIGN}_${seed}/stdout.log" 2>&1 &
done

wait
echo "All seeds complete."
```

#### Option B: SLURM job array (recommended for HPC clusters)

```bash
#!/bin/bash
#SBATCH --job-name=onezero-reduce
#SBATCH --array=0-99            # adjust range to number of seeds
#SBATCH --cpus-per-task=2       # 2 cores: one per Verilator sim
#SBATCH --mem=1G                # ~800 MB peak per seed, round up
#SBATCH --time=00:30:00         # 30 min per seed, generous
#SBATCH --output=logs/reduce_%A_%a.out
#SBATCH --error=logs/reduce_%A_%a.err

# ---- Configuration ----
DESIGN="boom"
SEED_OFFSET=0                   # first seed = SEED_OFFSET + SLURM_ARRAY_TASK_ID
TIMEOUT=300                     # per-simulation timeout
PHASE="all"                     # bb, instr, pillar, all

# ---- Environment ----
source /mnt/milesan-meta/env.sh

# ---- Derived ----
SEED=$((SEED_OFFSET + SLURM_ARRAY_TASK_ID))
WORKDIR="/mnt/milesan-data/onezero_reduce/${DESIGN}_${SEED}"
mkdir -p "$WORKDIR"

echo "=== Reducing ${DESIGN} seed ${SEED} on $(hostname) ==="
echo "Started: $(date)"

python /mnt/milesan-meta/fuzzer/do_reduce_onezero.py \
    "$DESIGN" "$SEED" \
    --timeout "$TIMEOUT" \
    --phase "$PHASE" \
    --workdir "$WORKDIR"

EXIT_CODE=$?
echo "Finished: $(date), exit code: $EXIT_CODE"
exit $EXIT_CODE
```

**Submit:** `sbatch reduce_array.sh`

**Check status:** `squeue -u $USER -n onezero-reduce`

**Key SLURM considerations:**
- `--cpus-per-task=2` because each oracle call runs 2 Verilator sims simultaneously.
- If your cluster nodes have many cores, you can pack multiple seeds per node. E.g., on a 32-core node, run 16 seeds simultaneously (each uses 2 CPUs).
- `--mem=1G` is conservative. If memory-constrained, you can try `--mem=512M` — most seeds peak around 400-800 MB.
- `--time=00:30:00` is generous for most seeds. Early-diverging seeds finish in 5-10 min; worst case (many BBs, late divergence) may take 20+ min.

#### Option C: GNU Parallel (flexible, no SLURM needed)

```bash
#!/bin/bash
source /mnt/milesan-meta/env.sh

# Generate seed list (e.g., from a file of known-diverging seeds)
SEEDS=$(cat diverging_seeds.txt)   # one seed per line
# or: SEEDS=$(seq 0 99)

echo "$SEEDS" | parallel -j 8 --progress --joblog reduce_joblog.txt \
    "python /mnt/milesan-meta/fuzzer/do_reduce_onezero.py boom {} \
        --timeout 300 \
        --workdir /mnt/milesan-data/onezero_reduce/boom_{} \
        > /mnt/milesan-data/onezero_reduce/boom_{}/stdout.log 2>&1"
```

### Sizing Guide

| Cluster cores | `--cpus-per-task` | Seeds in parallel | 100 seeds wall time |
|--------------|-------------------|-------------------|---------------------|
| 4 | 2 | 2 | ~5-8 hours |
| 16 | 2 | 8 | ~1.5-2 hours |
| 32 | 2 | 16 | ~45-60 min |
| 64 | 2 | 32 | ~20-30 min |

### Timeout Tuning

The default `--timeout 900` is extremely conservative. For most seeds:

- **VPC divergence appears within the first 50K cycles** (~5-10s of sim time at ~6K cycles/sec)
- The full 10M-cycle Chipyard `TIMEOUT_CYCLES` takes ~27 min per sim
- A shorter `--timeout` means partial VPC traces, which is fine — the reducer only needs enough trace to detect (or not detect) divergence

**Recommended timeouts:**
- `--timeout 120` — good for most seeds. If divergence exists, it shows up early.
- `--timeout 300` — safe default for HPC batch jobs. Handles slower-diverging seeds.
- `--timeout 900` — only needed if investigating non-diverging seeds or debugging.

You can also override `TIMEOUT_CYCLES` in the Chipyard Makefile to reduce sim time:
```bash
# In run_vpc_sim(), the make command picks up TIMEOUT_CYCLES from variables.mk.
# To reduce from 10M to 2M cycles, edit variables.mk:334 or pass it:
make -C /mnt/chipyard/sims/verilator run-binary \
    CONFIG=VpcPrintMediumBoomV3Config BINARY=<elf> \
    VERILATOR_THREADS=1 LOADMEM=1 TIMEOUT_CYCLES=2000000 \
    EXTRA_SIM_FLAGS=+vpcfile=<path>
```
Note: this is a Makefile-level change; the Python `--timeout` is a separate Python-level `subprocess.wait(timeout=...)` kill.

### Collecting Results

After a batch run, collect results into a summary:

```bash
# Aggregate all result.json files
for d in /mnt/milesan-data/onezero_reduce/boom_*/; do
    seed=$(basename "$d" | sed 's/boom_//')
    if [ -f "$d/result.json" ]; then
        echo "$d/result.json"
    else
        echo "MISSING: seed $seed" >&2
    fi
done | xargs -I{} jq -c '{
    seed: .seed,
    failing_bb: .failing_bb_id,
    failing_instr: .failing_instr_id,
    pillar: .pillar_bb_id,
    fault_prev: .fault_from_prev_bb,
    leaker_priv: .flags.leaker_priv,
    cross_priv: .flags.cross_priv,
    time_s: (.elapsed_bb_s + (.elapsed_instr_s // 0) + (.elapsed_pillar_s // 0))
}' {} | sort -t: -k2 -n

# Quick status check: which seeds completed?
ls /mnt/milesan-data/onezero_reduce/boom_*/result.json 2>/dev/null | wc -l
# Which seeds failed (no result.json)?
for seed in $(seq 0 99); do
    [ -f "/mnt/milesan-data/onezero_reduce/boom_${seed}/result.json" ] || echo "FAILED: $seed"
done
```

### Finding Diverging Seeds First

Not all seeds produce VPC divergence. Before running full reduction on 100+ seeds, identify which seeds actually diverge:

```bash
# Quick divergence screen: just run Phase 1 with short timeout
# Only the full-program sanity check matters — if it diverges, the seed is worth reducing
python do_reduce_onezero.py boom <seed> --phase bb --timeout 120
# Check exit code: 0 = diverges (found failing BB), 1 = no divergence
```

For bulk screening, you can run Phase 1 only on many seeds (faster, ~2 min each) and then run the full `--phase all` on the ones that diverge.

### Shared Filesystem Considerations

- **Workdir per seed:** Each seed writes to its own directory — no lock contention.
- **Simulator binary:** Read-only, shared. `/mnt/chipyard/sims/verilator/simulator-chipyard.harness-VpcPrintMediumBoomV3Config` is a 14 MB statically-linkable ELF; works fine from NFS or shared filesystem.
- **Spike binary:** Also read-only, accessed via `$PATH` from `env.sh`.
- **RISC-V toolchain:** Read-only. `riscv32-unknown-elf-as`, `riscv32-unknown-elf-ld`, etc. accessed from `$PATH`.
- **`/tmp`:** Each sim and ELF generation step may use `/tmp` for intermediate files. On shared-filesystem HPC, ensure each node has local `/tmp` or set `TMPDIR` to a local disk.
- **NFS throughput:** VPC log writes are small and sequential. Not a bottleneck even on slow NFS.

### Disk Space Planning

Per seed, typical artifact sizes:

| Artifact | Count per seed | Size each | Total per seed |
|----------|---------------|-----------|----------------|
| ELF files | ~10-20 (all phases) | ~500 KB | ~5-10 MB |
| VPC logs | ~10-20 | ~1-5 MB | ~10-50 MB |
| Sim logs | ~10-20 | ~100 KB | ~1-2 MB |
| reduced ELFs | 2 | ~500 KB | ~1 MB |
| objdump .dump | 2 | ~3 MB | ~6 MB |
| context.json | 1 | ~50 KB | ~50 KB |
| result.json | 1 | ~2 KB | ~2 KB |
| **Total** | | | **~25-70 MB** |

For 100 seeds: ~2.5-7 GB. For 1000 seeds: ~25-70 GB. Plan accordingly.

## Architecture Details

### The Oracle: `is_mismatch_onezero()`

The core oracle function used by all three phases:

```python
def is_mismatch_onezero(fs0, fs1, max_bb_id, timeout, workdir,
                        max_instr_id=None, first_bb=None):
```

Behavior depends on parameters:
- `max_instr_id=None, first_bb=None` → BB-level truncation (Phase 1)
- `max_instr_id=<int>, first_bb=None` → instruction-level truncation (Phase 2)
- `max_instr_id=<int>, first_bb=<int>` → pillar-trimmed truncation (Phase 3)

Each call:
1. Generates 2 truncated ELFs (one per taint value) via `deepcopy + truncate`
2. Runs 2 Verilator sims in parallel (ThreadPoolExecutor)
3. Compares VPC log files byte-by-byte

### ELF Truncation Mechanics

**BB-level (`gen_truncated_elf`):**
1. `deepcopy(fuzzerstate)` — preserve the original for reuse
2. `restore_states(max_bb_id)` — reset register/memory state
3. Replace last instruction of last-kept BB with `JAL` to final block
4. `_regen_final_block()` — regenerate exit sequence for current privilege/layout context
5. Truncate `instr_objs_seq` and `bb_start_addr_seq`
6. `verify_program()` + `gen_elf_from_bbs()`

**Instruction-level (`gen_truncated_elf_instr`):**
Same as above, but also truncates within the BB at `max_instr_id`. Instruction at `max_instr_id+1` becomes the JAL to final.

**Pillar-trimmed (`gen_truncated_elf_pillar`):**
1. Instruction-level truncation (end of program)
2. `_save_ctx_and_jump_to_pillar_specific_instr_oz()` — Spike-based context snapshot + context-setter BB generation
3. Delete BBs `[1, first_bb)` from the program
4. `verify_program()` + `gen_elf_from_bbs()`

### Context Save/Restore (Phase 3)

`_save_ctx_and_jump_to_pillar_specific_instr_oz()` is the most complex function, inlined from `reduce.py`. It:

1. Generates a Spike ELF of the (already end-truncated) program
2. Runs Spike to the target BB's first instruction
3. Snapshots: integer registers, FP CSR, mepc, sepc, mcause, scause, mscratch, sscratch, mtvec, stvec, medeleg, mstatus, minstret, satp, privilege level, and all memory stores
4. Builds a `SavedContext` with all these values (taint values zeroed — VPC oracle doesn't need them)
5. Calls `gen_context_setter()` which generates a new BB that writes all these values back
6. Redirects the initial block's tail jump to the context-setter

## Testing History

### Seed 34 (Phase 1 only)

- **Program descriptor:** memsize=505489, nmax_bbs=280, privs=True, actual BBs=22
- **ELF correctness:** Byte-identical to MileSan's `gen_fuzzerstate_elf_expectedvals()` output
- **VPC divergence point:** Cycle ~27,573 (line 13,174 of VPC log)
- **Sim termination:** Full program does NOT reach tohost within 10M cycles; sim terminates via `$stop`

### Seed 77 (Full reduction, all phases)

- **Total BBs:** 135, **Failing BB:** 62, **Failing instr:** 48, **Pillar BB:** 16
- **Leaker:** `bltu gp, gp, -668` at `0x8003c7b0` in User mode, layout 0
- **Exploit class:** Not cross-priv, not cross-layout (both leaker and pillar in User mode)
- **Divergence:** Line 17,762 / cycle 36,559
- **Total time:** ~355s (BB: 147s, instr: 117s, pillar: 91s)

### Seed 103 (Phase 1 only, pre-PRNG-fix)

- **Total BBs:** 170, **Failing BB:** 59
- **Total time:** 238s
- **Note:** Result is from commit `7760420a` (pre-PRNG-fix). Results differ on current HEAD.

## Dependencies

| Dependency | Path | Purpose |
|---|---|---|
| MileSan fuzzer | `milesan-meta/fuzzer/` | Program generation, fuzzerstate, instruction classes |
| Spike RISC-V ISA simulator | on `$PATH` via `env.sh` | `spike_resolution` during program generation; context snapshots in Phase 3 |
| VpcPrint BOOM simulator | `/mnt/chipyard/sims/verilator/simulator-chipyard.harness-VpcPrintMediumBoomV3Config` | VPC trace generation |
| RISC-V toolchain (32-bit) | `riscv32-unknown-elf-*` via `env.sh` | ELF generation (assembler, linker, objcopy) |
| RISC-V toolchain (64-bit) | `/mnt/chipyard/.conda-env/riscv-tools/bin/riscv64-unknown-elf-*` | ELF disassembly (objdump) |
| Chipyard build system | `/mnt/chipyard/sims/verilator/Makefile` | `make run-binary` invocation for sims |

## Key Reference Files

| File | What it provides |
|---|---|
| `milesan/reduce.py` | Original 9-phase CellIFT reduction. Phase 1 based on `_find_failing_bb()` (line 638), Phase 2 on `_find_failing_instr_in_bb()` (line 763), Phase 3 on `_find_pillar_bb()` (line 694). |
| `milesan/fuzzfromdescriptor.py` | `gen_new_test_instance()` (line 25) and `gen_fuzzerstate_elf_expectedvals()` (line 33) — canonical seeding and generation |
| `do_genmanyelfs.py` | Reference for FORCE_TAINT_VALUE patching pattern and ELF generation loop |
| `milesan/finalblock.py` | `finalblock()` generates the tohost exit sequence (writes 1 to `stopsigaddr`) |
| `milesan/gen_ctxt_final_block.py` | Helper functions for regenerating final block in correct privilege/layout context |
| `milesan/spikeresolution.py` | `spike_resolution()` — modifies instruction objects in-place (branch opcodes, producer offsets) |
| `milesan/contextreplay.py` | `SavedContext` and `gen_context_setter` — context save/restore for pillar search |
| `chipyard/variables.mk:334` | `TIMEOUT_CYCLES = 10000000` — Chipyard's default max-cycles |

## Open Issues / TODO

1. **Phase 4: NOPize sandwich instructions.** Plan exists at `plans/phase4_nopize.md`. Greedily replaces non-essential instructions between the pillar and leaker with NOPs. Expected to be the most time-consuming phase (~30s per instruction × hundreds of instructions = hours). The plan exists but implementation has not started.

2. **Phase 5-9: Future reduction phases.** Reduce dead code, reduce taint, etc. These mirror the remaining phases in `milesan/reduce.py` but use the VPC divergence oracle.

3. **`TIMEOUT_CYCLES` override.** Currently the 10M-cycle Chipyard default is used. For HPC batch runs, consider reducing to 2M-3M cycles to cut sim time from ~27 min to ~5-8 min per sim. This requires either editing `variables.mk` or passing `TIMEOUT_CYCLES=2000000` in the make command (would need a code change to `run_vpc_sim()`).

4. **Determinism validation.** The VPC oracle should be deterministic (same ELF → same VPC trace). Verify this holds under HPC conditions (different nodes, different `/tmp` filesystems, etc.).

5. **Bulk screening script.** A dedicated script to screen many seeds for VPC divergence (Phase 1 only, short timeout) and produce a list of diverging seeds for full reduction.
