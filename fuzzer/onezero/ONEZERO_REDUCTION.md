# One-Zero VPC-Based Reduction

## Overview

This module implements a new reduction approach for MileSan's information flow detection. Instead of relying on CellIFT taint-instrumented RTL (the existing MileSan approach), it detects information leakage by:

1. Generating two ELF variants per seed: one with tainted data forced to **0**, one forced to **1**
2. Running both on a **VpcPrint BOOM** simulator (Chipyard `VpcPrintMediumBoomV3Config`) that logs `s1_vpc` (speculative fetch PC) changes via `$fwrite` injected into `BoomFrontend.sv`
3. Diffing the `s1_vpc` traces -- if they diverge, the secret data influenced speculative fetch = **information flow violation**

This is called the "one-zero" approach because the only difference between the two program variants is whether bits under the taint mask are forced to 0 or 1.

## Motivation

- The CellIFT taint-instrumented BOOM design is complex to build and maintain
- The one-zero VPC approach works on a much simpler custom Chipyard config (just `$fwrite` on `s1_vpc` changes)
- It can detect the same class of speculative side-channel leaks (secret influences PC/fetch)
- Reduction is needed to isolate which basic block causes the divergence

## Current Scope: Find Failing BB (Phase 1 only)

Only the first reduction phase is implemented: **binary search for the failing basic block**. This identifies the first BB whose inclusion causes VPC divergence between the taint=0 and taint=1 variants.

Future phases (to be added incrementally):
- Find failing instruction within the BB
- Pillar search
- NOPize non-essential instructions
- Reduce dead code
- Reduce taint

These mirror the 9 phases in `milesan/reduce.py` but use the VPC divergence oracle instead of CellIFT taint checking.

## Files

| File | Purpose |
|---|---|
| `onezero/__init__.py` | Package init (empty) |
| `onezero/reduce_onezero.py` | Core reduction logic: program generation, ELF truncation, VPC simulation, binary search |
| `do_reduce_onezero.py` | Entry point script with argparse, profiling bypass, spike calibration |

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

This mirrors the pattern in `do_genmanyelfs.py` (lines 31-34).

### Random Seeding

Only `random.seed(seed)` matters for program generation. All `np.random` usage during `gen_basicblocks()` creates **local** `np.random.RandomState` objects seeded from `random.randrange()`. The global `np.random` state is irrelevant. Verified by tracing all `np.random` calls in `basicblock.py:385`, `initialblock.py:216`, `createcfinstr.py:275`.

### Binary Search (Find Failing BB)

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

    return failing_bb_id
```

**Invariant:** `is_mismatch(left_bound) = False`, `is_mismatch(right_bound) = True`. Binary search until `right_bound - left_bound == 1`. Returns `right_bound`.

### ELF Truncation

`gen_truncated_elf()` is a simplified version of `gen_reduced_elf()` Phase 1 from `reduce.py`:
1. `deepcopy(fuzzerstate)` -- preserve the original for reuse
2. `restore_states(max_bb_id)` -- reset register/memory state
3. Replace last instruction of last-kept BB with `JAL` to final block
4. `_regen_final_block()` -- regenerate exit sequence for current privilege/layout context
5. Truncate `instr_objs_seq` and `bb_start_addr_seq`
6. `verify_program()` + `gen_elf_from_bbs()`

`_regen_final_block()` is inlined from `reduce.py:gen_ctxt_finalbock()` to avoid importing `reduce.py` which pulls in the heavy CellIFT simulation backend. It uses helpers from `milesan/gen_ctxt_final_block.py` (`get_last_real_layout`, `get_last_mpp`, `get_last_sum_mprv`).

### VPC Simulation

Uses `make -C /mnt/chipyard/sims/verilator run-binary` for consistency with the rest of the infrastructure:

```
make run-binary CONFIG=VpcPrintMediumBoomV3Config \
    BINARY=<elf> VERILATOR_THREADS=1 LOADMEM=1 \
    EXTRA_SIM_FLAGS=+vpcfile=<path>
```

The Chipyard Makefile adds `+max-cycles=10000000` (from `TIMEOUT_CYCLES` in `variables.mk`).

**Termination handling:** `run_vpc_sim()` returns `True` if a non-empty VPC log was produced, regardless of how the sim ended (clean `$finish`, max-cycles `$stop`, watchdog hang, or Python timeout). Partial VPC traces are sufficient for divergence detection.

### VPC Log Comparison

Simple byte comparison of the two VPC log files. If they differ at any point, divergence is detected. The VPC log format is:

```
<cycle> <s1_vpc_hex_40bit>
```

## Usage

```bash
source /mnt/milesan-meta/env.sh

# Basic usage
python do_reduce_onezero.py boom 34

# With hints (skip sanity check, narrow search range)
python do_reduce_onezero.py boom 34 --hint-left 5 --hint-right 15

# Custom timeout and output directory
python do_reduce_onezero.py boom 34 --timeout 300 --workdir /tmp/test_reduce
```

### Output

Artifacts are stored in `--workdir` (default: `/mnt/milesan-data/onezero_reduce/<design>_<seed>/`):

| File pattern | Description |
|---|---|
| `bb<N>_t0.elf` / `bb<N>_t1.elf` | Truncated ELFs for taint=0/1 at BB count N |
| `bb<N>_t0_vpc.txt` / `bb<N>_t1_vpc.txt` | VPC trace logs |
| `bb<N>_t0_sim.log` / `bb<N>_t1_sim.log` | Simulator stdout/stderr logs |
| `bbALL_t*.*` | Full (untruncated) program variants |
| `result.json` | Final result: `failing_bb_id`, `total_bbs`, timing, etc. |

## Testing with Seed 34

Seed 34 was identified as a diverging case. Key observations from initial testing:

- **Program descriptor:** memsize=505489, nmax_bbs=280, privs=True, actual BBs=22
- **ELF correctness:** Our generated ELFs are byte-identical to MileSan's `gen_fuzzerstate_elf_expectedvals()` output (verified via `xxd` diff)
- **VPC divergence point:** Cycle ~27,573 (line 13,174 of VPC log) -- very early, within ~5s of sim time
- **Sim termination:** The full program does NOT reach `tohost` within 10M cycles. The sim terminates via `Verilog $stop` (max-cycles assertion in `TestDriver.v:147`), not via `$finish` (tohost success at `TestDriver.v:158`). This means the program loops or traps before reaching the final block.
- **Implication for reduction:** Since programs may not terminate cleanly, `run_vpc_sim` accepts any non-empty VPC output as success. The timeout should be long enough to capture the divergence point (~120-300s should suffice since divergence appears very early).

## Open Issues / TODO

1. **Sim timeout tuning:** The default Chipyard `TIMEOUT_CYCLES=10000000` makes sims run ~27 min at observed speeds (~6K cycles/sec). Two sims in parallel take even longer. For binary search iterations where divergence appears early, a shorter Python timeout (120-300s) may suffice. Alternatively, pass `TIMEOUT_CYCLES=2000000` to reduce sim time.

2. **Program termination:** Seed 34's program never reaches tohost. This may be normal (the program traps into an exception loop or enters virtual memory that never returns to the final block). The `$fwrite`-based VPC logging captures data regardless of termination, so this doesn't block divergence detection.

3. **Future reduction phases:** Only "Find Failing BB" is implemented. Remaining phases to add incrementally:
   - Phase 2: Find failing instruction (within the identified BB)
   - Phase 3: Pillar search
   - Phase 4: NOPize
   - Phase 5-9: Reduce dead code, reduce taint, etc.

4. **Cluster execution:** The reduction binary search involves many simulation runs. For faster turnaround, run on the cluster with higher parallelism.

## Dependencies

- MileSan fuzzer infrastructure (`milesan-meta/fuzzer/`)
- Spike RISC-V ISA simulator (for `spike_resolution` during program generation)
- Chipyard VpcPrint BOOM simulator (`/mnt/chipyard/sims/verilator/simulator-chipyard.harness-VpcPrintMediumBoomV3Config`)
- RISC-V toolchain (for ELF generation via `riscv32-unknown-elf-*` tools; source `milesan-meta/env.sh`)
- RISC-V analysis tools (for ELF inspection via `riscv64-unknown-elf-*` tools; source `chipyard/env.sh`)

## Key Reference Files

| File | What it provides |
|---|---|
| `milesan/reduce.py` | Original 9-phase CellIFT reduction (our Phase 1 is based on `_find_failing_bb()` at line 638 and `gen_reduced_elf()` at line 268) |
| `milesan/fuzzfromdescriptor.py` | `gen_new_test_instance()` (line 25) and `gen_fuzzerstate_elf_expectedvals()` (line 33) -- canonical seeding and generation |
| `do_genmanyelfs.py` | Reference for FORCE_TAINT_VALUE patching pattern and ELF generation loop |
| `parallel_sim_boom/run_sims.py` | Reference for VpcPrint simulation invocation via make run-binary |
| `milesan/finalblock.py` | `finalblock()` generates the tohost exit sequence (writes 1 to `stopsigaddr`) |
| `milesan/gen_ctxt_final_block.py` | Helper functions for regenerating final block in correct privilege/layout context |
| `milesan/spikeresolution.py` | `spike_resolution()` -- modifies instruction objects in-place (branch opcodes, producer offsets) |
| `chipyard/variables.mk:334` | `TIMEOUT_CYCLES = 10000000` -- Chipyard's default max-cycles |
| `chipyard/.../TestDriver.v:147-158` | `$fatal` (max-cycles failure) vs `$finish` (tohost success) |
