# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# One-zero VPC-based reduction: find the failing basic block by binary search.
# Instead of CellIFT taint checking, the oracle is: do s1_vpc traces diverge
# between FORCE_TAINT_VALUE=0 and =1 variants of the same truncated program?

import os
import random
import subprocess
import time
from copy import deepcopy

import params.fuzzparams
import milesan.basicblock
import milesan.memview
import milesan.randomize.createcfinstr

from common.designcfgs import get_design_boot_addr
from common.spike import SPIKE_STARTADDR
from milesan.basicblock import gen_basicblocks
from milesan.cfinstructionclasses_t0 import JALInstruction_t0
from milesan.finalblock import finalblock
from milesan.gen_ctxt_final_block import get_last_real_layout, get_last_mpp, get_last_sum_mprv
from milesan.genelf import gen_elf_from_bbs
from milesan.privilegestate import PrivilegeStateEnum
from milesan.spikeresolution import spike_resolution
from params.fuzzparams import USE_MMU

CHIPYARD_DIR = "/mnt/chipyard"
CONFIG = "VpcPrintMediumBoomV3Config"
FULL_PROGRAM_SENTINEL = 999999


def _regen_final_block(priv_level, layout_id, fuzzerstate, bb_id, instr_id):
    """Regenerate the final block for a given privilege/layout context.

    Inlined from gen_ctxt_finalbock() in reduce.py to avoid pulling in the
    heavy CellIFT import chain from that module.
    """
    assert bb_id != -1

    if instr_id == -1:
        instr_id = len(fuzzerstate.instr_objs_seq[bb_id]) - 1
    instr_id = instr_id - 1
    if instr_id == -1:
        bb_id -= 1
        instr_id = len(fuzzerstate.instr_objs_seq[bb_id]) - 1

    fuzzerstate.privilegestate.privstate = priv_level
    fuzzerstate.effective_curr_layout = layout_id
    if priv_level == PrivilegeStateEnum.MACHINE:
        fuzzerstate.real_curr_layout = get_last_real_layout(fuzzerstate, bb_id, instr_id)
    else:
        fuzzerstate.real_curr_layout = fuzzerstate.effective_curr_layout

    fuzzerstate.privilegestate.curr_mstatus_mpp = get_last_mpp(fuzzerstate, bb_id, instr_id)
    sum_bit, mprv_bit = get_last_sum_mprv(fuzzerstate, bb_id, instr_id)
    fuzzerstate.status_sum_mprv = (sum_bit, mprv_bit)

    fuzzerstate.final_bb = finalblock(fuzzerstate, fuzzerstate.design_name)


def patch_force_taint_value(value):
    """Patch FORCE_TAINT_VALUE across all modules that read it at import time.

    Must be called BEFORE generate_program() so that gen_basicblocks() picks up
    the correct value. Mirrors the pattern in do_genmanyelfs.py.
    """
    params.fuzzparams.FORCE_TAINT_VALUE = value
    milesan.basicblock.FORCE_TAINT_VALUE = value
    milesan.memview.FORCE_TAINT_VALUE = value
    milesan.randomize.createcfinstr.FORCE_TAINT_VALUE = value


def generate_program(design_name, seed, authorize_privileges, memsize, nmax_bbs):
    """Generate a FuzzerState with basic blocks and spike resolution.

    Matches gen_fuzzerstate_elf_expectedvals() seeding and generation exactly:
    random.seed(seed) then FuzzerState + gen_basicblocks() + spike_resolution().
    The caller must set FORCE_TAINT_VALUE before calling this.
    """
    from milesan.fuzzerstate import FuzzerState

    random.seed(seed)
    boot_addr = get_design_boot_addr(design_name)
    fuzzerstate = FuzzerState(boot_addr, design_name, memsize, seed, nmax_bbs, authorize_privileges)
    gen_basicblocks(fuzzerstate)
    spike_resolution(fuzzerstate, check_pc_spike_again=False, return_interm=True)
    return fuzzerstate


def gen_truncated_elf(fuzzerstate, max_bb_id, elf_path):
    """Truncate the program to max_bb_id basic blocks and generate an ELF.

    Simplified version of gen_reduced_elf() Phase 1 from reduce.py:
    - deepcopy fuzzerstate
    - Restore states to before max_bb_id
    - Replace last CF instruction with JAL to final block
    - Regenerate final block for current privilege/layout context
    - Truncate instr_objs_seq and bb_start_addr_seq
    - Generate ELF via gen_elf_from_bbs()

    Returns the ELF path.
    """
    if max_bb_id == 0:
        return None  # Can't truncate to just the initial block meaningfully
    if max_bb_id >= len(fuzzerstate.instr_objs_seq):
        # No truncation needed — generate the full program
        return _gen_full_elf(fuzzerstate, elf_path)

    fs = deepcopy(fuzzerstate)

    # Restore register/memory state to before the truncation point
    fs.restore_states(max_bb_id)

    # Replace the last instruction of the last-kept BB with a JAL to the final block
    last_instr = fs.instr_objs_seq[max_bb_id][-1]
    new_jal = JALInstruction_t0(
        fs, "jal", 0,
        fs.final_bb_base_addr - last_instr.paddr + SPIKE_STARTADDR
    )
    new_jal.paddr = last_instr.paddr
    new_jal.priv_level = last_instr.priv_level
    if USE_MMU:
        new_jal.vaddr = last_instr.vaddr
        new_jal.va_layout = last_instr.va_layout

    # Regenerate the final block for the privilege/layout at the truncation point
    last_addr_layout = last_instr.va_layout
    last_addr_priv = last_instr.priv_level
    _regen_final_block(last_addr_priv, last_addr_layout, fs, max_bb_id, -1)

    # Apply the replacement and truncate
    fs.instr_objs_seq[max_bb_id][-1] = new_jal
    fs.instr_objs_seq = fs.instr_objs_seq[:max_bb_id + 1]
    fs.bb_start_addr_seq = fs.bb_start_addr_seq[:max_bb_id + 1]

    # Verify and reset
    fs.verify_program()
    fs.reset_states()

    # Generate the ELF — not for spike, using design base address
    tmp_dir = os.path.dirname(elf_path)
    fs.tmp_dir = tmp_dir
    actual_path = gen_elf_from_bbs(
        fs, False, "onezero_trunc",
        f"bb{max_bb_id}",
        fs.design_base_addr,
        for_spike=False
    )
    # Move the generated ELF to the desired path
    if actual_path != elf_path:
        os.rename(actual_path, elf_path)
    return elf_path


def _gen_full_elf(fuzzerstate, elf_path):
    """Generate an ELF for the full (untruncated) program."""
    fs = deepcopy(fuzzerstate)
    fs.verify_program()
    fs.reset_states()
    tmp_dir = os.path.dirname(elf_path)
    fs.tmp_dir = tmp_dir
    actual_path = gen_elf_from_bbs(
        fs, False, "onezero_full",
        "bbALL",
        fs.design_base_addr,
        for_spike=False
    )
    if actual_path != elf_path:
        os.rename(actual_path, elf_path)
    return elf_path


def run_vpc_sim(elf_path, vpc_log_path, sim_log_path, timeout):
    """Run one ELF on VpcPrint BOOM simulator via make run-binary.

    Returns True if a non-empty VPC log was produced, regardless of how the sim
    ended (clean exit, max-cycles $stop, watchdog hang, or timeout).  We only
    need VPC traces to compare — partial traces are fine for divergence detection.
    """
    cmd = [
        "make", "-C", f"{CHIPYARD_DIR}/sims/verilator",
        "run-binary",
        f"CONFIG={CONFIG}",
        f"BINARY={elf_path}",
        "VERILATOR_THREADS=1",
        "LOADMEM=1",
        f"EXTRA_SIM_FLAGS=+vpcfile={vpc_log_path}",
    ]

    with open(sim_log_path, "w") as log_f:
        proc = subprocess.Popen(cmd, stdout=log_f, stderr=subprocess.STDOUT)
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            print(f"  TIMEOUT after {timeout}s: {elf_path}")

    # Success if we got a non-empty VPC log
    try:
        return os.path.getsize(vpc_log_path) > 0
    except OSError:
        return False


def vpc_logs_diverge(vpc_log_0, vpc_log_1):
    """Compare two VPC log files. Returns True if they differ."""
    try:
        with open(vpc_log_0, "rb") as f0, open(vpc_log_1, "rb") as f1:
            return f0.read() != f1.read()
    except FileNotFoundError:
        # If either log is missing, we can't compare — treat as no divergence
        print(f"  WARNING: VPC log missing ({vpc_log_0} or {vpc_log_1})")
        return False


def is_mismatch_onezero(fs0, fs1, max_bb_id, timeout, workdir):
    """One-zero oracle: does truncating to max_bb_id BBs still show VPC divergence?

    Takes pre-generated (spike-resolved) fuzzerstates for taint=0 and taint=1,
    truncates both to max_bb_id BBs, runs on VpcPrint BOOM in parallel, and
    compares VPC logs.
    """
    bb_label = f"bb{max_bb_id}" if max_bb_id < FULL_PROGRAM_SENTINEL else "bbALL"

    elf_0 = os.path.join(workdir, f"{bb_label}_t0.elf")
    elf_1 = os.path.join(workdir, f"{bb_label}_t1.elf")
    vpc_0 = os.path.join(workdir, f"{bb_label}_t0_vpc.txt")
    vpc_1 = os.path.join(workdir, f"{bb_label}_t1_vpc.txt")
    log_0 = os.path.join(workdir, f"{bb_label}_t0_sim.log")
    log_1 = os.path.join(workdir, f"{bb_label}_t1_sim.log")

    # Generate truncated ELFs from pre-resolved fuzzerstates
    total_bbs_0 = len(fs0.instr_objs_seq)
    total_bbs_1 = len(fs1.instr_objs_seq)
    gen_truncated_elf(fs0, min(max_bb_id, total_bbs_0), elf_0)
    gen_truncated_elf(fs1, min(max_bb_id, total_bbs_1), elf_1)

    # Run both simulations in parallel
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_0 = pool.submit(run_vpc_sim, elf_0, vpc_0, log_0, timeout)
        fut_1 = pool.submit(run_vpc_sim, elf_1, vpc_1, log_1, timeout)
        ok_0 = fut_0.result()
        ok_1 = fut_1.result()

    if not ok_0 or not ok_1:
        print(f"  WARNING: Simulation failed for {bb_label} (ok_0={ok_0}, ok_1={ok_1})")
        return False

    return vpc_logs_diverge(vpc_0, vpc_1)


def find_failing_bb(design_name, seed, authorize_privileges, memsize, nmax_bbs,
                    timeout, workdir, hint_left=None, hint_right=None):
    """Binary search for the first BB whose inclusion causes VPC divergence.

    Same algorithm as _find_failing_bb() in reduce.py:
    - Invariant: is_mismatch(left_bound) = False, is_mismatch(right_bound) = True
    - Binary search until right_bound - left_bound == 1
    - Returns right_bound (the failing BB index)

    Generates both taint=0 and taint=1 programs (with spike resolution) once
    at the start, then truncates for each binary search iteration.
    """
    # Generate both programs once (with spike resolution)
    print("Generating taint=0 program (with spike resolution)...")
    patch_force_taint_value(0)
    fs0 = generate_program(design_name, seed, authorize_privileges, memsize, nmax_bbs)

    print("Generating taint=1 program (with spike resolution)...")
    patch_force_taint_value(1)
    fs1 = generate_program(design_name, seed, authorize_privileges, memsize, nmax_bbs)

    total_bbs = len(fs0.instr_objs_seq)
    print(f"Program has {total_bbs} basic blocks (t0={len(fs0.instr_objs_seq)}, t1={len(fs1.instr_objs_seq)}).")

    # Set bounds
    left_bound = hint_left if hint_left is not None else 0
    right_bound = hint_right if hint_right is not None else total_bbs

    # Sanity: verify the full program diverges
    if hint_right is None:
        print("Verifying full program diverges...")
        if not is_mismatch_onezero(fs0, fs1, FULL_PROGRAM_SENTINEL, timeout, workdir):
            print("ERROR: Full program does NOT show VPC divergence. Nothing to reduce.")
            return -1, total_bbs

    print(f"### SEARCHING FOR FAILING BB ###")
    print(f"Initial bounds: [{left_bound}, {right_bound})")

    iteration = 0
    while right_bound - left_bound > 1:
        candidate = (right_bound + left_bound) // 2
        iteration += 1
        t_start = time.time()

        print(f"  Iteration {iteration}: testing bb{candidate}/{total_bbs} ...", end=" ", flush=True)
        diverges = is_mismatch_onezero(fs0, fs1, candidate, timeout, workdir)
        elapsed = time.time() - t_start

        if diverges:
            print(f"DIVERGES  ({elapsed:.1f}s)  [{left_bound}, {candidate})")
            right_bound = candidate
        else:
            print(f"matches   ({elapsed:.1f}s)  [{candidate}, {right_bound})")
            left_bound = candidate

    assert left_bound + 1 == right_bound, f"Binary search invariant broken: {left_bound}, {right_bound}"
    print(f"\nFailing BB: {right_bound} (out of {total_bbs})")

    return right_bound, total_bbs
