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
from copy import copy, deepcopy

import params.fuzzparams
import milesan.basicblock
import milesan.memview
import milesan.randomize.createcfinstr

from common.designcfgs import get_design_boot_addr, get_design_march_flags, get_design_march_flags_nocompressed
from common.spike import SPIKE_STARTADDR
from milesan.basicblock import gen_basicblocks
from milesan.cfinstructionclasses import IntStoreInstruction, is_placeholder
from milesan.cfinstructionclasses_t0 import JALInstruction_t0
from milesan.contextreplay import SavedContext, gen_context_setter
from milesan.finalblock import finalblock
from milesan.gen_ctxt_final_block import get_last_real_layout, get_last_mpp, get_last_sum_mprv, get_priv_and_layout_after_instruction
from milesan.genelf import gen_elf_from_bbs
from milesan.mmu_utils import virt2phys
from milesan.privilegestate import PrivilegeStateEnum
from milesan.spikeresolution import gen_ctx_regdump_reqs, run_trace_regs_at_pc_locs, spike_resolution
from params.fuzzparams import TAINT_EN, USE_COMPRESSED, USE_MMU
from params.runparams import DO_ASSERT, NO_REMOVE_TMPFILES

CHIPYARD_DIR = "/mnt/chipyard"
CONFIG = "VpcPrintMediumBoomV3Config"
SIM_BIN = f"{CHIPYARD_DIR}/sims/verilator/simulator-chipyard.harness-{CONFIG}"
DRAMSIM_INI = f"{CHIPYARD_DIR}/generators/testchipip/src/main/resources/dramsim2_ini"
SIM_MAX_CYCLES = 10_000_000
FULL_PROGRAM_SENTINEL = 999999
_POLL_INTERVAL = 0.5  # seconds between VPC divergence checks in early-kill oracle


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


def gen_truncated_elf_instr(fuzzerstate, max_bb_id, max_instr_id, elf_path):
    """Truncate to max_bb_id BBs, then within that BB keep instructions
    0..max_instr_id (inclusive), replacing the instruction at index
    max_instr_id+1 with JAL to the final block.

    Mirrors reduce.py:314-337 (the max_instr_id_except_cf < len(BB)-2 branch).
    Returns the ELF path.
    """
    fs = deepcopy(fuzzerstate)
    fs.restore_states(max_bb_id)

    # The instruction at max_instr_id+1 is the one we're replacing with a JAL.
    # (Instructions 0..max_instr_id are kept; max_instr_id+1 becomes JAL-to-final.)
    last_instr = fs.instr_objs_seq[max_bb_id][max_instr_id + 1]
    new_jal = JALInstruction_t0(
        fs, "jal", 0,
        fs.final_bb_base_addr - last_instr.paddr + SPIKE_STARTADDR
    )
    new_jal.paddr = last_instr.paddr
    new_jal.priv_level = last_instr.priv_level
    if USE_MMU:
        new_jal.vaddr = last_instr.vaddr
        new_jal.va_layout = last_instr.va_layout

    # Use get_priv_and_layout_after_instruction — NOT last_instr.va_layout/priv_level
    # directly, because for a non-CF instruction those fields don't reflect the
    # "after execution" state. (Mirrors reduce.py:324.)
    last_addr_layout, last_addr_priv = get_priv_and_layout_after_instruction(last_instr)
    _regen_final_block(last_addr_priv, last_addr_layout, fs, max_bb_id, max_instr_id)

    # Overwrite and truncate (mirrors reduce.py:327-337)
    fs.instr_objs_seq[max_bb_id][max_instr_id + 1] = new_jal
    fs.instr_objs_seq = fs.instr_objs_seq[:max_bb_id + 1]
    fs.instr_objs_seq[max_bb_id] = fs.instr_objs_seq[max_bb_id][:max_instr_id + 2]
    fs.bb_start_addr_seq = fs.bb_start_addr_seq[:max_bb_id + 1]

    fs.verify_program()
    fs.reset_states()

    tmp_dir = os.path.dirname(elf_path)
    fs.tmp_dir = tmp_dir
    actual_path = gen_elf_from_bbs(
        fs, False, "onezero_trunc_instr",
        f"bb{max_bb_id}i{max_instr_id}",
        fs.design_base_addr,
        for_spike=False
    )
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


def _build_sim_cmd(elf_path, vpc_log_path):
    """Build the VpcPrint BOOM simulator command for a given ELF and VPC log output."""
    return [
        SIM_BIN,
        "+permissive",
        "+dramsim",
        f"+dramsim_ini_dir={DRAMSIM_INI}",
        f"+max-cycles={SIM_MAX_CYCLES}",
        f"+loadmem={elf_path}",
        f"+vpcfile={vpc_log_path}",
        "+permissive-off",
        elf_path,
    ]


def run_vpc_sim(elf_path, vpc_log_path, sim_log_path, timeout):
    """Run one ELF on VpcPrint BOOM simulator.

    Returns (vpc_ok, clean_exit) where:
      vpc_ok     — VPC log is non-empty (some VPC activity was recorded)
      clean_exit — simulator reached Verilog $finish naturally (tohost write
                   detected), i.e. was NOT killed by wall-clock timeout.
    Phase 1-3 oracles only need vpc_ok.  Phase 4 oracle additionally requires
    clean_exit — a timed-out NOPized program has broken control flow and must
    be rejected, mirroring milesan's try/except revert on spike crash.
    """
    cmd = _build_sim_cmd(elf_path, vpc_log_path)

    timed_out = False
    with open(sim_log_path, "w") as log_f:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                                stdout=log_f, stderr=subprocess.STDOUT)
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            print(f"  TIMEOUT after {timeout}s: {elf_path}")

    vpc_ok = False
    try:
        vpc_ok = os.path.getsize(vpc_log_path) > 0
    except OSError:
        pass

    clean_exit = (not timed_out)
    return vpc_ok, clean_exit


def vpc_logs_diverge(vpc_log_0, vpc_log_1):
    """Compare two VPC log files. Returns True if they differ."""
    try:
        with open(vpc_log_0, "rb") as f0, open(vpc_log_1, "rb") as f1:
            return f0.read() != f1.read()
    except FileNotFoundError:
        # If either log is missing, we can't compare — treat as no divergence
        print(f"  WARNING: VPC log missing ({vpc_log_0} or {vpc_log_1})")
        return False


def _vpc_files_diverge_partial(path0, path1, min_lines=2):
    """Compare VPC log files as they're being written. Only compare complete lines.

    Returns True on the first differing line. Requires at least min_lines complete
    lines from each file before comparing, to avoid spurious matches during startup.
    Handles partial final lines (incomplete stdio-buffered writes) by discarding them.
    """
    try:
        with open(path0, "r") as f0, open(path1, "r") as f1:
            lines0 = f0.readlines()
            lines1 = f1.readlines()
    except (FileNotFoundError, IOError):
        return False
    # Discard potentially incomplete last line (not yet flushed by stdio)
    if lines0 and not lines0[-1].endswith("\n"):
        lines0 = lines0[:-1]
    if lines1 and not lines1[-1].endswith("\n"):
        lines1 = lines1[:-1]
    n = min(len(lines0), len(lines1))
    if n < min_lines:
        return False
    for i in range(n):
        if lines0[i] != lines1[i]:
            return True
    return False


def _run_vpc_pair_early_kill(elf_0, vpc_0, log_0, elf_1, vpc_1, log_1, timeout):
    """Run two VPC sims in parallel, killing both as soon as divergence is detected.

    Polls VPC log files every _POLL_INTERVAL seconds. On early divergence both
    processes are killed immediately, returning in ~1-3s instead of the full
    ~57s completion time. Sims that do NOT diverge still run to completion (or
    timeout), so rejected NOPs pay the same cost as before.

    Returns (diverges, vpc_ok_0, vpc_ok_1, clean_0, clean_1) where:
      diverges  — True if VPC logs differ (early or after natural completion)
      clean_0/1 — True only when the sim reached $finish without timeout;
                  always False for the early-kill case (processes were killed)
    """
    cmd_0 = _build_sim_cmd(elf_0, vpc_0)
    cmd_1 = _build_sim_cmd(elf_1, vpc_1)

    with open(log_0, "w") as lf0, open(log_1, "w") as lf1:
        p0 = subprocess.Popen(cmd_0, stdin=subprocess.DEVNULL,
                              stdout=lf0, stderr=subprocess.STDOUT)
        p1 = subprocess.Popen(cmd_1, stdin=subprocess.DEVNULL,
                              stdout=lf1, stderr=subprocess.STDOUT)

        t_start = time.time()
        early_diverge = False
        timed_out = False

        while p0.poll() is None or p1.poll() is None:
            if time.time() - t_start >= timeout:
                timed_out = True
                break
            if _vpc_files_diverge_partial(vpc_0, vpc_1):
                early_diverge = True
                break
            time.sleep(_POLL_INTERVAL)

        # Kill any still-running process (early-kill or timeout)
        for p in (p0, p1):
            if p.poll() is None:
                p.kill()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=5)

    def _vpc_ok(path):
        try:
            return os.path.getsize(path) > 0
        except OSError:
            return False

    if early_diverge:
        # Processes were killed; clean_exit is meaningless — return diverges=True directly.
        # Safe because _spike_sanity_check already validated architectural control flow.
        return True, _vpc_ok(vpc_0), _vpc_ok(vpc_1), False, False

    clean_0 = (p0.returncode == 0) and not timed_out
    clean_1 = (p1.returncode == 0) and not timed_out
    ok_0, ok_1 = _vpc_ok(vpc_0), _vpc_ok(vpc_1)

    if timed_out:
        return False, ok_0, ok_1, False, False

    # Both finished naturally — do full log comparison
    if not ok_0 or not ok_1:
        return False, ok_0, ok_1, clean_0, clean_1
    return vpc_logs_diverge(vpc_0, vpc_1), ok_0, ok_1, clean_0, clean_1


def is_mismatch_onezero(fs0, fs1, max_bb_id, timeout, workdir,
                        max_instr_id=None, first_bb=None):
    """One-zero oracle: does the truncated program still show VPC divergence?

    max_instr_id=None, first_bb=None → BB-level truncation (Phase 1)
    max_instr_id=<int>, first_bb=None → instruction-level truncation (Phase 2)
    max_instr_id=<int>, first_bb=<int> → pillar-trimmed truncation (Phase 3);
        first_bb <= 1 falls through to Phase 2 (no context save needed)
    """
    if first_bb is not None and first_bb > 1:
        bb_label = f"bb{max_bb_id}i{max_instr_id}_from{first_bb}"
    elif max_instr_id is None:
        bb_label = f"bb{max_bb_id}" if max_bb_id < FULL_PROGRAM_SENTINEL else "bbALL"
    else:
        bb_label = f"bb{max_bb_id}i{max_instr_id}"

    elf_0 = os.path.join(workdir, f"{bb_label}_t0.elf")
    elf_1 = os.path.join(workdir, f"{bb_label}_t1.elf")
    vpc_0 = os.path.join(workdir, f"{bb_label}_t0_vpc.txt")
    vpc_1 = os.path.join(workdir, f"{bb_label}_t1_vpc.txt")
    log_0 = os.path.join(workdir, f"{bb_label}_t0_sim.log")
    log_1 = os.path.join(workdir, f"{bb_label}_t1_sim.log")

    # Generate truncated ELFs from pre-resolved fuzzerstates.
    # Phase 3 (first_bb > 1): run t0 and t1 in parallel — each call deepcopies the
    # fuzzerstate immediately (line 620) so there is no shared Python state. The
    # identifier_suffix "_t0"/"_t1" makes Spike dbgcmds file paths unique so the
    # two threads don't collide on the filesystem (spike.py:62 names files after the
    # identifier_str).
    from concurrent.futures import ThreadPoolExecutor
    if first_bb is not None and first_bb > 1:
        with ThreadPoolExecutor(max_workers=2) as pool:
            fut_0 = pool.submit(gen_truncated_elf_pillar,
                                fs0, max_bb_id, max_instr_id, first_bb, elf_0, "_t0")
            fut_1 = pool.submit(gen_truncated_elf_pillar,
                                fs1, max_bb_id, max_instr_id, first_bb, elf_1, "_t1")
            fut_0.result()
            fut_1.result()
    elif max_instr_id is None:
        total_bbs_0 = len(fs0.instr_objs_seq)
        total_bbs_1 = len(fs1.instr_objs_seq)
        gen_truncated_elf(fs0, min(max_bb_id, total_bbs_0), elf_0)
        gen_truncated_elf(fs1, min(max_bb_id, total_bbs_1), elf_1)
    else:
        gen_truncated_elf_instr(fs0, max_bb_id, max_instr_id, elf_0)
        gen_truncated_elf_instr(fs1, max_bb_id, max_instr_id, elf_1)

    # Spike pre-check for Phase 1/2 (Phase 3 path already runs Spike inside
    # gen_truncated_elf_pillar → _save_ctx_and_jump_to_pillar_specific_instr_oz).
    # Mirrors milesan gen_reduced_elf:run_trace_regs_at_pc_locs which raises on a
    # broken truncated program. Raises RuntimeError → propagates to the caller,
    # terminating the binary search and recording the seed as FAILED.
    # Run both simulations in parallel
    if first_bb is None:
        # Phase 1/2: run Spike pre-checks and BOOM sims all in parallel.
        # Two Spike checks + two BOOM sims use 2 cores concurrently throughout,
        # keeping each worker at full 2-CPU utilisation (same as the BOOM-only phase).
        march = (get_design_march_flags(fs0.design_name) if USE_COMPRESSED
                 else get_design_march_flags_nocompressed(fs0.design_name))
        with ThreadPoolExecutor(max_workers=2) as pool:
            spike_fut_0 = pool.submit(_spike_sanity_check, elf_0, march, bb_label + "_t0")
            spike_fut_1 = pool.submit(_spike_sanity_check, elf_1, march, bb_label + "_t1")
            spike_fut_0.result()  # raises RuntimeError on broken ELF
            spike_fut_1.result()
    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_0 = pool.submit(run_vpc_sim, elf_0, vpc_0, log_0, timeout)
        fut_1 = pool.submit(run_vpc_sim, elf_1, vpc_1, log_1, timeout)
        ok_0, _ = fut_0.result()
        ok_1, _ = fut_1.result()

    if not ok_0 or not ok_1:
        raise RuntimeError(
            f"BOOM simulation failed for {bb_label} (ok_0={ok_0}, ok_1={ok_1}); "
            "VPC log empty — ELF or simulator error."
        )

    return vpc_logs_diverge(vpc_0, vpc_1)


def _save_ctx_and_jump_to_pillar_specific_instr_oz(fuzzerstate, index_first_bb, index_first_instr,
                                                    identifier_suffix=""):
    """Snapshot architectural state at the entry of BB index_first_bb via Spike,
    generate a context-setter BB that restores that state, and redirect the initial
    block's tail jump to the context setter.

    Modifies fuzzerstate in place. Returns (fuzzerstate, tgt_addr_layout, tgt_addr_priv).

    identifier_suffix: appended to instance_to_str() when naming Spike temp files.
    Pass "_t0" / "_t1" when calling concurrently for the two taint variants so their
    Spike dbgcmds files don't collide (spike.py names them after the identifier_str).

    Inlined from _save_ctx_and_jump_to_pillar_specific_instr() in milesan/reduce.py:71-262.
    The TAINT_EN/DO_ASSERT assertion block is replaced with zero-initialized taint values
    (safe for the VPC oracle which only compares fetch-trace files).
    """
    print(f"  Saving context at BB {index_first_bb} instr {index_first_instr} via Spike...")

    # Generate a Spike ELF of the (already end-truncated) program
    spikereduce_elfpath = gen_elf_from_bbs(
        fuzzerstate, False, "spikereduce_savectx_oz",
        f"{fuzzerstate.instance_to_str()}_{index_first_bb}_{index_first_instr}",
        SPIKE_STARTADDR, for_spike=True
    )

    target_instr = fuzzerstate.instr_objs_seq[index_first_bb][index_first_instr]
    tgt_pc = target_instr.vaddr if USE_MMU else target_instr.paddr
    assert tgt_pc is not None
    tgt_addr_layout = target_instr.va_layout
    tgt_addr_priv = target_instr.priv_level
    assert tgt_addr_priv is not None

    final_instr = fuzzerstate.instr_objs_seq[-1][-1]
    final_addr = final_instr.vaddr if USE_MMU else final_instr.paddr

    march_flags = (get_design_march_flags(fuzzerstate.design_name) if USE_COMPRESSED
                   else get_design_march_flags_nocompressed(fuzzerstate.design_name))

    ctx_regdump_reqs, storenumbytes, insts = gen_ctx_regdump_reqs(
        fuzzerstate, index_first_bb, index_first_instr, tgt_pc
    )
    dumpedvals = run_trace_regs_at_pc_locs(
        fuzzerstate.instance_to_str() + identifier_suffix, spikereduce_elfpath, march_flags,
        SPIKE_STARTADDR, ctx_regdump_reqs, False, final_addr,
        fuzzerstate.num_pickable_floating_regs if fuzzerstate.design_has_fpu else 0,
        fuzzerstate.design_has_fpud
    )
    # Taint values zeroed — the VPC oracle does not check taint propagation.
    dumpedvals_t0 = [0] * len(dumpedvals)
    del ctx_regdump_reqs

    if not NO_REMOVE_TMPFILES:
        os.remove(spikereduce_elfpath)

    # Parse the dump into SavedContext fields (mirrors reduce.py:118-247)
    NUM_CSRS = 13 + int(not fuzzerstate.is_design_64bit) + 2 * int(USE_MMU)
    num_stores_found = (len(dumpedvals) - NUM_CSRS
                        - fuzzerstate.num_pickable_floating_regs
                        - fuzzerstate.num_pickable_regs) // 2

    saved_stores = {}
    saved_stores_t0 = {}
    curr_id = 0
    curr_storebyte = 0
    for _ in range(num_stores_found):
        assert isinstance(insts[curr_id], IntStoreInstruction)
        for byte_id in range(storenumbytes[curr_storebyte]):
            addr = dumpedvals[curr_id] + byte_id + insts[curr_id].imm
            if insts[curr_id].priv_level == PrivilegeStateEnum.MACHINE:
                addr = addr - SPIKE_STARTADDR
            else:
                addr = virt2phys(addr, insts[curr_id].priv_level,
                                 insts[curr_id].va_layout, fuzzerstate)
            assert 0 < addr < fuzzerstate.memsize, f"Store addr {hex(addr)} out of bounds"
            saved_stores[addr] = (dumpedvals[curr_id + 1] >> (8 * byte_id)) & 0xFF
            saved_stores_t0[addr] = 0
        curr_storebyte += 1
        curr_id += 2

    def _next():
        nonlocal curr_id
        val = dumpedvals[curr_id]; curr_id += 1; return val

    saved_fcsr     = _next()
    saved_mepc     = _next()
    saved_sepc     = _next()
    saved_mcause   = _next()
    saved_scause   = _next()
    saved_mscratch = _next()
    saved_sscratch = _next()
    saved_mtvec    = _next()
    saved_stvec    = _next()
    saved_medeleg  = _next()
    saved_mstatus  = _next()
    saved_minstret = _next()
    if USE_MMU:
        saved_satp       = _next()
        saved_rprod_mask = _next()
    else:
        saved_satp = saved_rprod_mask = None
    saved_minstreth = _next() if not fuzzerstate.is_design_64bit else None

    priv_char = _next()
    if priv_char == 'M':
        saved_privilege = PrivilegeStateEnum.MACHINE
    elif priv_char == 'S':
        saved_privilege = PrivilegeStateEnum.SUPERVISOR
    elif priv_char == 'U':
        saved_privilege = PrivilegeStateEnum.USER
    else:
        raise ValueError(f"Unknown privilege level char: {priv_char!r}")

    curr_id += fuzzerstate.num_pickable_floating_regs  # FPU not implemented
    saved_regvals = dumpedvals[curr_id:curr_id + fuzzerstate.num_pickable_regs]
    saved_regvals_t0 = [0] * fuzzerstate.num_pickable_regs  # taint zeroed

    saved_context = SavedContext(
        saved_fcsr, saved_mepc, saved_sepc, saved_mcause, saved_scause,
        saved_mscratch, saved_sscratch, saved_mtvec, saved_stvec, saved_medeleg,
        saved_mstatus, saved_minstret, saved_minstreth, saved_satp, saved_privilege,
        saved_stores, saved_stores_t0,
        [],         # freg_vals (FPU not implemented)
        None,       # freg_vals_t0
        saved_regvals, saved_regvals_t0,
        saved_rprod_mask
    )

    # Wire context-setter BB and redirect the initial block's tail jump into it
    gen_context_setter(
        fuzzerstate, saved_context,
        fuzzerstate.bb_start_addr_seq[index_first_bb] + index_first_instr * 4,
        tgt_addr_layout, tgt_addr_priv
    )

    old_jump = fuzzerstate.instr_objs_seq[fuzzerstate.last_bb_id_before_ctx_saver][-1]
    n_instrs_in_initial = len(fuzzerstate.instr_objs_seq[fuzzerstate.last_bb_id_before_ctx_saver])
    new_jump = JALInstruction_t0(
        fuzzerstate, "jal", 0,
        fuzzerstate.ctxsv_bb_base_addr - 4 * (n_instrs_in_initial - 1)
    )
    new_jump.paddr = old_jump.paddr
    new_jump.priv_level = old_jump.priv_level
    if USE_MMU:
        new_jump.vaddr = old_jump.vaddr
        new_jump.va_layout = old_jump.va_layout
    fuzzerstate.instr_objs_seq[fuzzerstate.last_bb_id_before_ctx_saver][-1] = new_jump

    return fuzzerstate, tgt_addr_layout, tgt_addr_priv


def gen_truncated_elf_pillar(fuzzerstate, max_bb_id, max_instr_id, first_bb, elf_path,
                             identifier_suffix=""):
    """Generate a pillar-trimmed ELF: keep BBs [first_bb..max_bb_id] with a context
    setter that restores the architectural state those removed BBs would have produced,
    and truncate within max_bb_id at instruction max_instr_id (Phase 2 style).

    When first_bb <= 1 falls through to gen_truncated_elf_instr (no context save needed).

    Mirrors gen_reduced_elf() in reduce.py with index_first_bb_to_consider > 1.
    """
    fs = deepcopy(fuzzerstate)
    fs.restore_states(max_bb_id)

    # End-truncation: replace instruction max_instr_id+1 with JAL to final block
    last_instr = fs.instr_objs_seq[max_bb_id][max_instr_id + 1]
    new_jal = JALInstruction_t0(
        fs, "jal", 0,
        fs.final_bb_base_addr - last_instr.paddr + SPIKE_STARTADDR
    )
    new_jal.paddr = last_instr.paddr
    new_jal.priv_level = last_instr.priv_level
    if USE_MMU:
        new_jal.vaddr = last_instr.vaddr
        new_jal.va_layout = last_instr.va_layout

    last_addr_layout, last_addr_priv = get_priv_and_layout_after_instruction(last_instr)
    _regen_final_block(last_addr_priv, last_addr_layout, fs, max_bb_id, max_instr_id)

    fs.instr_objs_seq[max_bb_id][max_instr_id + 1] = new_jal
    fs.instr_objs_seq = fs.instr_objs_seq[:max_bb_id + 1]
    fs.instr_objs_seq[max_bb_id] = fs.instr_objs_seq[max_bb_id][:max_instr_id + 2]
    fs.bb_start_addr_seq = fs.bb_start_addr_seq[:max_bb_id + 1]

    # Context save (only when trimming from the front, i.e. first_bb > 1)
    if first_bb > 1:
        fs, _, _ = _save_ctx_and_jump_to_pillar_specific_instr_oz(
            fs, first_bb, 0, identifier_suffix=identifier_suffix)

    # Front-trimming: delete BBs [1, first_bb) from instr_objs_seq and bb_start_addr_seq
    if first_bb > 1:
        del fs.instr_objs_seq[1:first_bb]
        del fs.bb_start_addr_seq[1:first_bb]

    # verify_program() can raise AssertionError when the context-setter changes a
    # register that a CSR instruction reads, causing spike vs Python sim to disagree.
    # Propagate the error — a broken pillar ELF should fail the oracle call, not
    # silently continue (mirrors reduce.py:426 which lets the exception propagate).
    try:
        fs.verify_program()
    except AssertionError as e:
        raise RuntimeError(
            f"verify_program failed for pillar ELF (context-setter/CSR mismatch): {e}"
        ) from e
    fs.reset_states()

    label = f"bb{max_bb_id}i{max_instr_id}_from{first_bb}"
    tmp_dir = os.path.dirname(elf_path)
    fs.tmp_dir = tmp_dir
    actual_path = gen_elf_from_bbs(
        fs, False, "onezero_pillar", label,
        fs.design_base_addr, for_spike=False
    )
    if actual_path != elf_path:
        os.rename(actual_path, elf_path)
    return elf_path


def find_failing_instr(fs0, fs1, failing_bb_id, timeout, workdir,
                       hint_left=None, hint_right=None):
    """Binary search within failing_bb_id for the specific failing instruction.

    Mirrors _find_failing_instr_in_bb() in reduce.py:763-821.

    Returns:
        None  if the issue actually comes from the previous BB's CF instruction
              (the check is_mismatch(..., max_instr_id=0) fires True immediately)
        int   the failing instruction index within failing_bb_id otherwise

    Invariant: left=no mismatch, right=mismatch. Returns right_bound.
    """
    bb = fs0.instr_objs_seq[failing_bb_id]

    # Edge case: single-instruction BB has nothing to search within
    if len(bb) == 1:
        return None

    left_bound = hint_left if hint_left is not None else 0
    # -1 because last instruction is the CF terminator (handled by Phase 1)
    right_bound = hint_right if hint_right is not None else len(bb) - 1

    print("### SEARCHING FOR FAILING INSTRUCTION ###")

    # Short-circuit: if truncating to just instr_id=0 still diverges, the real
    # cause is the CF instruction of the *previous* BB, not anything in this BB.
    if right_bound == 0 or is_mismatch_onezero(fs0, fs1, failing_bb_id, timeout, workdir, max_instr_id=0):
        print("Issue comes from the previous BB's CF instruction.")
        return None

    while right_bound - left_bound > 1:
        candidate = (right_bound + left_bound) // 2
        if is_mismatch_onezero(fs0, fs1, failing_bb_id, timeout, workdir, max_instr_id=candidate):
            print(f"  instr {candidate}: DIVERGES  -> right={candidate}")
            right_bound = candidate
        else:
            print(f"  instr {candidate}: matches   -> left={candidate}")
            left_bound = candidate

    assert left_bound + 1 == right_bound
    print(f"\nFailing instruction: {right_bound} in BB {failing_bb_id}")
    return right_bound


def find_pillar_bb(fs0, fs1, failing_bb_id, failing_instr_id, timeout, workdir,
                   fault_from_prev_bb=False, hint_left=None, hint_right=None):
    """Binary search for the pillar (primer) BB — the first BB that must be present
    for the VPC-divergence leak to occur.

    Mirrors _find_pillar_bb() in reduce.py:694-759.

    'candidate' = first_bb_to_consider = index of the first BB to keep. BBs before
    candidate are replaced by a context-setter that restores the architectural state.

    Invariant (per reduce.py:730-745 code, NOT its stale comment):
      left_bound  = largest candidate with mismatch=True  (primer present → leaks)
      right_bound = smallest candidate with mismatch=False (primer removed → no leak)

    Returns right_bound - 1 = the pillar BB index (= left_bound at convergence).
    """
    assert 0 < failing_bb_id < len(fs0.instr_objs_seq), \
        f"failing_bb_id={failing_bb_id} out of range [1, {len(fs0.instr_objs_seq)})"
    assert failing_instr_id is not None, "find_pillar_bb requires failing_instr_id"

    left_bound  = hint_left  if hint_left  is not None else 0
    right_bound = hint_right if hint_right is not None else failing_bb_id + 1

    # Leaker invariance: instr index to check whether leaker shifted (mirrors reduce.py:685-688).
    # fault_from_prev_bb: the actual leaker is the last real instr of failing_bb; check second-to-last.
    if fault_from_prev_bb:
        _leaker_check_instr = len(fs0.instr_objs_seq[failing_bb_id]) - 2
    else:
        _leaker_check_instr = failing_instr_id - 1

    print("### SEARCHING FOR PILLAR BB ###")
    print(f"Initial bounds: [{left_bound}, {right_bound})")

    iteration = 0
    while right_bound - left_bound > 1:
        candidate = (right_bound + left_bound) // 2
        iteration += 1
        t_start = time.time()
        print(f"  Iteration {iteration}: testing first_bb={candidate} ...", end=" ", flush=True)

        diverges = is_mismatch_onezero(
            fs0, fs1, failing_bb_id, timeout, workdir,
            max_instr_id=failing_instr_id, first_bb=candidate
        )
        elapsed = time.time() - t_start

        if diverges:
            # Leaker invariance check: if removing the last failing instr *still* diverges,
            # the leaker shifted to an earlier instruction → reject this candidate (mirrors
            # CHECK_LEAKER_INVARIANCE / _leaker_changed() in reduce.py:731-736).
            if _leaker_check_instr >= 0 and is_mismatch_onezero(
                    fs0, fs1, failing_bb_id, timeout, workdir,
                    max_instr_id=_leaker_check_instr, first_bb=candidate):
                print(f"DIVERGES  ({elapsed:.1f}s)  leaker shifted → right={candidate}")
                right_bound = candidate
                continue
            print(f"DIVERGES  ({elapsed:.1f}s)  left={candidate}")
            left_bound = candidate
        else:
            print(f"matches   ({elapsed:.1f}s)  right={candidate}")
            right_bound = candidate

    assert left_bound + 1 == right_bound
    pillar_bb = right_bound - 1
    print(f"\nPillar BB: {pillar_bb} (first_bb_to_consider={left_bound} still leaks; "
          f"first_bb_to_consider={right_bound} does not)")
    return pillar_bb


def find_failing_bb(design_name, seed, authorize_privileges, memsize, nmax_bbs,
                    timeout, workdir, hint_left=None, hint_right=None):
    """Binary search for the first BB whose inclusion causes VPC divergence.

    Same algorithm as _find_failing_bb() in reduce.py:
    - Invariant: is_mismatch(left_bound) = False, is_mismatch(right_bound) = True
    - Binary search until right_bound - left_bound == 1
    - Returns (right_bound, total_bbs, fs0, fs1)

    Returns fs0/fs1 so the caller can pass them directly to find_failing_instr
    without re-generating the programs.

    On failure: returns (-1, total_bbs, None, None).
    """
    # Generate both programs once (with spike resolution)
    print("Generating taint=0 program (with spike resolution)...")
    patch_force_taint_value(0)
    fs0 = generate_program(design_name, seed, authorize_privileges, memsize, nmax_bbs)

    print("Generating taint=1 program (with spike resolution)...")
    patch_force_taint_value(1)
    fs1 = generate_program(design_name, seed, authorize_privileges, memsize, nmax_bbs)

    total_bbs = len(fs0.instr_objs_seq)
    assert total_bbs > 0, f"seed {seed}: program has 0 BBs"
    print(f"Program has {total_bbs} basic blocks (t0={len(fs0.instr_objs_seq)}, t1={len(fs1.instr_objs_seq)}).")

    # Set bounds
    left_bound = hint_left if hint_left is not None else 0
    right_bound = hint_right if hint_right is not None else total_bbs

    # Sanity: verify the full program diverges
    if hint_right is None:
        print("Verifying full program diverges...")
        if not is_mismatch_onezero(fs0, fs1, FULL_PROGRAM_SENTINEL, timeout, workdir):
            print("ERROR: Full program does NOT show VPC divergence. Nothing to reduce.")
            return -1, total_bbs, None, None

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

    return right_bound, total_bbs, fs0, fs1


# ===========================================================================
# Phase 4 — Dead-code NOPization (gadget minimization)
# ===========================================================================

# Canonical RISC-V NOP bytecodes
_NOP_BYTECODE_32 = 0x00000013  # addi x0, x0, 0
_NOP_BYTECODE_16 = 0x0001      # c.nop (= c.addi x0, 0)


class _NopSubstitute:
    """Drop-in replacement for an instruction object during Phase-4 NOPization.

    Preserves paddr / vaddr / priv_level / va_layout / iscompressed of the
    original so that gen_elf_from_bbs() lays it out at the correct address.
    Emits a canonical RISC-V NOP (addi x0,x0,0 or c.nop).  execute() is a no-op
    (we never run verify_program() on a Phase-4 fuzzerstate).
    """
    __slots__ = ("fuzzerstate", "paddr", "vaddr", "priv_level", "va_layout",
                 "iscompressed", "instr_str", "isdead", "iscontext",
                 "_orig_paddr", "_orig_mnemonic")

    def __init__(self, orig):
        self.fuzzerstate = getattr(orig, "fuzzerstate", None)
        self.paddr       = orig.paddr
        self.vaddr       = getattr(orig, "vaddr", None)
        self.priv_level  = orig.priv_level
        self.va_layout   = getattr(orig, "va_layout", None)
        self.iscompressed = getattr(orig, "iscompressed", False)
        self.instr_str    = "c.nop" if self.iscompressed else "addi"
        self.isdead       = True
        self.iscontext    = False
        # Kept for diagnostics
        self._orig_paddr    = orig.paddr
        self._orig_mnemonic = getattr(orig, "instr_str", type(orig).__name__)

    def gen_bytecode_int(self, is_spike_resolution: bool):
        return _NOP_BYTECODE_16 if self.iscompressed else _NOP_BYTECODE_32

    def execute(self, is_spike_resolution: bool = True):
        return  # addi x0,x0,0 has no architectural effect

    def get_str(self, is_spike_resolution: bool = True, color_taint: bool = False):
        priv = self.priv_level.name[0] if self.priv_level is not None else "?"
        return (f"({priv}/{self.va_layout}): {hex(self.paddr) if self.paddr is not None else '?'}"
                f": NOP  [was {self._orig_mnemonic}]")


def _can_nopize(instr) -> bool:
    """Milesan-exact safety check: skip only placeholders and already-NOPs."""
    if isinstance(instr, _NopSubstitute):
        return False
    if is_placeholder(instr):
        return False
    return True


def _build_phase4_baseline(fuzzerstate, max_bb_id, max_instr_id, first_bb):
    """Build the Phase-3-equivalent trimmed fuzzerstate for Phase 4 NOPization.

    Same prefix as gen_truncated_elf_pillar() up to (but NOT including) verify_program.
    We skip verify_program because NOP substitutions break architectural execution
    equivalence with the original snapshotted state (registers/CSRs would diverge
    from what simulate_execution expects).

    Returns the trimmed fuzzerstate ready for in-place NOP mutations.
    """
    fs = deepcopy(fuzzerstate)
    fs.restore_states(max_bb_id)

    last_instr = fs.instr_objs_seq[max_bb_id][max_instr_id + 1]
    new_jal = JALInstruction_t0(
        fs, "jal", 0,
        fs.final_bb_base_addr - last_instr.paddr + SPIKE_STARTADDR
    )
    new_jal.paddr = last_instr.paddr
    new_jal.priv_level = last_instr.priv_level
    if USE_MMU:
        new_jal.vaddr = last_instr.vaddr
        new_jal.va_layout = last_instr.va_layout

    last_addr_layout, last_addr_priv = get_priv_and_layout_after_instruction(last_instr)
    _regen_final_block(last_addr_priv, last_addr_layout, fs, max_bb_id, max_instr_id)

    fs.instr_objs_seq[max_bb_id][max_instr_id + 1] = new_jal
    fs.instr_objs_seq = fs.instr_objs_seq[:max_bb_id + 1]
    fs.instr_objs_seq[max_bb_id] = fs.instr_objs_seq[max_bb_id][:max_instr_id + 2]
    fs.bb_start_addr_seq = fs.bb_start_addr_seq[:max_bb_id + 1]

    if first_bb > 1:
        fs, _, _ = _save_ctx_and_jump_to_pillar_specific_instr_oz(fs, first_bb, 0)
        del fs.instr_objs_seq[1:first_bb]
        del fs.bb_start_addr_seq[1:first_bb]

    fs.reset_states()
    return fs


def _gen_phase4_elf(fs, label, elf_path):
    """Generate an ELF from a Phase-4 (possibly NOP-substituted) fuzzerstate.

    Skips verify_program() — callers must have built `fs` via _build_phase4_baseline()
    and mutated only via _NopSubstitute swaps.
    """
    fs.reset_states()
    tmp_dir = os.path.dirname(elf_path)
    fs.tmp_dir = tmp_dir
    actual_path = gen_elf_from_bbs(
        fs, False, "onezero_nopize", label,
        fs.design_base_addr, for_spike=False
    )
    if actual_path != elf_path:
        if os.path.exists(elf_path):
            os.remove(elf_path)
        os.rename(actual_path, elf_path)
    return elf_path


_SPIKE_SANITY_TIMEOUT = 10  # seconds; Spike runs at ~100M inst/s so 10s is generous


def _spike_sanity_check(elf_path, march, label):
    """Fast Spike validation: can the ELF reach tohost without crashing?

    Mirrors the Spike pre-check inside milesan gen_reduced_elf (reduce.py:374-399).
    Raises RuntimeError on spike crash or timeout so callers can treat it as a
    revert signal — same role as the bare `except:` in milesan reduce.py:941-944.
    """
    try:
        r = subprocess.run(
            ["spike", f"--isa={march}", f"--pc={hex(SPIKE_STARTADDR)}", elf_path],
            capture_output=True, timeout=_SPIKE_SANITY_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"spike sanity timeout: {label}")
    if r.returncode != 0:
        raise RuntimeError(f"spike sanity rc={r.returncode}: {label}")


def _phase4_oracle(fs0_phase4, fs1_phase4, label, workdir, timeout):
    """Run the VPC-divergence oracle on a Phase-4 fuzzerstate pair.

    Uses _run_vpc_pair_early_kill so accepted NOPs (diverge quickly) return in
    ~1-3s rather than waiting for full BOOM completion (~57s).
    """
    elf_0 = os.path.join(workdir, f"{label}_t0.elf")
    elf_1 = os.path.join(workdir, f"{label}_t1.elf")
    vpc_0 = os.path.join(workdir, f"{label}_t0_vpc.txt")
    vpc_1 = os.path.join(workdir, f"{label}_t1_vpc.txt")
    log_0 = os.path.join(workdir, f"{label}_t0_sim.log")
    log_1 = os.path.join(workdir, f"{label}_t1_sim.log")

    _gen_phase4_elf(fs0_phase4, label + "_t0", elf_0)
    _gen_phase4_elf(fs1_phase4, label + "_t1", elf_1)

    # Spike pre-check: fast-fail broken programs before invoking BOOM.
    # Mirrors milesan gen_reduced_elf's run_trace_regs_at_pc_locs (reduce.py:397) which
    # throws on spike crash; the except: branch in reduce.py:941 reverts the NOP.
    march = (get_design_march_flags(fs0_phase4.design_name) if USE_COMPRESSED
             else get_design_march_flags_nocompressed(fs0_phase4.design_name))
    try:
        _spike_sanity_check(elf_0, march, label + "_t0")
        _spike_sanity_check(elf_1, march, label + "_t1")
    except Exception:
        return False  # NOP broke architectural control flow — reject immediately

    diverges, ok0, ok1, clean0, clean1 = _run_vpc_pair_early_kill(
        elf_0, vpc_0, log_0, elf_1, vpc_1, log_1, timeout
    )

    if not ok0 or not ok1:
        return False
    if diverges:
        # Early-kill or natural completion: any detected divergence is genuine
        # (Spike pre-check already validated architectural control flow above).
        return True
    if not clean0 or not clean1:
        # Both sims ran without divergence but timed out — microarch hang, reject.
        return False
    return False  # Clean exit, identical VPC logs — NOP removed needed code


def _fine_grain_nopize_bb(base_fs0, base_fs1, bb_idx, instr_range,
                           leaker_paddr, oracle_fn, n_nops, n_attempts, label_prefix):
    """Fine-grain NOPize: try each instruction in instr_range individually.

    Mirrors milesan reduce.py sections (A), (C), and (B) fine-grain fallback.
    Returns updated (n_nops, n_attempts).
    """
    for instr_idx in instr_range:
        orig0 = base_fs0.instr_objs_seq[bb_idx][instr_idx]
        orig1 = base_fs1.instr_objs_seq[bb_idx][instr_idx]

        if orig0.paddr == leaker_paddr:
            continue
        if not _can_nopize(orig0):
            continue

        n_attempts += 1
        label = f"{label_prefix}_bb{bb_idx}i{instr_idx}_a{n_attempts}"
        t_a = time.time()

        base_fs0.instr_objs_seq[bb_idx][instr_idx] = _NopSubstitute(orig0)
        base_fs1.instr_objs_seq[bb_idx][instr_idx] = _NopSubstitute(orig1)

        try:
            diverges = oracle_fn(base_fs0, base_fs1, label)
        except Exception as e:
            diverges = False
            print(f"  [{n_attempts:3d}]  bb{bb_idx:3d}.{instr_idx:3d}  "
                  f"spike/sim error, revert: {e}")
        dt = time.time() - t_a

        if diverges:
            n_nops += 1
            print(f"  [{n_attempts:3d}]  bb{bb_idx:3d}.{instr_idx:3d}  "
                  f"NOP ({dt:.1f}s)  [was {getattr(orig0, 'instr_str', '?')}]")
        else:
            base_fs0.instr_objs_seq[bb_idx][instr_idx] = orig0
            base_fs1.instr_objs_seq[bb_idx][instr_idx] = orig1
            print(f"  [{n_attempts:3d}]  bb{bb_idx:3d}.{instr_idx:3d}  "
                  f"keep ({dt:.1f}s)  [{getattr(orig0, 'instr_str', '?')}]")
    return n_nops, n_attempts


def nopize_gadget(fs0, fs1, pillar_bb, failing_bb, failing_instr, fault_from_prev_bb,
                  timeout, workdir):
    """Phase 4 — greedy single-pass NOPization of the leaker↔pillar span.

    Exact port of milesan _turn_sandwich_instructions_into_nops, adapted to the
    VPC-divergence oracle. Sections A/B/C with coarse-grain + fine-grain fallback.

    Returns (n_nops_added, gadget_size, cap_hit, minimal_t0_path, minimal_t1_path,
             sanity_check_ok, reason).
    `gadget_size` = number of non-NOP non-context instructions in the span.
    """
    print()
    print("### PHASE 4: NOPize (gadget minimization) ###")
    t_start = time.time()

    # Oracle end-truncation point (same as Phase 3)
    if fault_from_prev_bb:
        p3_bb, p3_instr = failing_bb, 0
        # Leaker is the CF terminator of the previous BB (last instr of that BB)
        leaker_paddr = fs0.instr_objs_seq[failing_bb - 1][-1].paddr
    else:
        p3_bb, p3_instr = failing_bb, failing_instr
        leaker_paddr = fs0.instr_objs_seq[failing_bb][failing_instr].paddr

    print(f"  Building Phase-4 baselines (trimmed: bbs {pillar_bb}..{failing_bb})")
    base_fs0 = _build_phase4_baseline(fs0, p3_bb, p3_instr, pillar_bb)
    base_fs1 = _build_phase4_baseline(fs1, p3_bb, p3_instr, pillar_bb)

    # Sanity: templates must diverge before any NOP is applied
    print(f"  Verifying pre-NOP baseline diverges...", end=" ", flush=True)
    if not _phase4_oracle(base_fs0, base_fs1, "phase4_baseline", workdir, timeout):
        elapsed = time.time() - t_start
        print(f"no divergence — aborting Phase 4 ({elapsed:.1f}s)")
        return 0, None, False, None, None, False, "baseline_does_not_diverge"
    print("OK")

    # Mirrors milesan reduce.py:911-916: verify leaker minimality before NOPization.
    if DO_ASSERT and not fault_from_prev_bb and failing_instr > 0:
        sb_fs0 = _build_phase4_baseline(fs0, failing_bb, failing_instr - 1, pillar_bb)
        sb_fs1 = _build_phase4_baseline(fs1, failing_bb, failing_instr - 1, pillar_bb)
        assert not _phase4_oracle(sb_fs0, sb_fs1, "assert_pre_stepback", workdir, timeout), \
            f"DO_ASSERT: step-back by 1 instr should eliminate divergence (failing_instr={failing_instr})"

    # Trimmed index mapping after _build_phase4_baseline:
    #   index 0          = initial block (untouched)
    #   index 1          = pillar BB
    #   index 2..N-2     = intermediate BBs
    #   index N-1 (last) = failing BB
    trimmed_failing_idx = len(base_fs0.instr_objs_seq) - 1
    trimmed_pillar_idx  = 1  # always 1; _build_phase4_baseline del[1:first_bb]

    def oracle_fn(fs0, fs1, label):
        return _phase4_oracle(fs0, fs1, label, workdir, timeout)

    n_nops = 0
    n_attempts = 0
    total_span = sum(len(bb) for bb in base_fs0.instr_objs_seq[trimmed_pillar_idx:])
    print(f"  Span: pillar(bb_t{trimmed_pillar_idx}) .. failing(bb_t{trimmed_failing_idx}), "
          f"~{total_span} instrs across {trimmed_failing_idx} BBs")

    # ----------------------------------------------------------------
    # (A) Pillar BB — fine-grain
    # Mirrors milesan reduce.py section (A)
    # ----------------------------------------------------------------
    pillar_bb_len = len(base_fs0.instr_objs_seq[trimmed_pillar_idx])
    print(f"  (A) Pillar BB fine-grain: {pillar_bb_len - 1} candidates")
    n_nops, n_attempts = _fine_grain_nopize_bb(
        base_fs0, base_fs1, trimmed_pillar_idx,
        range(pillar_bb_len - 1),   # skip last (CF exit)
        leaker_paddr, oracle_fn, n_nops, n_attempts, "p4A",
    )

    # ----------------------------------------------------------------
    # (B) Intermediate BBs — coarse-grain first, fine-grain fallback
    # Mirrors milesan reduce.py section (B)
    # ----------------------------------------------------------------
    for bb_idx in range(trimmed_pillar_idx + 1, trimmed_failing_idx):
        bb0 = base_fs0.instr_objs_seq[bb_idx]
        bb1 = base_fs1.instr_objs_seq[bb_idx]
        bb_len = len(bb0)
        # Save instructions (all but last = CF exit of this BB)
        saved0 = [bb0[i] for i in range(bb_len - 1)]
        saved1 = [bb1[i] for i in range(bb_len - 1)]

        # Coarse: replace all non-placeholder instructions with NOPs at once
        coarse_noped = []
        for i in range(bb_len - 1):
            if _can_nopize(bb0[i]) and bb0[i].paddr != leaker_paddr:
                base_fs0.instr_objs_seq[bb_idx][i] = _NopSubstitute(bb0[i])
                base_fs1.instr_objs_seq[bb_idx][i] = _NopSubstitute(bb1[i])
                coarse_noped.append(i)

        if not coarse_noped:
            continue

        n_attempts += 1
        t_a = time.time()
        label = f"p4B_coarse_bb{bb_idx}_a{n_attempts}"
        try:
            diverges = oracle_fn(base_fs0, base_fs1, label)
        except Exception as e:
            diverges = False
            print(f"  [{n_attempts:3d}]  bb{bb_idx:3d}  coarse spike/sim error: {e} → fine-grain")
        dt = time.time() - t_a

        if diverges:
            n_nops += len(coarse_noped)
            print(f"  [{n_attempts:3d}]  bb{bb_idx:3d}  COARSE-NOP "
                  f"({len(coarse_noped)} instrs, {dt:.1f}s)")
        else:
            # Revert coarse; fall back to fine-grain per instruction
            for i in range(len(saved0)):
                base_fs0.instr_objs_seq[bb_idx][i] = saved0[i]
                base_fs1.instr_objs_seq[bb_idx][i] = saved1[i]
            print(f"  [{n_attempts:3d}]  bb{bb_idx:3d}  coarse fail ({dt:.1f}s) → fine-grain")
            n_nops, n_attempts = _fine_grain_nopize_bb(
                base_fs0, base_fs1, bb_idx,
                range(bb_len - 1),
                leaker_paddr, oracle_fn, n_nops, n_attempts, "p4B",
            )

    # ----------------------------------------------------------------
    # (C) Failing BB — fine-grain: instructions before failing_instr
    # Mirrors milesan reduce.py section (C)
    # ----------------------------------------------------------------
    fail_bb_len = len(base_fs0.instr_objs_seq[trimmed_failing_idx])
    fail_instr_trimmed = failing_instr if not fault_from_prev_bb else fail_bb_len - 2
    # Mirrors milesan reduce.py section (C): range(failing_instr_id - 1).
    # The instruction directly before the leaker is by definition load-bearing
    # (step-back pre-check asserts this), so skip it to save one guaranteed-fail call.
    fail_c_range = range(max(0, fail_instr_trimmed - 1))
    print(f"  (C) Failing BB fine-grain: {len(fail_c_range)} candidates before leaker")
    n_nops, n_attempts = _fine_grain_nopize_bb(
        base_fs0, base_fs1, trimmed_failing_idx,
        fail_c_range,
        leaker_paddr, oracle_fn, n_nops, n_attempts, "p4C",
    )

    # Emit final minimal ELFs
    minimal_t0 = os.path.join(workdir, "minimal_t0.elf")
    minimal_t1 = os.path.join(workdir, "minimal_t1.elf")
    _gen_phase4_elf(base_fs0, "minimal_t0", minimal_t0)
    _gen_phase4_elf(base_fs1, "minimal_t1", minimal_t1)

    # Post-Phase-4 sanity check: oracle must still diverge on the final minimal ELFs
    print(f"  Running post-Phase-4 sanity check on minimal ELFs...", end=" ", flush=True)
    final_diverges = _phase4_oracle(base_fs0, base_fs1, "minimal", workdir, timeout)
    sanity_ok = bool(final_diverges)
    print("OK" if sanity_ok else "FAILED")

    leaker_present = any(
        instr.paddr == leaker_paddr
        for bb in base_fs0.instr_objs_seq
        for instr in bb
    )
    if not leaker_present:
        sanity_ok = False
        print(f"  Sanity check FAILED: leaker paddr {hex(leaker_paddr)} missing from minimal gadget")

    gadget_size = sum(
        1 for bb in base_fs0.instr_objs_seq
        for instr in bb
        if not isinstance(instr, _NopSubstitute) and not getattr(instr, "iscontext", False)
    )

    elapsed = time.time() - t_start
    reason = "ok" if sanity_ok else "sanity_failed"
    print(f"  Phase 4 done: n_nops={n_nops}, gadget_size={gadget_size}, "
          f"sanity_ok={sanity_ok}  ({elapsed:.1f}s)")

    return n_nops, gadget_size, False, minimal_t0, minimal_t1, sanity_ok, reason
