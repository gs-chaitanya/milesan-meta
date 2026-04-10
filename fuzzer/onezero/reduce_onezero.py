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
from milesan.cfinstructionclasses import IntStoreInstruction
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

    # Generate truncated ELFs from pre-resolved fuzzerstates
    if first_bb is not None and first_bb > 1:
        gen_truncated_elf_pillar(fs0, max_bb_id, max_instr_id, first_bb, elf_0)
        gen_truncated_elf_pillar(fs1, max_bb_id, max_instr_id, first_bb, elf_1)
    elif max_instr_id is None:
        total_bbs_0 = len(fs0.instr_objs_seq)
        total_bbs_1 = len(fs1.instr_objs_seq)
        gen_truncated_elf(fs0, min(max_bb_id, total_bbs_0), elf_0)
        gen_truncated_elf(fs1, min(max_bb_id, total_bbs_1), elf_1)
    else:
        gen_truncated_elf_instr(fs0, max_bb_id, max_instr_id, elf_0)
        gen_truncated_elf_instr(fs1, max_bb_id, max_instr_id, elf_1)

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


def _save_ctx_and_jump_to_pillar_specific_instr_oz(fuzzerstate, index_first_bb, index_first_instr):
    """Snapshot architectural state at the entry of BB index_first_bb via Spike,
    generate a context-setter BB that restores that state, and redirect the initial
    block's tail jump to the context setter.

    Modifies fuzzerstate in place. Returns (fuzzerstate, tgt_addr_layout, tgt_addr_priv).

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
        fuzzerstate.instance_to_str(), spikereduce_elfpath, march_flags,
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


def gen_truncated_elf_pillar(fuzzerstate, max_bb_id, max_instr_id, first_bb, elf_path):
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
        fs, _, _ = _save_ctx_and_jump_to_pillar_specific_instr_oz(fs, first_bb, 0)

    # Front-trimming: delete BBs [1, first_bb) from instr_objs_seq and bb_start_addr_seq
    if first_bb > 1:
        del fs.instr_objs_seq[1:first_bb]
        del fs.bb_start_addr_seq[1:first_bb]

    fs.verify_program()
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
                   hint_left=None, hint_right=None):
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
    assert failing_bb_id > 0, "Pillar search assumes failing_bb_id > 0"
    assert failing_instr_id is not None, "find_pillar_bb requires failing_instr_id"

    left_bound  = hint_left  if hint_left  is not None else 0
    right_bound = hint_right if hint_right is not None else failing_bb_id + 1

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
