# Copyright 2026 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# Post-hoc forensic evidence layer for one-zero VPC reductions.
#
# Operates READ-ONLY over an existing reduction workdir, emitting a structured
# `forensic.json` + markdown `forensic_report.md`.  When `minimal_t{0,1}.elf`
# (Phase 4 NOPize output) exist they are used as the gadget basis — this is the
# "smoking gun" evidence per the plan.  Else we fall back to `reduced_t{0,1}.elf`.
#
# The data gatherer is deliberately separate from the renderer so the report
# format can iterate without re-running spike.

import json
import os
import re
import subprocess

from params.fuzzparams import USE_MMU

from common.spike import SPIKE_STARTADDR
from onezero.context import (
    instr_to_dict, find_first_divergence, pick_divergence_logs,
    OBJDUMP, OBJDUMP_FLAGS,
)

_SPIKE_BIN = "spike"


# ---------------------------------------------------------------------------
# Spike replay (optional — degrades gracefully if spike fails)
# ---------------------------------------------------------------------------

def _run_spike_commit_log(elf_path, isa, max_instrs=2000, timeout=60):
    """Run spike --log-commits on an ELF and return the parsed trace.

    Returns list of dicts: {pc, priv, mnemonic, rd, rd_val, memop, addr}.
    Empty list on failure.
    """
    if not os.path.isfile(elf_path):
        return []
    # spike --log-commits prints lines like:
    #   core   0: 3 0x0000000080000004 (0x00000013) x 0 0x00000000 DASM(0x00000013)
    # We'll use -l (log all instructions) and --log-commits for commit trace.
    cmd = [
        _SPIKE_BIN,
        "--log-commits",
        f"-l",
        f"--isa={isa}",
        f"--pc={SPIKE_STARTADDR}",
        elf_path,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except Exception:
        return []
    # Commit trace is written to stderr by spike
    text = proc.stderr.decode(errors="replace")
    lines = text.splitlines()
    trace = []
    # Regex for the commit-log line
    # Example: "core   0: 3 0x0000000080000004 (0x00000013) x 0 0x00000000"
    #      or: "core   0: 3 0x000...004 (0x00000013) mem 0x80001000 0x00000042"
    line_re = re.compile(
        r"core\s+\d+:\s+(?P<priv>\d+)\s+0x(?P<pc>[0-9a-fA-F]+)\s+\(0x(?P<bc>[0-9a-fA-F]+)\)"
        r"(?:\s+(?P<kind>x|f|mem)\s+(?P<dst>\S+)\s+0x(?P<val>[0-9a-fA-F]+))?"
        r"(?:\s+mem\s+0x(?P<memaddr>[0-9a-fA-F]+)(?:\s+0x(?P<memval>[0-9a-fA-F]+))?)?"
    )
    for ln in lines:
        m = line_re.search(ln)
        if not m:
            continue
        entry = {
            "priv": int(m.group("priv")),
            "pc": int(m.group("pc"), 16),
            "bytecode": int(m.group("bc"), 16),
        }
        if m.group("kind"):
            entry["writeback_kind"] = m.group("kind")
            entry["writeback_dst"] = m.group("dst")
            if m.group("val"):
                try:
                    entry["writeback_val"] = int(m.group("val"), 16)
                except Exception:
                    pass
        if m.group("memaddr"):
            entry["memaddr"] = int(m.group("memaddr"), 16)
        trace.append(entry)
        if len(trace) >= max_instrs:
            break
    return trace


def _arch_diff(trace0, trace1):
    """Compare two spike commit traces. Returns classification dict.

    Returns one of:
      {"class": "arch-visible", "first_diff_idx": i, "first_diff_pc_t0": ..., "first_diff_pc_t1": ...}
      {"class": "microarch-only", "first_value_diff_idx": i, "pc": ..., "val_t0": ..., "val_t1": ...}
      {"class": "spike-identical"}
      {"class": "unavailable"}
    """
    if not trace0 or not trace1:
        return {"class": "unavailable",
                "reason": f"spike trace empty (t0={len(trace0)} t1={len(trace1)})"}
    min_len = min(len(trace0), len(trace1))
    # Control-flow divergence: different PCs at same index
    for i in range(min_len):
        if trace0[i]["pc"] != trace1[i]["pc"]:
            return {
                "class": "arch-visible",
                "first_diff_idx": i,
                "first_diff_pc_t0": hex(trace0[i]["pc"]),
                "first_diff_pc_t1": hex(trace1[i]["pc"]),
                "t0_mnemonic_bc": hex(trace0[i]["bytecode"]),
                "t1_mnemonic_bc": hex(trace1[i]["bytecode"]),
            }
    if len(trace0) != len(trace1):
        return {
            "class": "arch-visible",
            "first_diff_idx": min_len,
            "reason": "trace lengths differ",
            "len_t0": len(trace0),
            "len_t1": len(trace1),
        }
    # Data divergence: same PCs but different writeback values
    for i in range(min_len):
        v0 = trace0[i].get("writeback_val")
        v1 = trace1[i].get("writeback_val")
        if v0 is not None and v1 is not None and v0 != v1:
            return {
                "class": "microarch-only",
                "first_value_diff_idx": i,
                "pc": hex(trace0[i]["pc"]),
                "val_t0": hex(v0),
                "val_t1": hex(v1),
                "dst_t0": trace0[i].get("writeback_dst"),
                "dst_t1": trace1[i].get("writeback_dst"),
            }
    return {"class": "spike-identical",
            "note": "spike sees no architectural or value divergence — RTL VPC divergence is likely microarchitectural (speculative)"}


# ---------------------------------------------------------------------------
# Objdump parsing
# ---------------------------------------------------------------------------

def _parse_objdump(dump_path):
    """Return {paddr_int: disasm_str} for a .dump file."""
    out = {}
    if not os.path.isfile(dump_path):
        return out
    line_re = re.compile(r"^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]+)\s+(.*)$")
    with open(dump_path) as f:
        for ln in f:
            m = line_re.match(ln)
            if not m:
                continue
            try:
                addr = int(m.group(1), 16)
                out[addr] = m.group(3).strip()
            except Exception:
                pass
    return out


# ---------------------------------------------------------------------------
# Gadget extraction from fuzzerstate (prefers minimal, falls back to reduced)
# ---------------------------------------------------------------------------

def _extract_gadget_instrs(fs, pillar_bb, failing_bb, failing_instr, fault_from_prev_bb,
                            nopize_active, disasm_by_paddr=None):
    """Walk fs instruction sequence from pillar through failing_bb and return the
    surviving (non-NOP) instructions annotated with (bb_id, instr_idx, paddr,
    str, priv, class, is_nop).

    When `nopize_active` is True, an instruction is flagged is_nop=True if either
    (a) its in-memory object is a _NopSubstitute / has isdead=True, or
    (b) `disasm_by_paddr` says the minimal-ELF bytecode at its paddr is a NOP.
    The disasm overlay handles the common case where Phase 4 mutated a deepcopy
    that the caller does not have a handle to (e.g. when do_reduce.py passed the
    un-mutated fs0 into build_forensic).
    """
    try:
        from onezero.reduce_onezero import _NopSubstitute
    except ImportError:
        _NopSubstitute = None

    items = []
    total_bbs = len(fs.instr_objs_seq)
    start_bb = max(1, min(pillar_bb, total_bbs - 1)) if pillar_bb is not None else max(1, failing_bb)
    end_bb = min(failing_bb, total_bbs - 1)

    def _is_nop_disasm(s):
        if not s:
            return False
        s = s.strip().lower()
        # canonical addi x0,x0,0 — numeric disasm (no-aliases) uses "x0", ABI uses "zero"
        return (s.startswith("nop") or s.startswith("c.nop")
                or "addi\tx0,x0,0" in s or "addi\tzero,zero,0" in s)

    for bb_id in range(start_bb, end_bb + 1):
        bb = fs.instr_objs_seq[bb_id]
        for instr_idx, instr in enumerate(bb):
            is_nop = (_NopSubstitute is not None and isinstance(instr, _NopSubstitute)) or \
                     getattr(instr, "isdead", False)
            if not is_nop and disasm_by_paddr is not None:
                try:
                    paddr_int = instr.paddr
                except Exception:
                    paddr_int = None
                if paddr_int is not None:
                    is_nop = _is_nop_disasm(disasm_by_paddr.get(paddr_int))
            entry = {
                "bb_id": bb_id,
                "instr_idx": instr_idx,
                "is_nop": bool(is_nop),
            }
            try:
                entry["paddr"] = hex(instr.paddr) if instr.paddr is not None else None
            except Exception:
                entry["paddr"] = None
            try:
                entry["priv"] = instr.priv_level.name if instr.priv_level is not None else None
            except Exception:
                entry["priv"] = None
            try:
                entry["str"] = instr.get_str(False)
            except Exception:
                entry["str"] = repr(instr)
            try:
                entry["mnemonic"] = getattr(instr, "instr_str", type(instr).__name__)
            except Exception:
                entry["mnemonic"] = None
            try:
                entry["class"] = type(instr).__name__
            except Exception:
                entry["class"] = None
            for f in ("rd", "rs1", "rs2"):
                if hasattr(instr, f):
                    entry[f] = getattr(instr, f)
            if hasattr(instr, "imm"):
                try:
                    entry["imm"] = instr.imm
                except Exception:
                    pass
            items.append(entry)
    return items


# ---------------------------------------------------------------------------
# Tagger (PRIMER / SETUP / TRANSMIT / LEAKER / BRANCH / FAULT-TRIGGER / CTRL)
# ---------------------------------------------------------------------------

def _tag_instrs(items, leaker_paddr, pillar_paddr, taint_source_privs):
    """Rule-based tagger for Section 2. Operates over the pre-extracted items.

    Tags (first applicable wins):
      - LEAKER:        instr at leaker_paddr
      - FAULT-TRIGGER: ecall/ebreak/illegal/sret/mret/trap-causing
      - BRANCH:        beq/bne/blt/bge/bltu/bgeu/c.beqz/c.bnez
      - TRANSMIT:      load/store in the last 1/3 of the span
      - SETUP:         everything in the middle
      - PRIMER:        pillar_paddr (the first surviving non-initial instr)
      - CF:            JAL/JALR
    """
    FAULT_MNEMONICS = {"ecall", "ebreak", "sret", "mret", "uret"}
    BRANCH_MNEMONICS = {"beq","bne","blt","bge","bltu","bgeu","c.beqz","c.bnez"}
    CF_MNEMONICS = {"jal","jalr","c.jal","c.jalr","c.j","c.jr"}
    LOAD_MNEMONICS = {"lb","lh","lw","lwu","ld","lbu","lhu","c.lw","c.ld","c.lwsp","c.ldsp"}
    STORE_MNEMONICS = {"sb","sh","sw","sd","c.sw","c.sd","c.swsp","c.sdsp"}

    survivors = [i for i in items if not i.get("is_nop")]
    n = len(survivors)
    cutoff_transmit = max(n - max(1, n // 3), 0)

    leaker_paddr_int = int(leaker_paddr, 16) if isinstance(leaker_paddr, str) else leaker_paddr

    for i, entry in enumerate(survivors):
        p_int = int(entry["paddr"], 16) if entry.get("paddr") else None
        mn = (entry.get("mnemonic") or "").lower()
        if p_int is not None and p_int == leaker_paddr_int:
            entry["tag"] = "LEAKER"
        elif mn in FAULT_MNEMONICS or "Exception" in (entry.get("class") or "") or "Illegal" in (entry.get("class") or ""):
            entry["tag"] = "FAULT-TRIGGER"
        elif mn in BRANCH_MNEMONICS:
            entry["tag"] = "BRANCH"
        elif mn in CF_MNEMONICS:
            entry["tag"] = "CF"
        elif mn in LOAD_MNEMONICS or mn in STORE_MNEMONICS:
            entry["tag"] = "TRANSMIT" if i >= cutoff_transmit else "SETUP"
        elif i == 0:
            entry["tag"] = "PRIMER"
        else:
            entry["tag"] = "SETUP"

    # Map tags back onto original items by (bb_id, instr_idx)
    tag_by_key = {(e["bb_id"], e["instr_idx"]): e["tag"] for e in survivors}
    for item in items:
        key = (item["bb_id"], item["instr_idx"])
        if item.get("is_nop"):
            item["tag"] = "NOP"
        else:
            item["tag"] = tag_by_key.get(key, "SETUP")

    return items


# ---------------------------------------------------------------------------
# Backward dataflow slice
# ---------------------------------------------------------------------------

def _dataflow_slice(gadget_items, leaker_entry, depth_cap=20):
    """Starting from leaker's rs1/rs2, walk backward to find the chain of writers.

    Each hop: find the latest preceding survivor whose rd == consumed_reg.
    Stops at depth_cap or when we hit an instruction with no further dependency
    (loads, CSR reads, lui, auipc terminate the chain).

    Returns list of hops: [{reg, producer_entry, depth}].
    """
    if not leaker_entry:
        return []
    survivors = [e for e in gadget_items if not e.get("is_nop")]
    try:
        leaker_idx_in_survivors = next(i for i, e in enumerate(survivors)
                                       if e.get("bb_id") == leaker_entry["bb_id"]
                                       and e.get("instr_idx") == leaker_entry["instr_idx"])
    except StopIteration:
        return []

    CHAIN_TERMINATORS = {
        "lb","lh","lw","lwu","ld","lbu","lhu","c.lw","c.ld","c.lwsp","c.ldsp",
        "lui","auipc","c.lui",
        "csrrw","csrrs","csrrc","csrrwi","csrrsi","csrrci",
    }

    hops = []
    worklist = []  # (reg, consumer_idx, depth)
    for f in ("rs1", "rs2"):
        rv = leaker_entry.get(f)
        if rv is not None and rv != 0:
            worklist.append((rv, leaker_idx_in_survivors, 0, f))
    visited = set()
    while worklist and len(hops) < depth_cap:
        reg, consumer_idx, depth, src_field = worklist.pop(0)
        if (reg, consumer_idx) in visited:
            continue
        visited.add((reg, consumer_idx))
        # Find nearest prior survivor whose rd == reg
        producer = None
        producer_idx = None
        for pi in range(consumer_idx - 1, -1, -1):
            e = survivors[pi]
            if e.get("rd") == reg and reg != 0:
                producer = e
                producer_idx = pi
                break
        if producer is None:
            hops.append({"reg": reg, "via": src_field, "depth": depth,
                         "producer": None, "terminator": "not-found-in-span"})
            continue
        mn = (producer.get("mnemonic") or "").lower()
        hop = {"reg": reg, "via": src_field, "depth": depth,
               "producer": {k: producer.get(k) for k in ("bb_id","instr_idx","paddr","str","mnemonic","class","rd","rs1","rs2","tag")},
               "terminator": None}
        if mn in CHAIN_TERMINATORS:
            hop["terminator"] = mn
            hops.append(hop)
            continue
        hops.append(hop)
        for f in ("rs1", "rs2"):
            rv = producer.get(f)
            if rv is not None and rv != 0:
                worklist.append((rv, producer_idx, depth + 1, f))
    return hops


# ---------------------------------------------------------------------------
# Exception / memory / taint section builders
# ---------------------------------------------------------------------------

def _section_exceptions(gadget_items):
    """Scan the gadget for exception-triggering instructions."""
    events = []
    EXC_SET = {"ecall","ebreak","sret","mret"}
    for item in gadget_items:
        if item.get("is_nop"):
            continue
        mn = (item.get("mnemonic") or "").lower()
        cls = item.get("class") or ""
        if mn in EXC_SET or "Illegal" in cls or "Misaligned" in cls:
            events.append({
                "bb_id": item["bb_id"], "instr_idx": item["instr_idx"],
                "paddr": item.get("paddr"), "priv": item.get("priv"),
                "mnemonic": mn, "class": cls, "str": item.get("str"),
            })
    return events


def _section_memaccess(gadget_items):
    """All loads/stores in the gadget, tagged with priv and basic info."""
    LOADS = {"lb","lh","lw","lwu","ld","lbu","lhu","c.lw","c.ld","c.lwsp","c.ldsp"}
    STORES = {"sb","sh","sw","sd","c.sw","c.sd","c.swsp","c.sdsp"}
    events = []
    for item in gadget_items:
        if item.get("is_nop"):
            continue
        mn = (item.get("mnemonic") or "").lower()
        if mn in LOADS or mn in STORES:
            events.append({
                "bb_id": item["bb_id"], "instr_idx": item["instr_idx"],
                "paddr": item.get("paddr"), "priv": item.get("priv"),
                "direction": "load" if mn in LOADS else "store",
                "mnemonic": mn, "str": item.get("str"),
                "rs1": item.get("rs1"), "rs2": item.get("rs2"),
                "rd": item.get("rd"), "imm": item.get("imm"),
            })
    return events


def _section_taint_sources(gadget_items, taint_source_privs):
    """Forward slice: which gadget instructions consume a tainted value?

    Conservative proxy: any load executing in a privilege level that IS a taint
    source is flagged as a potential tainted-value consumer.  The one-zero
    pipeline can't directly observe taint at the byte level without the CellIFT
    design, so this is a privilege-based heuristic.
    """
    if not taint_source_privs:
        return []
    LOADS = {"lb","lh","lw","lwu","ld","lbu","lhu","c.lw","c.ld","c.lwsp","c.ldsp"}
    events = []
    for item in gadget_items:
        if item.get("is_nop"):
            continue
        mn = (item.get("mnemonic") or "").lower()
        if mn in LOADS and item.get("priv") in taint_source_privs:
            events.append({
                "bb_id": item["bb_id"], "instr_idx": item["instr_idx"],
                "paddr": item.get("paddr"), "priv": item.get("priv"),
                "mnemonic": mn, "consumer_reg": item.get("rd"),
                "str": item.get("str"),
            })
    return events


def _section_cf_timeline(fs, pillar_bb, failing_bb):
    """One entry per BB between pillar and failing (inclusive), describing its
    first PC, privilege, instr count, and exit kind."""
    timeline = []
    total_bbs = len(fs.instr_objs_seq)
    start_bb = max(1, pillar_bb) if pillar_bb is not None else max(1, failing_bb)
    end_bb = min(failing_bb, total_bbs - 1)
    for bb_id in range(start_bb, end_bb + 1):
        bb = fs.instr_objs_seq[bb_id]
        first = bb[0] if bb else None
        last = bb[-1] if bb else None
        entry = {"bb_id": bb_id, "n_instrs": len(bb)}
        try:
            entry["first_pc"] = hex(first.paddr) if first and first.paddr is not None else None
        except Exception:
            entry["first_pc"] = None
        try:
            entry["priv"] = first.priv_level.name if first and first.priv_level else None
        except Exception:
            entry["priv"] = None
        try:
            last_mn = (getattr(last, "instr_str", "") or "").lower()
            if last_mn in {"jal","jalr","c.j","c.jr","c.jal","c.jalr"}:
                entry["exit_kind"] = "jump"
            elif last_mn in {"beq","bne","blt","bge","bltu","bgeu","c.beqz","c.bnez"}:
                entry["exit_kind"] = "branch"
            elif last_mn in {"ecall","ebreak","sret","mret"}:
                entry["exit_kind"] = "trap"
            else:
                entry["exit_kind"] = "fallthrough"
        except Exception:
            entry["exit_kind"] = None
        timeline.append(entry)
    return timeline


# ---------------------------------------------------------------------------
# Top-level builder
# ---------------------------------------------------------------------------

def _lookup_context_json(workdir):
    path = os.path.join(workdir, "context.json")
    if os.path.isfile(path):
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            return None
    return None


def _lookup_result_json(workdir):
    path = os.path.join(workdir, "result.json")
    if os.path.isfile(path):
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            return None
    return None


def _design_isa(design_name):
    """Return spike --isa flag for a given design."""
    try:
        from common.designcfgs import get_design_march_flags
        return get_design_march_flags(design_name)
    except Exception:
        # boom default
        return "rv64imc"


def build_forensic(workdir, fs0=None, fs1=None, result=None, context=None,
                   spike_max_instrs=2000, spike_timeout=60, dataflow_depth_cap=20):
    """Assemble the forensic dict for one reduction workdir.

    Args:
        workdir: the per-seed directory containing result.json, context.json,
                 reduced_t*.elf, and (optionally) minimal_t*.elf.
        fs0/fs1: optional spike-resolved FuzzerStates (in-memory path); if None,
                 we rely only on objdump + context.json + VPC logs.
        result:  optional pre-loaded result.json dict (saves a disk read).
        context: optional pre-loaded context.json dict (saves a disk read).
    """
    forensic = {"workdir": workdir}

    if result is None:
        result = _lookup_result_json(workdir)
    if context is None:
        context = _lookup_context_json(workdir)

    if result is None:
        forensic["error"] = "result.json missing — cannot build forensic"
        return forensic

    design = result.get("design", "boom")
    seed = result.get("seed")
    failing_bb = result.get("failing_bb_id")
    failing_instr = result.get("failing_instr_id")
    pillar_bb = result.get("pillar_bb_id")
    fault_from_prev_bb = bool(result.get("fault_from_prev_bb"))
    nopize_info = result.get("nopize") or {}
    nopize_active = bool(nopize_info.get("minimal_t0_elf") and
                          os.path.isfile(nopize_info["minimal_t0_elf"]))

    forensic["seed"] = seed
    forensic["design"] = design
    forensic["failing_bb_id"] = failing_bb
    forensic["failing_instr_id"] = failing_instr
    forensic["pillar_bb_id"] = pillar_bb
    forensic["fault_from_prev_bb"] = fault_from_prev_bb
    forensic["nopize_active"] = nopize_active
    forensic["nopize_info"] = nopize_info

    # Inline flags / divergence from context
    if context is not None:
        forensic["flags"] = context.get("flags") or {}
        forensic["divergence"] = context.get("divergence") or {}
        forensic["leaker_from_context"] = context.get("leaker") or {}
    else:
        forensic["flags"] = {}
        forensic["divergence"] = {}
        forensic["leaker_from_context"] = {}

    # Gadget items — prefer mutated fs (post-Phase-4) if we have it
    gadget_items = []
    leaker_entry = None
    pillar_entry = None
    if fs0 is not None and failing_bb is not None:
        try:
            # When Phase 4 is active, overlay actual NOP positions by parsing
            # minimal_t0.elf.dump (the in-memory fs0 may not carry the mutations
            # if Phase 4 operated on a deepcopy).
            disasm_overlay = None
            if nopize_active:
                min_dump = os.path.join(workdir, "minimal_t0.elf.dump")
                if os.path.isfile(min_dump):
                    disasm_overlay = _parse_objdump(min_dump)
            items = _extract_gadget_instrs(
                fs0, pillar_bb, failing_bb, failing_instr, fault_from_prev_bb,
                nopize_active, disasm_by_paddr=disasm_overlay,
            )
            # Resolve leaker paddr for tagging
            if fault_from_prev_bb:
                leaker_paddr = fs0.instr_objs_seq[failing_bb - 1][-1].paddr
            else:
                leaker_paddr = fs0.instr_objs_seq[failing_bb][failing_instr].paddr
            taint_source_privs = None
            try:
                taint_source_privs = [p.name for p in fs0.taint_source_privs]
            except Exception:
                pass
            pillar_paddr = None
            try:
                if pillar_bb is not None and pillar_bb < len(fs0.instr_objs_seq):
                    pillar_paddr = fs0.instr_objs_seq[pillar_bb][0].paddr
            except Exception:
                pass
            items = _tag_instrs(items, hex(leaker_paddr), pillar_paddr, taint_source_privs)
            gadget_items = items
            # Locate leaker_entry and pillar_entry in items
            for it in items:
                if it.get("paddr") == hex(leaker_paddr):
                    leaker_entry = it
                if pillar_paddr is not None and it.get("paddr") == hex(pillar_paddr):
                    pillar_entry = it
        except Exception as e:
            forensic["gadget_error"] = str(e)

    forensic["gadget"] = {
        "n_instrs": sum(1 for i in gadget_items if not i.get("is_nop")),
        "n_nops": sum(1 for i in gadget_items if i.get("is_nop")),
        "items": gadget_items,
        "leaker": leaker_entry,
        "pillar": pillar_entry,
    }

    # Section 3: leaker annotated (operand last-writer)
    if leaker_entry and fs0 is not None:
        forensic["leaker_annotated"] = {
            "disasm": leaker_entry.get("str"),
            "paddr": leaker_entry.get("paddr"),
            "priv": leaker_entry.get("priv"),
            "mnemonic": leaker_entry.get("mnemonic"),
            "class": leaker_entry.get("class"),
            "rd": leaker_entry.get("rd"),
            "rs1": leaker_entry.get("rs1"),
            "rs2": leaker_entry.get("rs2"),
        }

    # Section 5: arch state diff via spike (optional — minimal_t*.elf preferred)
    spike_trace_pair = {}
    arch_diff = {"class": "unavailable", "reason": "no elfs"}
    elf_source = None
    elf_t0 = nopize_info.get("minimal_t0_elf") if nopize_active else None
    elf_t1 = nopize_info.get("minimal_t1_elf") if nopize_active else None
    if not elf_t0 or not os.path.isfile(elf_t0):
        elf_t0 = os.path.join(workdir, "reduced_t0.elf")
        elf_t1 = os.path.join(workdir, "reduced_t1.elf")
        if os.path.isfile(elf_t0):
            elf_source = "reduced"
    else:
        elf_source = "minimal"

    if elf_source and os.path.isfile(elf_t0) and os.path.isfile(elf_t1):
        isa = _design_isa(design)
        t0_trace = _run_spike_commit_log(elf_t0, isa, max_instrs=spike_max_instrs, timeout=spike_timeout)
        t1_trace = _run_spike_commit_log(elf_t1, isa, max_instrs=spike_max_instrs, timeout=spike_timeout)
        spike_trace_pair = {
            "elf_source": elf_source,
            "len_t0": len(t0_trace),
            "len_t1": len(t1_trace),
        }
        arch_diff = _arch_diff(t0_trace, t1_trace)

    forensic["spike_trace_pair"] = spike_trace_pair
    forensic["arch_diff"] = arch_diff

    # Section 6: backward dataflow slice
    forensic["dataflow_slice"] = _dataflow_slice(gadget_items, leaker_entry,
                                                  depth_cap=dataflow_depth_cap)

    # Section 7: CF timeline
    if fs0 is not None and failing_bb is not None:
        forensic["cf_timeline"] = _section_cf_timeline(fs0, pillar_bb, failing_bb)
    else:
        forensic["cf_timeline"] = []

    # Section 8: exceptions
    forensic["exceptions"] = _section_exceptions(gadget_items)

    # Section 9: memory log
    forensic["memory_log"] = _section_memaccess(gadget_items)

    # Section 10: taint-source consumer summary
    taint_source_privs = forensic.get("flags", {}).get("taint_source_privs") or []
    forensic["taint_source_consumers"] = _section_taint_sources(gadget_items, taint_source_privs)

    # Section 4: divergence point — already in forensic["divergence"]; add window reference
    window_file = os.path.join(workdir, "divergence_window.txt")
    if os.path.isfile(window_file):
        forensic["divergence_window_file"] = window_file

    return forensic
