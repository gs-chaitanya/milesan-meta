# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# Post-reduction diagnostic context assembly for one-zero VPC reduction.
# Pure read-only helpers — no simulation, no reduction logic, no side effects.
# All functions wrap attribute access in try/except and degrade gracefully.

import os
import shutil
import subprocess
from pathlib import Path

from params.fuzzparams import USE_MMU

OBJDUMP = (
    "/mnt/chipyard/.conda-env/riscv-tools/bin/riscv64-unknown-elf-objdump"
)
OBJDUMP_FLAGS = ["-d", "--disassembler-options=numeric,no-aliases"]


# ---------------------------------------------------------------------------
# Objdump parsing for full disassembly in summary.txt
# ---------------------------------------------------------------------------

def _parse_objdump_file(dump_path):
    """Return {paddr_int: line_str} from an objdump output file.

    Skips headers, section labels, and blank lines — keeps only disasm lines
    whose first token is a hex address followed by ':'.
    """
    out = {}
    try:
        with open(dump_path) as f:
            for raw in f:
                stripped = raw.lstrip()
                if not stripped:
                    continue
                colon = stripped.find(":")
                if colon < 1 or colon > 20:
                    continue
                try:
                    pa = int(stripped[:colon], 16)
                    out[pa] = raw.rstrip("\n")
                except ValueError:
                    continue
    except OSError:
        pass
    return out


def _render_disasm_bb(label, bb_instrs, dump_map, leaker_paddr=None):
    """Return list of strings: header + full per-instruction objdump disassembly.

    bb_instrs: list of instruction dicts from context.json (keys: paddr, str, ...).
    dump_map:  {paddr_int: line_str} built from display_t0.elf.dump, which is
               produced by gen_truncated_elf(fs0, failing_bb) — keeping the FULL
               failing BB so every instruction in both pillar BB and leaker BB
               has an entry.
    leaker_paddr: if set, marks that instruction with '>>' and '<-- LEAKER'.
    """
    if not bb_instrs:
        return []
    try:
        start = int(bb_instrs[0]["paddr"], 16)
        priv  = bb_instrs[0].get("priv_level", "?")
    except Exception:
        start, priv = 0, "?"

    lines = ["=== {} (bb_start=0x{:x}, n={}, priv={}) ===".format(
        label, start, len(bb_instrs), priv)]

    for instr_d in bb_instrs:
        try:
            paddr = int(instr_d["paddr"], 16)
        except Exception:
            paddr = None

        disasm_line = dump_map.get(paddr) if paddr is not None else None
        if disasm_line is None:
            # Fallback: only expected for the injected JAL that replaces the CF
            # terminator at the end of the leaker BB in display_t0.elf.
            disasm_line = "  0x{:x}:  {}".format(paddr or 0, instr_d.get("str", "?"))

        if leaker_paddr is not None and paddr == leaker_paddr:
            lines.append(">> {}  <-- LEAKER".format(disasm_line))
        else:
            lines.append("   {}".format(disasm_line))

    return lines


# ---------------------------------------------------------------------------
# Instruction / BB serialization
# ---------------------------------------------------------------------------

def instr_to_dict(instr, local_idx=None):
    """Serialize one instruction object to a JSON-safe dict."""
    d = {}
    if local_idx is not None:
        d["idx"] = local_idx
    try:
        d["str"] = instr.get_str(False)
    except Exception:
        d["str"] = repr(instr)
    try:
        d["mnemonic"] = instr.instr_str
    except Exception:
        d["mnemonic"] = None
    try:
        d["class"] = type(instr).__name__
    except Exception:
        d["class"] = None
    try:
        d["bytecode_hex"] = f"{instr.gen_bytecode_int(False):08x}"
    except Exception:
        d["bytecode_hex"] = None
    try:
        d["paddr"] = hex(instr.paddr) if instr.paddr is not None else None
    except Exception:
        d["paddr"] = None
    if USE_MMU:
        try:
            d["vaddr"] = hex(instr.vaddr) if instr.vaddr is not None else None
        except Exception:
            d["vaddr"] = None
        try:
            d["va_layout"] = instr.va_layout
        except Exception:
            d["va_layout"] = None
    try:
        d["priv_level"] = instr.priv_level.name if instr.priv_level is not None else None
    except Exception:
        d["priv_level"] = None
    return d


def bb_to_dict(fs, bb_id, full=True):
    """Serialize one basic block from fuzzerstate."""
    d = {"bb_id": bb_id}
    try:
        d["bb_start_paddr"] = hex(fs.bb_start_addr_seq[bb_id])
    except Exception:
        d["bb_start_paddr"] = None
    try:
        bb = fs.instr_objs_seq[bb_id]
        d["n_instrs"] = len(bb)
    except Exception:
        d["n_instrs"] = None
        if full:
            d["instructions"] = []
        return d

    try:
        d["priv_level"] = bb[0].priv_level.name if bb[0].priv_level is not None else None
    except Exception:
        d["priv_level"] = None
    if USE_MMU:
        try:
            d["va_layout"] = bb[0].va_layout
        except Exception:
            d["va_layout"] = None

    if full:
        d["instructions"] = [instr_to_dict(instr, idx) for idx, instr in enumerate(bb)]
    else:
        # Summary only: first and last instruction
        try:
            d["first_instr"] = instr_to_dict(bb[0], 0)
            d["last_instr"] = instr_to_dict(bb[-1], len(bb) - 1)
        except Exception:
            pass
    return d


def intermediate_bbs_summary(fs, pillar_bb, failing_bb):
    """Summarise each BB strictly between pillar_bb and failing_bb (exclusive)."""
    summaries = []
    for bb_id in range(pillar_bb + 1, failing_bb):
        try:
            bb = fs.instr_objs_seq[bb_id]
            entry = {
                "bb_id": bb_id,
                "n_instrs": len(bb),
            }
            try:
                entry["bb_start_paddr"] = hex(fs.bb_start_addr_seq[bb_id])
            except Exception:
                entry["bb_start_paddr"] = None
            try:
                entry["priv_level"] = bb[0].priv_level.name if bb[0].priv_level is not None else None
            except Exception:
                entry["priv_level"] = None
            # Last instruction (CF terminator)
            try:
                entry["last_instr"] = instr_to_dict(bb[-1], len(bb) - 1)
            except Exception:
                entry["last_instr"] = None
            summaries.append(entry)
        except Exception:
            summaries.append({"bb_id": bb_id, "error": "serialization failed"})
    return summaries


# ---------------------------------------------------------------------------
# VPC log analysis
# ---------------------------------------------------------------------------

def find_first_divergence(vpc0_path, vpc1_path, window=10):
    """Compare two VPC log files and return info about the first diverging line.

    Returns a dict with keys:
      diverge_line_no, cycle_t0, vpc_t0, cycle_t1, vpc_t1,
      total_lines_t0, total_lines_t1,
      window_t0 (list of str), window_t1 (list of str)
    Returns None if the files are identical or cannot be read.
    """
    try:
        with open(vpc0_path, "r") as f0, open(vpc1_path, "r") as f1:
            lines0 = f0.readlines()
            lines1 = f1.readlines()
    except OSError:
        return None

    total0 = len(lines0)
    total1 = len(lines1)
    min_len = min(total0, total1)

    diverge_line = None
    for i in range(min_len):
        if lines0[i] != lines1[i]:
            diverge_line = i
            break
    # Files may be equal up to min_len but differ in length
    if diverge_line is None and total0 != total1:
        diverge_line = min_len

    if diverge_line is None:
        return None  # identical

    result = {
        "diverge_line_no": diverge_line,
        "total_lines_t0": total0,
        "total_lines_t1": total1,
    }

    def _parse_vpc_line(line):
        """Parse '<cycle> <vpc_hex>' into (cycle_int, vpc_hex_str)."""
        try:
            parts = line.strip().split()
            return int(parts[0]), parts[1]
        except Exception:
            return None, line.strip()

    if diverge_line < total0:
        result["cycle_t0"], result["vpc_t0"] = _parse_vpc_line(lines0[diverge_line])
    else:
        result["cycle_t0"], result["vpc_t0"] = None, "<eof>"

    if diverge_line < total1:
        result["cycle_t1"], result["vpc_t1"] = _parse_vpc_line(lines1[diverge_line])
    else:
        result["cycle_t1"], result["vpc_t1"] = None, "<eof>"

    # Context window (up to `window` lines before + after)
    lo = max(0, diverge_line - window)
    hi_0 = min(total0, diverge_line + window + 1)
    hi_1 = min(total1, diverge_line + window + 1)
    result["window_t0"] = [l.rstrip() for l in lines0[lo:hi_0]]
    result["window_t1"] = [l.rstrip() for l in lines1[lo:hi_1]]

    return result


def pick_divergence_logs(workdir, p3_bb, p3_instr, pillar_bb, failing_bb, failing_instr):
    """Find the most-reduced pair of VPC log files that show divergence.

    Tries candidates in order from most-reduced to least-reduced:
      1. Pillar-trimmed:  bb{p3_bb}i{p3_instr}_from{pillar_bb}_t*_vpc.txt  (when pillar_bb > 1)
      2. Instr-level:     bb{p3_bb}i{p3_instr}_t*_vpc.txt
      3. BB-level:        bb{failing_bb}_t*_vpc.txt
      4. Full program:    bbALL_t*_vpc.txt

    Returns (path0, path1, label) for the first existing pair, or (None, None, None).
    """
    candidates = []

    if pillar_bb is not None and pillar_bb > 1 and p3_instr is not None:
        candidates.append(f"bb{p3_bb}i{p3_instr}_from{pillar_bb}")
    if p3_instr is not None:
        candidates.append(f"bb{p3_bb}i{p3_instr}")
    candidates.append(f"bb{failing_bb}")
    candidates.append("bbALL")

    for label in candidates:
        p0 = os.path.join(workdir, f"{label}_t0_vpc.txt")
        p1 = os.path.join(workdir, f"{label}_t1_vpc.txt")
        if os.path.isfile(p0) and os.path.isfile(p1):
            return p0, p1, label

    return None, None, None


# ---------------------------------------------------------------------------
# Cross-priv / cross-layout exploit-class flags
# ---------------------------------------------------------------------------

def cross_priv_flags(fs, failing_bb, failing_instr_id, pillar_bb, fault_from_prev_bb):
    """Compute cross-privilege and cross-layout indicators.

    cross_priv: leaking instruction executes outside the set of privilege levels
                that hold tainted (secret) data (fs.taint_source_privs).
                Mirrors reduce.py:1445: leaker.priv_level not in taint_source_privs.

    cross_layout: leaking instruction's MMU layout differs from the taint source
                  layouts (fs.taint_source_layouts), when MMU is enabled.

    Also records leaker_priv, taint_source_privs, pillar_priv for reference.
    """
    flags = {
        "cross_priv": None,
        "cross_layout": None,
        "leaker_priv": None,
        "taint_source_privs": None,
        "pillar_priv": None,
        "leaker_layout": None,
        "taint_source_layouts": None,
        "pillar_layout": None,
    }
    try:
        if fault_from_prev_bb:
            leaker_bb = failing_bb - 1
            leaker_instr_idx = len(fs.instr_objs_seq[leaker_bb]) - 1
        else:
            leaker_bb = failing_bb
            leaker_instr_idx = failing_instr_id

        leaker_instr = fs.instr_objs_seq[leaker_bb][leaker_instr_idx]
        pillar_instr = fs.instr_objs_seq[pillar_bb][0] if pillar_bb is not None else None

        if leaker_instr.priv_level is not None:
            flags["leaker_priv"] = leaker_instr.priv_level.name

        # taint_source_privs: per-seed set of privilege levels whose data is tainted
        try:
            tsp = fs.taint_source_privs
            flags["taint_source_privs"] = [p.name for p in tsp]
            if leaker_instr.priv_level is not None:
                flags["cross_priv"] = leaker_instr.priv_level not in tsp
        except AttributeError:
            pass

        if pillar_instr is not None and pillar_instr.priv_level is not None:
            flags["pillar_priv"] = pillar_instr.priv_level.name

        if USE_MMU:
            flags["leaker_layout"] = leaker_instr.va_layout
            if pillar_instr is not None:
                flags["pillar_layout"] = pillar_instr.va_layout
            try:
                tsl = fs.taint_source_layouts
                flags["taint_source_layouts"] = list(tsl)
                if leaker_instr.va_layout is not None:
                    flags["cross_layout"] = leaker_instr.va_layout not in tsl
            except AttributeError:
                # Fallback: compare leaker vs pillar layout
                if flags["leaker_layout"] is not None and flags["pillar_layout"] is not None:
                    flags["cross_layout"] = flags["leaker_layout"] != flags["pillar_layout"]
    except Exception:
        pass

    return flags


# ---------------------------------------------------------------------------
# Artifact generation (Option A: regenerate canonical reduced ELFs)
# ---------------------------------------------------------------------------

def _objdump_elf(elf_path, dump_path):
    """Run objdump on elf_path, writing stdout to dump_path. Returns dump_path or None."""
    try:
        with open(dump_path, "w") as dump_f:
            subprocess.run(
                [OBJDUMP] + OBJDUMP_FLAGS + [elf_path],
                stdout=dump_f, stderr=subprocess.DEVNULL,
                timeout=60,
            )
        return dump_path
    except Exception:
        return None


def generate_reduced_artifacts(fs0, fs1, failing_bb, failing_instr_id, pillar_bb,
                                fault_from_prev_bb, workdir):
    """Generate reduced_t{0,1}.elf and display_t0.elf plus their objdump .dump files.

    reduced_t0.elf  — truncated at the failing instruction (for simulation).
    display_t0.elf  — truncated at the END of the failing BB, keeping every
                      instruction in it intact (only the CF terminator gets a JAL
                      appended).  This ELF is used only for human-readable
                      disassembly of the complete leaker BB and pillar BB.

    Returns a dict describing the generated artifacts (paths, sizes, errors).
    """
    from onezero.reduce_onezero import (
        gen_truncated_elf, gen_truncated_elf_instr, gen_truncated_elf_pillar,
    )

    # Determine truncation parameters for the simulation ELF
    if fault_from_prev_bb:
        trunc_bb    = failing_bb
        trunc_instr = 0
    else:
        trunc_bb    = failing_bb
        trunc_instr = failing_instr_id

    artifacts = {}

    for tval, fs, suffix in [(0, fs0, "t0"), (1, fs1, "t1")]:
        elf_path = os.path.join(workdir, f"reduced_{suffix}.elf")
        dump_path = elf_path + ".dump"
        entry = {"elf": elf_path, "dump": dump_path}

        try:
            if pillar_bb is not None and trunc_instr is not None:
                gen_truncated_elf_pillar(fs, trunc_bb, trunc_instr, pillar_bb, elf_path)
            elif trunc_instr is not None:
                gen_truncated_elf_instr(fs, trunc_bb, trunc_instr, elf_path)
            else:
                gen_truncated_elf(fs, trunc_bb, elf_path)

            try:
                entry["elf_size"] = os.path.getsize(elf_path)
            except OSError:
                entry["elf_size"] = None

            if _objdump_elf(elf_path, dump_path):
                entry["dump_size"] = os.path.getsize(dump_path)

        except Exception as e:
            entry["elf_error"] = str(e)

        artifacts[suffix] = entry

    # display_t0.elf — gen_truncated_elf(fs0, failing_bb) keeps BBs [0..failing_bb]
    # with only the CF terminator of the failing BB replaced by a JAL.  Every
    # other instruction in the failing BB (including the leaker) stays untouched,
    # so objdump of this ELF gives full disassembly of both pillar BB and leaker BB.
    display_elf = os.path.join(workdir, "display_t0.elf")
    display_dump = display_elf + ".dump"
    try:
        gen_truncated_elf(fs0, failing_bb, display_elf)
        _objdump_elf(display_elf, display_dump)
        artifacts["display_dump"] = display_dump
    except Exception as e:
        artifacts["display_dump_error"] = str(e)

    return artifacts


# ---------------------------------------------------------------------------
# Divergence window file
# ---------------------------------------------------------------------------

def write_divergence_window(divergence_info, workdir):
    """Write a human-readable divergence_window.txt from find_first_divergence output."""
    if not divergence_info:
        return None
    path = os.path.join(workdir, "divergence_window.txt")
    try:
        with open(path, "w") as f:
            f.write(f"First divergence at line {divergence_info['diverge_line_no']}\n")
            f.write(f"  t0: cycle={divergence_info.get('cycle_t0')}  vpc={divergence_info.get('vpc_t0')}\n")
            f.write(f"  t1: cycle={divergence_info.get('cycle_t1')}  vpc={divergence_info.get('vpc_t1')}\n")
            f.write(f"  total VPC log lines: t0={divergence_info['total_lines_t0']}  t1={divergence_info['total_lines_t1']}\n")
            f.write("\n--- t0 window ---\n")
            for line in divergence_info.get("window_t0", []):
                f.write(line + "\n")
            f.write("\n--- t1 window ---\n")
            for line in divergence_info.get("window_t1", []):
                f.write(line + "\n")
    except Exception:
        return None
    return path


# ---------------------------------------------------------------------------
# Top-level context assembly
# ---------------------------------------------------------------------------

def assemble_context(fs0, memsize, nmax_bbs, authorize_privileges,
                     failing_bb, failing_instr_id, pillar_bb,
                     fault_from_prev_bb, workdir, full_context=False):
    """Build the full diagnostic context dict from the reduced fuzzerstate.

    Uses fs0 (full, unmodified, spike-resolved) as the source of instruction data.
    Does not run any simulation.

    Args:
        fs0: spike-resolved FuzzerState with FORCE_TAINT_VALUE=0
        full_context: if True, include full per-instruction listings of intermediate BBs
    """
    ctx = {}

    # --- Program metadata ---
    ctx["meta"] = {
        "memsize": memsize,
        "nmax_bbs": nmax_bbs,
        "authorize_privileges": authorize_privileges,
        "use_mmu": USE_MMU,
        "total_bbs": len(fs0.instr_objs_seq),
        "total_instrs": sum(len(bb) for bb in fs0.instr_objs_seq),
    }
    try:
        ctx["meta"]["design_base_addr"] = hex(fs0.design_base_addr)
        ctx["meta"]["final_bb_base_addr"] = hex(fs0.final_bb_base_addr)
    except Exception:
        pass

    # --- Leaking instruction ---
    if fault_from_prev_bb:
        actual_leak_bb    = failing_bb - 1
        actual_leak_instr = len(fs0.instr_objs_seq[actual_leak_bb]) - 1
    else:
        actual_leak_bb    = failing_bb
        actual_leak_instr = failing_instr_id

    ctx["leaker"] = {"fault_from_prev_bb": fault_from_prev_bb}
    try:
        leak_instr = fs0.instr_objs_seq[actual_leak_bb][actual_leak_instr]
        ctx["leaker"].update(instr_to_dict(leak_instr, actual_leak_instr))
        ctx["leaker"]["bb_id"] = actual_leak_bb
    except Exception as e:
        ctx["leaker"]["error"] = str(e)

    # --- Leaker BB (full) ---
    try:
        ctx["leaker_bb"] = bb_to_dict(fs0, actual_leak_bb, full=True)
        ctx["leaker_bb"]["leaker_local_idx"] = actual_leak_instr
    except Exception as e:
        ctx["leaker_bb"] = {"error": str(e)}

    # --- If fault_from_prev_bb: also include first few instrs of the "trigger" BB ---
    if fault_from_prev_bb:
        try:
            ctx["trigger_bb_head"] = {
                "bb_id": failing_bb,
                "instructions": [
                    instr_to_dict(instr, idx)
                    for idx, instr in enumerate(fs0.instr_objs_seq[failing_bb][:5])
                ],
            }
        except Exception:
            pass

    # --- Pillar BB (full) ---
    if pillar_bb is not None:
        try:
            ctx["pillar_bb"] = bb_to_dict(fs0, pillar_bb, full=True)
        except Exception as e:
            ctx["pillar_bb"] = {"error": str(e)}
    else:
        ctx["pillar_bb"] = None

    # --- Intermediate BBs ---
    if pillar_bb is not None:
        try:
            ctx["intermediate_bbs"] = intermediate_bbs_summary(
                fs0, pillar_bb, actual_leak_bb
            )
            ctx["n_intermediate_bbs"] = len(ctx["intermediate_bbs"])
        except Exception as e:
            ctx["intermediate_bbs"] = []
            ctx["n_intermediate_bbs"] = None

        if full_context:
            try:
                ctx["intermediate_bbs_full"] = [
                    bb_to_dict(fs0, bb_id, full=True)
                    for bb_id in range(pillar_bb + 1, actual_leak_bb)
                ]
            except Exception:
                pass
    else:
        ctx["intermediate_bbs"] = []
        ctx["n_intermediate_bbs"] = None

    # --- Cross-priv / exploit-class flags ---
    if pillar_bb is not None:
        ctx["flags"] = cross_priv_flags(
            fs0, actual_leak_bb, actual_leak_instr, pillar_bb, fault_from_prev_bb
        )
    else:
        ctx["flags"] = {}

    # --- VPC divergence signal ---
    if fault_from_prev_bb:
        p3_bb, p3_instr = failing_bb, 0
    else:
        p3_bb, p3_instr = failing_bb, failing_instr_id

    vpc0, vpc1, div_label = pick_divergence_logs(
        workdir, p3_bb, p3_instr, pillar_bb, failing_bb, failing_instr_id
    )
    div_info = find_first_divergence(vpc0, vpc1) if vpc0 else None
    if div_info:
        ctx["divergence"] = {
            "vpc_log_label": div_label,
            "diverge_line_no": div_info["diverge_line_no"],
            "cycle_t0": div_info.get("cycle_t0"),
            "vpc_t0": div_info.get("vpc_t0"),
            "cycle_t1": div_info.get("cycle_t1"),
            "vpc_t1": div_info.get("vpc_t1"),
            "total_lines_t0": div_info["total_lines_t0"],
            "total_lines_t1": div_info["total_lines_t1"],
        }
        # Write divergence window file
        win_path = write_divergence_window(div_info, workdir)
        if win_path:
            ctx["divergence"]["window_file"] = win_path
    else:
        ctx["divergence"] = {"error": "VPC logs not found or identical", "vpc_log_label": div_label}

    return ctx


# ---------------------------------------------------------------------------
# Human-readable summary
# ---------------------------------------------------------------------------

def render_summary(context, result, display_dump_path=None):
    """Produce a human-readable plaintext summary of the reduction.

    display_dump_path: path to display_t0.elf.dump — objdump of the ELF generated
    by gen_truncated_elf(fs0, failing_bb), which keeps every instruction in the
    failing BB intact (only the CF terminator is replaced by a JAL).  This gives
    full disassembly of both the pillar BB and the complete leaker BB.
    When absent, falls back to the milesan instruction string (str field).
    """
    lines = []
    meta = context.get("meta", {})
    design = result.get("design", "?")
    seed   = result.get("seed", "?")

    lines.append("=== ONE-ZERO REDUCTION: {} seed {} ===".format(design, seed))
    lines.append("Total BBs: {}   Total instrs: {}   MMU: {}".format(
        meta.get("total_bbs"), meta.get("total_instrs"), meta.get("use_mmu")))
    lines.append("")

    # Leaker instruction — one-line callout for quick scan
    leaker = context.get("leaker", {})
    lines.append("--- Leaking instruction ---")
    lines.append("  {}".format(leaker.get("str", "?")))
    lines.append("  bytecode: {}   class: {}".format(
        leaker.get("bytecode_hex", "?"), leaker.get("class", "?")))
    lines.append("  bb={}  instr_local={}  fault_from_prev_bb={}".format(
        result.get("failing_bb_id"), result.get("failing_instr_id"),
        result.get("fault_from_prev_bb")))
    lines.append("")

    # Build paddr→line map from display_t0.elf.dump (covers both BBs fully)
    dump_map = _parse_objdump_file(display_dump_path) if display_dump_path else {}

    # Leaker paddr for marking
    leaker_paddr = None
    try:
        lp = leaker.get("paddr")
        if lp:
            leaker_paddr = int(lp, 16)
    except Exception:
        pass

    # Leaker BB — full disassembly using display dump
    lbb = context.get("leaker_bb", {})
    lbb_instrs = lbb.get("instructions", [])
    if lbb_instrs:
        lines.extend(_render_disasm_bb("LEAKER BB", lbb_instrs, dump_map,
                                       leaker_paddr=leaker_paddr))
    lines.append("")

    # Pillar BB — full disassembly using display dump
    pbb = context.get("pillar_bb")
    if pbb:
        pbb_instrs = pbb.get("instructions", [])
        if pbb_instrs:
            lines.extend(_render_disasm_bb("PILLAR BB", pbb_instrs, dump_map))
        lines.append("")

    # Intermediate BBs summary
    n_inter = context.get("n_intermediate_bbs")
    inter = context.get("intermediate_bbs", [])
    if n_inter:
        first_id = inter[0]["bb_id"]  if inter else "?"
        last_id  = inter[-1]["bb_id"] if inter else "?"
        lines.append(f"--- Intermediate BBs: {n_inter} (bb {first_id}..{last_id}) ---")
        for entry in inter:
            last = entry.get("last_instr", {})
            lines.append(f"  bb={entry['bb_id']:4d}  n={entry.get('n_instrs'):4}  "
                         f"priv={entry.get('priv_level')}  "
                         f"cf: {last.get('str', '?') if last else '?'}")
        lines.append("")

    # Divergence
    div = context.get("divergence", {})
    lines.append("--- VPC Divergence ---")
    if "error" not in div:
        lines.append(f"  Source log: {div.get('vpc_log_label')}")
        lines.append(f"  First divergence: line {div.get('diverge_line_no')} / "
                     f"t0={div.get('total_lines_t0')} lines  t1={div.get('total_lines_t1')} lines")
        lines.append(f"  t0: cycle={div.get('cycle_t0')}  vpc={div.get('vpc_t0')}")
        lines.append(f"  t1: cycle={div.get('cycle_t1')}  vpc={div.get('vpc_t1')}")
    else:
        lines.append(f"  {div.get('error')}")
    lines.append("")

    # Flags
    flags = context.get("flags", {})
    lines.append("--- Exploit-class flags ---")
    lines.append(f"  cross_priv={flags.get('cross_priv')}  "
                 f"leaker_priv={flags.get('leaker_priv')}  "
                 f"taint_source_privs={flags.get('taint_source_privs')}  "
                 f"pillar_priv={flags.get('pillar_priv')}")
    if meta.get("use_mmu"):
        lines.append(f"  cross_layout={flags.get('cross_layout')}  "
                     f"leaker_layout={flags.get('leaker_layout')}  "
                     f"taint_source_layouts={flags.get('taint_source_layouts')}  "
                     f"pillar_layout={flags.get('pillar_layout')}")
    lines.append("")

    # Artifacts
    artifacts = result.get("artifacts", {})
    lines.append("--- Artifacts ---")
    for key in ("t0", "t1"):
        art = artifacts.get(key, {})
        elf  = art.get("elf",  "?")
        dump = art.get("dump", "?")
        elf_sz  = art.get("elf_size",  "?")
        dump_sz = art.get("dump_size", "?")
        err = art.get("elf_error") or art.get("dump_error")
        if err:
            lines.append(f"  {key}: ERROR: {err}")
        else:
            lines.append(f"  {key}: {os.path.basename(elf)} ({elf_sz} B)  "
                         f"dump: {os.path.basename(dump)} ({dump_sz} B)")
    win = div.get("window_file")
    if win:
        lines.append(f"  divergence_window.txt: {win}")

    lines.append("")
    return "\n".join(lines)
