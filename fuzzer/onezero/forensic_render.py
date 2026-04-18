# Copyright 2026 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# Markdown renderer for one-zero forensic reports.  Kept separate from forensic.py
# so the format can iterate without re-running spike / parsing logs.


def _h(title):
    return f"\n## {title}\n"


def _fmt_tag(tag):
    return f"`{tag}`"


def render(forensic):
    """Render a forensic dict (from build_forensic) into a markdown report."""
    lines = []
    seed = forensic.get("seed", "?")
    design = forensic.get("design", "?")
    nopize = forensic.get("nopize_info") or {}
    flags = forensic.get("flags") or {}
    div = forensic.get("divergence") or {}
    gadget = forensic.get("gadget") or {}
    n_gadget = gadget.get("n_instrs") or 0
    n_nops = gadget.get("n_nops") or 0

    lines.append(f"# Forensic Report — {design} seed {seed}")
    lines.append("")
    lines.append(f"- Workdir: `{forensic.get('workdir')}`")
    lines.append(f"- Nopize active: **{forensic.get('nopize_active')}**  |  "
                 f"gadget size: **{nopize.get('gadget_size', n_gadget)}**  "
                 f"(n_nops_added = {nopize.get('n_nops_added', '?')}, "
                 f"cap_hit = {nopize.get('cap_hit', '?')}, "
                 f"sanity_check_ok = {nopize.get('sanity_check_ok', '?')})")

    # ── Section 1: Executive summary ────────────────────────────────────────
    lines.append(_h("1. Executive summary"))
    leaker = forensic.get("leaker_from_context") or {}
    lines.append(f"- **Leaker**: `{leaker.get('str', '?')}`")
    lines.append(f"    - class: `{leaker.get('class', '?')}`   "
                 f"paddr: `{leaker.get('paddr', '?')}`   "
                 f"priv: `{leaker.get('priv_level', '?')}`")
    lines.append(f"- **Failing BB / instr**: bb={forensic.get('failing_bb_id')}, "
                 f"instr={forensic.get('failing_instr_id')}, "
                 f"fault_from_prev_bb={forensic.get('fault_from_prev_bb')}")
    lines.append(f"- **Pillar BB**: {forensic.get('pillar_bb_id')}")
    lines.append(f"- **Cross-priv**: {flags.get('cross_priv')}   "
                 f"leaker_priv={flags.get('leaker_priv')}   "
                 f"taint_source_privs={flags.get('taint_source_privs')}   "
                 f"pillar_priv={flags.get('pillar_priv')}")
    if flags.get("leaker_layout") is not None or flags.get("pillar_layout") is not None:
        lines.append(f"- **Cross-layout**: {flags.get('cross_layout')}   "
                     f"leaker_layout={flags.get('leaker_layout')}   "
                     f"taint_source_layouts={flags.get('taint_source_layouts')}   "
                     f"pillar_layout={flags.get('pillar_layout')}")
    lines.append(f"- **VPC divergence**: line {div.get('diverge_line_no')}  "
                 f"(t0 cycle={div.get('cycle_t0')} pc={div.get('vpc_t0')}; "
                 f"t1 cycle={div.get('cycle_t1')} pc={div.get('vpc_t1')})")
    lines.append(f"- **Source log**: `{div.get('vpc_log_label')}`")

    # ── Section 2: Minimal gadget listing (headline classification section) ─
    lines.append(_h("2. Minimal gadget listing (post-Phase-4)"))
    items = gadget.get("items") or []
    if not items:
        lines.append("_No gadget items available._")
    else:
        lines.append(f"Surviving instructions (non-NOP): **{n_gadget}**   "
                     f"NOPized: {n_nops}")
        lines.append("")
        lines.append("```")
        prev_bb = None
        for item in items:
            bb_id = item.get("bb_id")
            if prev_bb != bb_id:
                lines.append(f"--- bb {bb_id}  priv={item.get('priv')} ---")
                prev_bb = bb_id
            tag = item.get("tag") or ("NOP" if item.get("is_nop") else "SETUP")
            marker = "[NOP]" if item.get("is_nop") else f"[{tag:>12}]"
            paddr = item.get("paddr") or "?"
            s = item.get("str") or "?"
            lines.append(f"  {paddr:>12}  {marker}  {s}")
        lines.append("```")

    # ── Section 3: Leaker instruction (annotated) ───────────────────────────
    lines.append(_h("3. Leaker instruction (annotated)"))
    la = forensic.get("leaker_annotated") or {}
    if la:
        lines.append(f"- Disasm: `{la.get('disasm')}`")
        lines.append(f"- Class: `{la.get('class')}`   mnemonic: `{la.get('mnemonic')}`")
        lines.append(f"- paddr: `{la.get('paddr')}`   priv: `{la.get('priv')}`")
        lines.append(f"- rd: `{la.get('rd')}`   rs1: `{la.get('rs1')}`   rs2: `{la.get('rs2')}`")
        # Dataflow slice gives us the last-writers
        slc = forensic.get("dataflow_slice") or []
        if slc:
            lines.append("")
            lines.append("**Operand last-writers (depth-0 hops):**")
            for hop in slc:
                if hop.get("depth", 0) != 0:
                    continue
                p = hop.get("producer") or {}
                if not p:
                    lines.append(f"- `{hop.get('via')}` (x{hop.get('reg')}): producer not in span")
                else:
                    lines.append(f"- `{hop.get('via')}` (x{hop.get('reg')}): "
                                 f"`{p.get('str')}`  [{p.get('tag')}]")
    else:
        lines.append("_Leaker annotation unavailable._")

    # ── Section 4: Divergence point ────────────────────────────────────────
    lines.append(_h("4. Divergence point"))
    if div and "error" not in div:
        lines.append(f"- First diverging VPC-log line: **{div.get('diverge_line_no')}** "
                     f"(of t0={div.get('total_lines_t0')}, t1={div.get('total_lines_t1')})")
        lines.append(f"- t0 at divergence: cycle=`{div.get('cycle_t0')}`  pc=`{div.get('vpc_t0')}`")
        lines.append(f"- t1 at divergence: cycle=`{div.get('cycle_t1')}`  pc=`{div.get('vpc_t1')}`")
        wf = forensic.get("divergence_window_file")
        if wf:
            lines.append(f"- ±10-line window: see `{wf}`")
    else:
        lines.append(f"_{div.get('error', 'divergence info unavailable')}_")

    # ── Section 5: Architectural state diff (trichotomy) ────────────────────
    lines.append(_h("5. Architectural state diff (spike t0 vs t1)"))
    adiff = forensic.get("arch_diff") or {}
    stp = forensic.get("spike_trace_pair") or {}
    lines.append(f"- ELF source for spike replay: **{stp.get('elf_source', 'n/a')}**   "
                 f"(trace lens: t0={stp.get('len_t0', 0)}, t1={stp.get('len_t1', 0)})")
    klass = adiff.get("class")
    if klass == "arch-visible":
        lines.append("")
        lines.append("**Verdict: arch-visible divergence** — spike sees a differing committed PC stream.")
        lines.append(f"- First diff idx: {adiff.get('first_diff_idx')}   "
                     f"t0 pc=`{adiff.get('first_diff_pc_t0')}`   "
                     f"t1 pc=`{adiff.get('first_diff_pc_t1')}`")
        if adiff.get("reason"):
            lines.append(f"- Note: {adiff['reason']}   len t0={adiff.get('len_t0')}   len t1={adiff.get('len_t1')}")
    elif klass == "microarch-only":
        lines.append("")
        lines.append("**Verdict: microarch-only divergence** — spike sees identical PC stream but differing register values.  "
                     "Likely speculative / transient execution side channel.")
        lines.append(f"- First value-diff at idx {adiff.get('first_value_diff_idx')} (pc=`{adiff.get('pc')}`): "
                     f"t0=`{adiff.get('val_t0')}`, t1=`{adiff.get('val_t1')}`")
    elif klass == "spike-identical":
        lines.append("")
        lines.append("**Verdict: spike-vs-RTL mismatch** — spike sees no divergence at all, yet VPC logs diverged.  "
                     "This divergence is purely microarchitectural; spike cannot explain it.  "
                     "Pending microarch-signal extension (future work).")
    else:
        lines.append(f"_Spike arch diff unavailable ({adiff.get('reason', klass)})_")

    # ── Section 6: Backward dataflow slice ──────────────────────────────────
    lines.append(_h("6. Backward dataflow slice from leaker"))
    slc = forensic.get("dataflow_slice") or []
    if slc:
        lines.append("```")
        for hop in slc:
            d = hop.get("depth", 0)
            reg = hop.get("reg")
            via = hop.get("via")
            p = hop.get("producer") or {}
            term = hop.get("terminator") or ""
            if p:
                lines.append(f"{'  '*d}└─ x{reg} (via {via}) ← [{p.get('tag')}] "
                             f"{p.get('paddr')}  {p.get('str')}{'  **TERM:' + term + '**' if term else ''}")
            else:
                lines.append(f"{'  '*d}└─ x{reg} (via {via}) ← (not in span)")
        lines.append("```")
    else:
        lines.append("_No dataflow slice (leaker has no register operands or slice empty)._")

    # ── Section 7: Control-flow timeline ────────────────────────────────────
    lines.append(_h("7. Control-flow timeline (pillar → leaker BBs)"))
    tl = forensic.get("cf_timeline") or []
    if tl:
        lines.append("| bb_id | first_pc | priv | n_instrs | exit |")
        lines.append("|---|---|---|---|---|")
        for e in tl:
            lines.append(f"| {e.get('bb_id')} | `{e.get('first_pc')}` | "
                         f"{e.get('priv')} | {e.get('n_instrs')} | {e.get('exit_kind')} |")
    else:
        lines.append("_CF timeline unavailable._")

    # ── Section 8: Exceptions / fault events ────────────────────────────────
    lines.append(_h("8. Exception / fault events in gadget"))
    exc = forensic.get("exceptions") or []
    if exc:
        for e in exc:
            lines.append(f"- bb{e.get('bb_id')}.{e.get('instr_idx')}  "
                         f"`{e.get('mnemonic')}`  [{e.get('class')}]  "
                         f"priv={e.get('priv')}  paddr=`{e.get('paddr')}`  — `{e.get('str')}`")
    else:
        lines.append("_No synchronous exception-triggering instructions in the gadget._")

    # ── Section 9: Memory access log ────────────────────────────────────────
    lines.append(_h("9. Memory access log"))
    mem = forensic.get("memory_log") or []
    if mem:
        lines.append("| bb.i | paddr | dir | priv | mnemonic | str |")
        lines.append("|---|---|---|---|---|---|")
        for e in mem:
            lines.append(f"| bb{e.get('bb_id')}.{e.get('instr_idx')} | "
                         f"`{e.get('paddr')}` | {e.get('direction')} | "
                         f"{e.get('priv')} | `{e.get('mnemonic')}` | `{e.get('str')}` |")
    else:
        lines.append("_No loads/stores in the gadget._")

    # ── Section 10: Taint-source consumers ──────────────────────────────────
    lines.append(_h("10. Taint-source consumers (privilege heuristic)"))
    tsc = forensic.get("taint_source_consumers") or []
    if tsc:
        lines.append(f"Privilege levels with tainted data: `{flags.get('taint_source_privs')}`")
        lines.append("")
        for e in tsc:
            lines.append(f"- bb{e.get('bb_id')}.{e.get('instr_idx')}  "
                         f"priv=**{e.get('priv')}**  `{e.get('mnemonic')}` → consumer reg x{e.get('consumer_reg')}  "
                         f"— `{e.get('str')}`")
    else:
        lines.append("_No loads executing in a taint-source privilege level found in the gadget._")

    lines.append("")
    lines.append("---")
    lines.append("_Generated by onezero/forensic_render.py_")
    return "\n".join(lines) + "\n"
