# Copyright 2023 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This module provides facilities for reducing test cases

from common.designcfgs import get_design_march_flags_nocompressed, get_design_boot_addr, get_design_cascade_path
from common.spike import SPIKE_STARTADDR

from cascade.basicblock import gen_basicblocks
from cascade.finalblock import finalblock
from cascade.mmu_utils import phys2virt, PAGE_ALIGNMENT_MASK, virt2phys
from cascade.cfinstructionclasses import filter_reg_traceback, is_placeholder, SpeculativeInstructionEncapsulator
from cascade.cfinstructionclasses_t0 import JALInstruction_t0, RegImmInstruction_t0, JALRInstruction_t0, ImmRdInstruction_t0, RegImmInstruction_t0, R12DInstruction_t0, BranchInstruction_t0
from cascade.fuzzsim import SimulatorEnum, runtest_simulator
from cascade.spikeresolution import gen_elf_from_bbs, gen_regdump_reqs_reduced, gen_ctx_regdump_reqs, run_trace_regs_at_pc_locs, spike_resolution, gen_regdump_reqs_all_rds
from cascade.contextreplay import SavedContext, gen_context_setter
from cascade.gen_ctxt_final_block import *
from cascade.privilegestate import PrivilegeStateEnum

from params.runparams import DO_ASSERT, NO_REMOVE_TMPFILES
from params.fuzzparams import TAINT_EN, USE_SPIKE_INTERM_ELF, RELOCATOR_REGISTER_ID, IGNORE_TAINT_MISMATCH, ASSERT_EXEC_IN_TAINT_SINK_PRIV, INSERT_SPECTRE_GADGETS, USE_MMU

from rv.asmutil import li_into_reg, to_unsigned

from drfuzz_mem.check_isa_sim_taint import FailTypeEnum

from copy import deepcopy, copy
import itertools
import os
import random
import shutil
import subprocess
import time
from pathlib import Path

REDUCTION_SIMULATOR = SimulatorEnum.VERILATOR
NOPIZE_SANDWICH_INSTRUCTIONS = False
FLATTEN_SANDWICH_INSTRUCTIONS = False
REDUCE_TAINT = False
FIND_PILLARS = False
# @brief since stopsig and regdump addr are vitrual, the final block also needs some context, mainly, the translation scheme of stores in the current priviledge
def gen_ctxt_finalbock(priv_level, layout_id, fuzzerstate, bb_id, instr_id):
    assert bb_id != -1

    # Handle the case where the instr id is the last 
    if instr_id == -1: 
        instr_id = len(fuzzerstate.instr_objs_seq[bb_id]) - 1
    # We want to start looking at the instruction before the one we overwrite, if we overwrite an instruction
    instr_id = instr_id - 1
    # If it was the first instr in a block, we go to the previous block
    if instr_id == -1:
        bb_id -= 1
        instr_id = len(fuzzerstate.instr_objs_seq[bb_id]) - 1

    # Update layout and priviledge, the real layout is used in case we are in machine mode
    fuzzerstate.privilegestate.privstate = priv_level
    fuzzerstate.effective_curr_layout = layout_id
    if priv_level == PrivilegeStateEnum.MACHINE:
        fuzzerstate.real_curr_layout = get_last_real_layout(fuzzerstate, bb_id, instr_id)
    else:
        fuzzerstate.real_curr_layout = fuzzerstate.effective_curr_layout

    # Get the last mpp
    fuzzerstate.privilegestate.curr_mstatus_mpp = get_last_mpp(fuzzerstate, bb_id, instr_id)
    # Update sum and mprv bits
    sum_bit, mprv_bit = get_last_sum_mprv(fuzzerstate, bb_id, instr_id)
    fuzzerstate.status_sum_mprv = (sum_bit, mprv_bit)

    print(f"Generating new final block, sum/mstatus: {fuzzerstate.status_sum_mprv}, priv: {priv_level}, real_l: {fuzzerstate.real_curr_layout}, eff_l: {layout_id}, mpp: ", fuzzerstate.privilegestate.curr_mstatus_mpp)
    # Generate a new final block to handle the case where the priviledge/translation cahnged in the final block
    fuzzerstate.final_bb = finalblock(fuzzerstate, fuzzerstate.design_name)


# Used for removing the first BBs and instructions.
def _save_ctx_and_jump_to_pillar_specific_instr(fuzzerstate, index_first_bb_to_consider: int, index_first_instr_to_consider: int):
    print(f"Saving context and jumping to pillar-specific instruction {index_first_bb_to_consider}:{index_first_instr_to_consider}...")
    spikereduce_elfpath = gen_elf_from_bbs(fuzzerstate, False, "spikereduce_savectx", f"{fuzzerstate.instance_to_str()}_{index_first_bb_to_consider}_{index_first_instr_to_consider}", SPIKE_STARTADDR)
    print(f"elf at {spikereduce_elfpath}")

    # tgt_addr_layout, tgt_addr_priv = get_last_bb_layout_and_priv(fuzzerstate, index_first_bb_to_consider, index_first_instr_to_consider, False)
    # tgt_pc = phys2virt((fuzzerstate.bb_start_addr_seq[index_first_bb_to_consider] + 4*index_first_instr_to_consider + SPIKE_STARTADDR), tgt_addr_priv, tgt_addr_layout, fuzzerstate, False)
    # final_addr = phys2virt((fuzzerstate.final_bb_base_addr+SPIKE_STARTADDR), fuzzerstate.privilegestate.privstate, fuzzerstate.effective_curr_layout, fuzzerstate, False)
    target_instr = fuzzerstate.instr_objs_seq[index_first_bb_to_consider][index_first_instr_to_consider]
    tgt_pc =  target_instr.vaddr if USE_MMU else target_instr.paddr
    assert tgt_pc is not None
    tgt_addr_layout = target_instr.va_layout
    assert tgt_addr_layout is not None
    tgt_addr_priv = target_instr.priv_level
    tgt_addr_priv is not None

    final_instr = fuzzerstate.instr_objs_seq[-1][-1]
    final_addr = final_instr.vaddr if USE_MMU else final_instr.paddr
    print(f"THE TARGET PC IS {hex((tgt_pc))} ({hex(final_instr.paddr)})")
    print(f"TARGET LAYOUT IS {tgt_addr_layout}")
    print(f"TARGET PRIV IS {tgt_addr_priv}")

    ctx_regdump_reqs, storenumbytes, insts = gen_ctx_regdump_reqs(fuzzerstate, index_first_bb_to_consider, index_first_instr_to_consider, tgt_pc)

    dumpedvals = run_trace_regs_at_pc_locs(fuzzerstate.instance_to_str(), spikereduce_elfpath, get_design_march_flags_nocompressed(fuzzerstate.design_name), SPIKE_STARTADDR, ctx_regdump_reqs, False, final_addr, fuzzerstate.num_pickable_floating_regs if fuzzerstate.design_has_fpu else 0, fuzzerstate.design_has_fpud)

    if TAINT_EN and DO_ASSERT:
        dumpedvals_in_situ, dumpedvals_t0 = fuzzerstate.get_regdumps_from_reqs(ctx_regdump_reqs, True, None, False, True)
        assert len(dumpedvals_in_situ) == len(dumpedvals), f"Dumped {len(dumpedvals)} in spike but got only {len(dumpedvals_in_situ)} from in-situ."
        # for idx, (in_situ_d, in_situ_d_t0, spike_d) in enumerate(zip(dumpedvals_in_situ, dumpedvals_t0, dumpedvals)):
            # assert in_situ_d == spike_d or in_situ_d_t0 == 0, f"Mismatch between in-situ simulation and spike at addr {hex(ctx_regdump_reqs[idx][0])} for reg ID {ctx_regdump_reqs[idx][2]}: {filter_reg_traceback(ctx_regdump_reqs[idx][2],ctx_regdump_reqs[idx][0],fuzzerstate,spike_d).get_str()}: {hex(in_situ_d)} != {hex(spike_d)}, {hex(in_situ_d_t0)}" # Some dumps differ between in-situ and spike (e.g. generated and consumed registers)
    del ctx_regdump_reqs

    # Remove the ELF
    if not NO_REMOVE_TMPFILES:
        os.remove(spikereduce_elfpath)
        del spikereduce_elfpath

    # Generate the context setter
    NUM_CSRS = 13 + int(not fuzzerstate.is_design_64bit) + 2*USE_MMU # includes the privilege request. +1 for minstreth if 32-bit
    if DO_ASSERT:
        assert (len(dumpedvals) - NUM_CSRS - fuzzerstate.num_pickable_floating_regs - fuzzerstate.num_pickable_regs) % 2 == 0, "The number of dumps for memory operations must be even: one address for one value."

    # Get the saved context
    curr_id_in_dumpedvals = 0
    num_stores_found = (len(dumpedvals) - NUM_CSRS - fuzzerstate.num_pickable_floating_regs - fuzzerstate.num_pickable_regs) // 2
    saved_stores = dict()
    saved_stores_t0 = dict()

    curr_id_in_storenumbytes = 0
    for _ in range(num_stores_found):
        for byte_id in range(storenumbytes[curr_id_in_storenumbytes]):
            vaddr = dumpedvals[curr_id_in_dumpedvals] + byte_id
            if insts[curr_id_in_dumpedvals].priv_level == PrivilegeStateEnum.MACHINE:
                addr = vaddr - SPIKE_STARTADDR
            else:
                addr = virt2phys(vaddr, insts[curr_id_in_dumpedvals].priv_level, insts[curr_id_in_dumpedvals].va_layout, fuzzerstate)
            # print(f"paddr: {hex(addr)}, vadd: {hex(vaddr)}, instr: {insts[curr_id_in_dumpedvals].get_str()}")
            assert addr > 0 and addr < fuzzerstate.memsize, f"Address {hex(addr)} exceeds memory, maybe virtual?"
            val = (dumpedvals[curr_id_in_dumpedvals+1] >> (8*byte_id)) & 0xFF
            val_t0 = (dumpedvals_t0[curr_id_in_dumpedvals+1] >> (8*byte_id)) & 0xFF
            saved_stores[addr] = val
            saved_stores_t0[addr] = val_t0 # We only care for the taints of the stores, not CSRs as those are untainted by construction.
        curr_id_in_storenumbytes += 1
        curr_id_in_dumpedvals += 2
    csr_count_fordebug = 0
    saved_fcsr = dumpedvals[curr_id_in_dumpedvals]
    curr_id_in_dumpedvals += 1
    csr_count_fordebug += 1
    saved_mepc = dumpedvals[curr_id_in_dumpedvals]
    curr_id_in_dumpedvals += 1
    csr_count_fordebug += 1
    saved_sepc = dumpedvals[curr_id_in_dumpedvals]
    curr_id_in_dumpedvals += 1
    csr_count_fordebug += 1
    saved_mcause = dumpedvals[curr_id_in_dumpedvals]
    curr_id_in_dumpedvals += 1
    csr_count_fordebug += 1
    saved_scause = dumpedvals[curr_id_in_dumpedvals]
    curr_id_in_dumpedvals += 1
    csr_count_fordebug += 1
    saved_mscratch = dumpedvals[curr_id_in_dumpedvals]
    curr_id_in_dumpedvals += 1
    csr_count_fordebug += 1
    saved_sscratch = dumpedvals[curr_id_in_dumpedvals]
    curr_id_in_dumpedvals += 1
    csr_count_fordebug += 1
    saved_mtvec = dumpedvals[curr_id_in_dumpedvals]
    curr_id_in_dumpedvals += 1
    csr_count_fordebug += 1
    saved_stvec = dumpedvals[curr_id_in_dumpedvals]
    curr_id_in_dumpedvals += 1
    csr_count_fordebug += 1
    saved_medeleg = dumpedvals[curr_id_in_dumpedvals]
    curr_id_in_dumpedvals += 1
    csr_count_fordebug += 1
    saved_mstatus = dumpedvals[curr_id_in_dumpedvals]
    curr_id_in_dumpedvals += 1
    csr_count_fordebug += 1
    saved_minstret = dumpedvals[curr_id_in_dumpedvals]
    curr_id_in_dumpedvals += 1
    csr_count_fordebug += 1
    if USE_MMU:
        saved_satp = dumpedvals[curr_id_in_dumpedvals]
        curr_id_in_dumpedvals += 1
        csr_count_fordebug += 1
        saved_rprod_mask = dumpedvals[curr_id_in_dumpedvals]
        curr_id_in_dumpedvals += 1
        csr_count_fordebug += 1
    else: 
        saved_satp = None
        saved_rprod_mask = None
    if not fuzzerstate.is_design_64bit:
        saved_minstreth = dumpedvals[curr_id_in_dumpedvals]
        curr_id_in_dumpedvals += 1
        csr_count_fordebug += 1
    else:
        saved_minstreth = None

    # Parse the privilege level
    saved_privilege_char = dumpedvals[curr_id_in_dumpedvals]
    if saved_privilege_char == 'M':
        saved_privilege = PrivilegeStateEnum.MACHINE
    elif saved_privilege_char == 'S':
        saved_privilege = PrivilegeStateEnum.SUPERVISOR
    elif saved_privilege_char == 'U':
        saved_privilege = PrivilegeStateEnum.USER
    else:
        raise ValueError("Unknown privilege level: " + str(saved_privilege_char))
    csr_count_fordebug += 1
    curr_id_in_dumpedvals += 1

    if DO_ASSERT:
        assert csr_count_fordebug == NUM_CSRS, "The number of CSRs found is not the expected one. Found: " + str(csr_count_fordebug) + ", expected: " + str(num_csrs)

    if fuzzerstate.design_has_fpu:
        raise NotImplementedError("fpu not implemented.")
        # We only take the low part of the floats, because (currently) spike represents them on 16 bytes.
        if fuzzerstate.design_has_fpud:
            saved_fregvals = list(map(lambda x: ((1 << 64) -1) & x, dumpedvals[curr_id_in_dumpedvals:curr_id_in_dumpedvals+fuzzerstate.num_pickable_floating_regs]))
        else:
            saved_fregvals = list(map(lambda x: ((1 << 32) -1) & x, dumpedvals[curr_id_in_dumpedvals:curr_id_in_dumpedvals+fuzzerstate.num_pickable_floating_regs]))
    else:
        saved_fregvals = []

    curr_id_in_dumpedvals += fuzzerstate.num_pickable_floating_regs
    saved_regvals  = dumpedvals[curr_id_in_dumpedvals:curr_id_in_dumpedvals+fuzzerstate.num_pickable_regs]
    saved_regvals_t0  = dumpedvals_t0[curr_id_in_dumpedvals:curr_id_in_dumpedvals+fuzzerstate.num_pickable_regs]

    if DO_ASSERT:
        assert curr_id_in_dumpedvals + fuzzerstate.num_pickable_regs == len(dumpedvals)
    saved_context = SavedContext(saved_fcsr,
                                    saved_mepc,
                                    saved_sepc,
                                    saved_mcause,
                                    saved_scause,
                                    saved_mscratch,
                                    saved_sscratch,
                                    saved_mtvec,
                                    saved_stvec,
                                    saved_medeleg,
                                    saved_mstatus,
                                    saved_minstret,
                                    saved_minstreth,
                                    saved_satp,
                                    saved_privilege,
                                    saved_stores,
                                    saved_stores_t0,
                                    saved_fregvals,
                                    None, # fp taint not supported yet
                                    saved_regvals,
                                    saved_regvals_t0,
                                    saved_rprod_mask)

    # fuzzerstate.init_new_ctxsv_bb()
    gen_context_setter(fuzzerstate, saved_context, fuzzerstate.bb_start_addr_seq[index_first_bb_to_consider] + index_first_instr_to_consider * 4, tgt_addr_layout, tgt_addr_priv) # NO_COMPRESSED
    # Jump from the last basic block to the context setter. For the first context setter, the last block is the initial block.
    old_jump = fuzzerstate.instr_objs_seq[fuzzerstate.last_bb_id_before_ctx_saver][-1]
    new_jump = JALInstruction_t0(fuzzerstate,"jal", 0, fuzzerstate.ctxsv_bb_base_addr - 4*(len(fuzzerstate.instr_objs_seq[fuzzerstate.last_bb_id_before_ctx_saver])-1)) # NO_COMPRESSED
    new_jump.paddr = old_jump.paddr
    new_jump.priv_level = old_jump.priv_level
    if USE_MMU:
        new_jump.vaddr = old_jump.vaddr
        new_jump.va_layout = old_jump.va_layout
    fuzzerstate.instr_objs_seq[fuzzerstate.last_bb_id_before_ctx_saver][-1] = new_jump
    # print(f"Replacing {old_jump.get_str()} with {new_jump.get_str()}")

    return fuzzerstate, tgt_addr_layout, tgt_addr_priv

# @param max_bb_id_to_consider: the number of BBs to consider, hence from 0 to len(fuzzerstate.instr_objs_seq)-1.
# @param max_instr_id_except_cf: the number of instructions in the bb `max_bb_id_to_consider` to consider in total, including the cf instruction that may be added (equivalently, the max instruction index to consider in the bb `max_bb_id_to_consider` when ignoring the cf instruction). -1 means that we only want the CF instruction. None means that we do not expect to do any replacement.
# @param index_first_bb_to_consider: the index of the first BB to consider. 1 if we remove no bb on the left side.
# @return test_fuzzerstate, rtl_elfpath, (finalintregvals_spikeresol[1:], finalfloatregvals_spikeresol), numinstrs
def gen_reduced_elf(fuzzerstate, max_bb_id_to_consider: int, max_instr_id_except_cf: int = None, index_first_bb_to_consider: int = 1, index_first_instr_to_consider: int = 0):
    # print(f"gen_reduced_elf with max_bb_id_to_consider: {max_bb_id_to_consider}, max_instr_id_except_cf: {max_instr_id_except_cf}, index_first_bb_to_consider: {index_first_bb_to_consider}, index_first_instr_to_consider: {index_first_instr_to_consider}")
    if DO_ASSERT:
        assert max_bb_id_to_consider >= 0
        assert max_bb_id_to_consider < len(fuzzerstate.instr_objs_seq), f"Expected max_bb_id_to_consider `{max_bb_id_to_consider}` <= len(fuzzerstate.instr_objs_seq) `{len(fuzzerstate.instr_objs_seq)}`"
        assert index_first_bb_to_consider >= 0
        assert index_first_bb_to_consider <= max_bb_id_to_consider or max_bb_id_to_consider == 0, f"index_first_bb_to_consider: `{index_first_bb_to_consider}`, max_bb_id_to_consider: `{max_bb_id_to_consider}`"

    max_instr_id_except_speculative = len([instr for instr in fuzzerstate.instr_objs_seq[max_bb_id_to_consider] if not isinstance(instr, SpeculativeInstructionEncapsulator)])

    if max_bb_id_to_consider == 0:
        return False
    if max_instr_id_except_cf is None:
        max_instr_id_except_cf = len(fuzzerstate.instr_objs_seq[max_bb_id_to_consider])
        # print(f"max_instr_id_except_cf: {max_instr_id_except_cf}, {fuzzerstate.instr_objs_seq[max_bb_id_to_consider][max_instr_id_except_cf-1].get_str()}")
    if DO_ASSERT:
        if max_instr_id_except_cf is not None:
            assert max_instr_id_except_cf >= -1, f"Expected max_instr_id_except_cf `{max_instr_id_except_cf}` >= -1"  # if -1, then it means that we only want the CF instruction.
            assert max_instr_id_except_cf <= len(fuzzerstate.instr_objs_seq[max_bb_id_to_consider]), f"Expected `{max_instr_id_except_cf}` <= `{len(fuzzerstate.instr_objs_seq[max_bb_id_to_consider])}-1`"
        # Check that we do not remove beyond the buggy instruction
        if index_first_bb_to_consider == max_bb_id_to_consider and max_instr_id_except_cf is not None and index_first_instr_to_consider is not None:
            assert max_instr_id_except_cf+1 >= index_first_instr_to_consider, f"Expected max_instr_id_except_cf+1 `{max_instr_id_except_cf+1}` >= index_first_instr_to_consider `{index_first_instr_to_consider}`"
            assert index_first_instr_to_consider <= len(fuzzerstate.instr_objs_seq[index_first_bb_to_consider])-1, f"Expected `{index_first_instr_to_consider}` <= `{len(fuzzerstate.instr_objs_seq[index_first_bb_to_consider])-1}`"

    ###
    # Remove the last basic blocks
    ###

    # Copy the fuzzerstate. Maybe it is an overkill.
    test_fuzzerstate = deepcopy(fuzzerstate)
    del fuzzerstate # Just for safety. We will not need fuzzerstate anymore in this function

    # test_fuzzerstate.intregpickstate.restore_state(test_fuzzerstate.saved_reg_states[max_bb_id_to_consider])
    test_fuzzerstate.restore_states(max_bb_id_to_consider)
    # test_fuzzerstate.reset_after_execution()

    if DO_ASSERT:
        if isinstance(test_fuzzerstate.instr_objs_seq[max_bb_id_to_consider][-1], JALInstruction_t0):
            assert test_fuzzerstate.memsize <= 1 << 20, "The whole memory cannot be addressed with JAL."

    ###
    # Remove the last instructions in the last basic block
    ###

    # Pop intermediate cf-instructions if required 
    if max_instr_id_except_cf < max_instr_id_except_speculative:
        last_instr = test_fuzzerstate.instr_objs_seq[max_bb_id_to_consider][max_instr_id_except_cf+1]
        new_jal = JALInstruction_t0(test_fuzzerstate, "jal", 0, test_fuzzerstate.final_bb_base_addr-last_instr.paddr+SPIKE_STARTADDR)
        print(f"Replacig {last_instr.get_str()} with {new_jal.get_str()}")
        new_jal.paddr = last_instr.paddr
        new_jal.priv_level = last_instr.priv_level
        if USE_MMU:
            new_jal.vaddr = last_instr.vaddr
            new_jal.va_layout = last_instr.va_layout

        last_addr_layout, last_addr_priv = get_priv_and_layout_after_instruction(last_instr)
        gen_ctxt_finalbock(last_addr_priv, last_addr_layout, test_fuzzerstate, max_bb_id_to_consider, max_instr_id_except_cf)

        test_fuzzerstate.instr_objs_seq[max_bb_id_to_consider][max_instr_id_except_cf+1] = new_jal
        test_fuzzerstate.instr_objs_seq = test_fuzzerstate.instr_objs_seq[:max_bb_id_to_consider+1]
        test_fuzzerstate.instr_objs_seq[max_bb_id_to_consider] = test_fuzzerstate.instr_objs_seq[max_bb_id_to_consider][:max_instr_id_except_cf+2]
    
    # Pop speculative instructions. We don't need a new JAL as we can use the original jump/branch.
    elif max_instr_id_except_cf < len(test_fuzzerstate.instr_objs_seq[max_bb_id_to_consider]):
        assert INSERT_SPECTRE_GADGETS
        assert max_instr_id_except_cf >=  max_instr_id_except_speculative
        last_instr = test_fuzzerstate.instr_objs_seq[max_bb_id_to_consider][max_instr_id_except_cf+1]
        assert isinstance(last_instr, SpeculativeInstructionEncapsulator)
        last_addr_layout = last_instr.va_layout
        last_addr_priv = last_instr.priv_level
        gen_ctxt_finalbock(last_addr_priv, last_addr_layout, test_fuzzerstate, max_bb_id_to_consider, max_instr_id_except_cf)
        test_fuzzerstate.instr_objs_seq = test_fuzzerstate.instr_objs_seq[:max_bb_id_to_consider+1]
        test_fuzzerstate.instr_objs_seq[max_bb_id_to_consider] = test_fuzzerstate.instr_objs_seq[max_bb_id_to_consider][:max_instr_id_except_cf+2]
    # Remove the cf-ambiguous instruction
    else:
        # last_addr_layout, last_addr_priv = get_last_bb_layout_and_priv(test_fuzzerstate, max_bb_id_to_consider, -1, True)
        last_instr = test_fuzzerstate.instr_objs_seq[max_bb_id_to_consider][max_instr_id_except_speculative-1]
        new_jal = JALInstruction_t0(test_fuzzerstate, "jal", 0, test_fuzzerstate.final_bb_base_addr-last_instr.paddr+SPIKE_STARTADDR)
        print(f"Replacig {last_instr.get_str()} with {new_jal.get_str()}")
        new_jal.paddr = last_instr.paddr
        new_jal.priv_level = last_instr.priv_level
        if USE_MMU:
            new_jal.vaddr = last_instr.vaddr
            new_jal.va_layout = last_instr.va_layout

        last_addr_layout = last_instr.va_layout
        last_addr_priv = last_instr.priv_level
        gen_ctxt_finalbock(last_addr_priv, last_addr_layout, test_fuzzerstate, max_bb_id_to_consider, -1)

        test_fuzzerstate.instr_objs_seq[max_bb_id_to_consider][max_instr_id_except_speculative-1] = new_jal
        test_fuzzerstate.instr_objs_seq = test_fuzzerstate.instr_objs_seq[:max_bb_id_to_consider+1]

    test_fuzzerstate.bb_start_addr_seq = test_fuzzerstate.bb_start_addr_seq[:max_bb_id_to_consider+1]


    ###
    # Remove the first basic blocks and instructions
    ###

    if index_first_bb_to_consider > 1 or index_first_instr_to_consider > 0:
        # First, we must record the context in the end of the last removed bb and after the correct number of instructions in that bb
        # storenumbytes is a list which, for each store operation, returns the number of bytes stored
        test_fuzzerstate, ctxt_exit_layout, ctxt_exit_prv  = _save_ctx_and_jump_to_pillar_specific_instr(test_fuzzerstate, index_first_bb_to_consider, index_first_instr_to_consider)
        spikereduce_elfpath = gen_elf_from_bbs(test_fuzzerstate, False, "spikereduce_reducedstart", f"{test_fuzzerstate.instance_to_str()}_{max_bb_id_to_consider}_{max_instr_id_except_cf}_{index_first_bb_to_consider}_{index_first_instr_to_consider}", SPIKE_STARTADDR)
    else:
        ctxt_exit_layout, ctxt_exit_prv = -1, PrivilegeStateEnum.MACHINE
        spikereduce_elfpath = gen_elf_from_bbs(test_fuzzerstate, False, "spikereduce", f"{test_fuzzerstate.instance_to_str()}_{max_bb_id_to_consider}_{max_instr_id_except_cf}_{index_first_bb_to_consider}_{index_first_instr_to_consider}", SPIKE_STARTADDR)
        

    ###
    # Generate the ELF for RTL
    ###

    regdump_reqs = gen_regdump_reqs_reduced(test_fuzzerstate, max_bb_id_to_consider, min(max_instr_id_except_cf, max_instr_id_except_speculative)+1, index_first_bb_to_consider, index_first_instr_to_consider)

    final_addr = test_fuzzerstate.final_bb_base_addr+SPIKE_STARTADDR

    if USE_MMU:
    # Generate the translated last address
        final_addr = phys2virt(final_addr, last_addr_priv, last_addr_layout, test_fuzzerstate, False)

    # This is actually only needed for generating the final reg and freg values iirc.
    _, (finalintregvals_spikeresol, finalfloatregvals_spikeresol) = run_trace_regs_at_pc_locs(test_fuzzerstate.instance_to_str(), spikereduce_elfpath, get_design_march_flags_nocompressed(test_fuzzerstate.design_name), SPIKE_STARTADDR, regdump_reqs, True, final_addr, test_fuzzerstate.num_pickable_floating_regs if test_fuzzerstate.design_has_fpu else 0, test_fuzzerstate.design_has_fpud)
    
    


    # Retrieves the rd stream throughout execution to compare to in-situ simulation, only for safety.
    rd_regdump_reqs = gen_regdump_reqs_all_rds(test_fuzzerstate, index_first_bb_to_consider=index_first_bb_to_consider, first_instr_id_in_first_bb_to_consider=index_first_instr_to_consider)
    rd_regvals = run_trace_regs_at_pc_locs(test_fuzzerstate.instance_to_str(), spikereduce_elfpath, get_design_march_flags_nocompressed(test_fuzzerstate.design_name), SPIKE_STARTADDR, rd_regdump_reqs, False, final_addr, test_fuzzerstate.num_pickable_floating_regs if test_fuzzerstate.design_has_fpu else 0, test_fuzzerstate.design_has_fpud)

    rtl_elfpath = spikereduce_elfpath

    # To reduce the timeout duration, we compute the (approx) expected number of instructions
    numinstrs = len(test_fuzzerstate.final_bb)
    for bb in test_fuzzerstate.instr_objs_seq[:max_bb_id_to_consider+1]:
        numinstrs += len(bb)

    # We delete the instructions only here as the array size is changed.
    del test_fuzzerstate.instr_objs_seq[index_first_bb_to_consider][:index_first_instr_to_consider]
    test_fuzzerstate.bb_start_addr_seq[index_first_bb_to_consider] += 4*index_first_instr_to_consider # The bb start address changes since we remove the instructions before pillar instr.
    del test_fuzzerstate.instr_objs_seq[1:index_first_bb_to_consider]
    del test_fuzzerstate.bb_start_addr_seq[1:index_first_bb_to_consider]

    # Verify that the modifed program still has a valid taint propagation. 
    test_fuzzerstate.verify_program()

    return test_fuzzerstate, rtl_elfpath, (finalintregvals_spikeresol[1:], finalfloatregvals_spikeresol, rd_regdump_reqs, rd_regvals), numinstrs

# This module resolves a mismatch between design and simulation by finding the first basic block that causes a mismatch.
# @param failing_instr_id the index of the first instruction in the bb `failing_bb_id` that causes trouble, in the sense that when it is removed (and all the following instructions and bbs), the test case does not fail anymore. It is None if the failing instruction is actually the last one in the previous bb. Only used in the second step.
# @param index_first_bb_to_consider: only used in the second step
def is_mismatch(fuzzerstate, max_bb_id_to_consider: int, failing_instr_id: int = None, index_first_bb_to_consider: int = 1, index_first_instr_to_consider: int = 0, quiet: bool = True):
    # try:
    test_fuzzerstate, rtl_elfpath, expected_regvals_pairs, numinstrs = gen_reduced_elf(fuzzerstate, max_bb_id_to_consider, failing_instr_id, index_first_bb_to_consider, index_first_instr_to_consider)
    test_fuzzerstate.expected_regvals = expected_regvals_pairs
    test_fuzzerstate.rtl_elfpath = rtl_elfpath
    # except Exception as e:
    #     print(f"Error when generating reduced elf: `{e}`, for tuple: ({fuzzerstate.memsize}, design_name, {fuzzerstate.randseed}, {fuzzerstate.nmax_bbs})")
    #     raise Exception(e)
    if NO_REMOVE_TMPFILES and not quiet:
        print(f"Generated RTL elf: {rtl_elfpath}")

    del fuzzerstate

    is_success, exception = runtest_simulator(test_fuzzerstate, rtl_elfpath, expected_regvals_pairs, numinstrs, REDUCTION_SIMULATOR)

    if not is_success and exception.fail_type == FailTypeEnum.TAINT_MISMATCH and IGNORE_TAINT_MISMATCH:
        is_success = True # We triggered leakage, but we are reducing for an architectural bug, not leakage.

    if DO_ASSERT and not IGNORE_TAINT_MISMATCH:
        assert not (ASSERT_EXEC_IN_TAINT_SINK_PRIV and not is_success and test_fuzzerstate.compute_context_stats() == 0 and exception.fail_type == FailTypeEnum.TAINT_MISMATCH), f"Triggered leakage without executing in taint sink privilege. Aborting reduction."

    if quiet and not is_success:
        print(str(exception))
    return not is_success

def is_mismatch_t0(test_fuzzerstate,quiet = False):
    is_success, exception = runtest_simulator(test_fuzzerstate, test_fuzzerstate.rtl_elfpath,  test_fuzzerstate.expected_regvals)

    if not is_success and exception.fail_type == FailTypeEnum.TAINT_MISMATCH and IGNORE_TAINT_MISMATCH:
        is_success = True # We triggered leakage, but we are reducing for an architectural bug, not leakage.


    assert is_success or exception.fail_type == FailTypeEnum.TAINT_MISMATCH

    if not quiet and not is_success:
        print(str(exception))
    return not is_success


def _find_right_taint_bound(test_fuzzerstate):
    tainted_addresses = [i for i,j in test_fuzzerstate.memview.data_t0.items() if j != 0]
    left_bound = 0
    right_bound = len(tainted_addresses)
    while right_bound - left_bound > 1:
        tmp_fuzzerstate = deepcopy(test_fuzzerstate)
        if DO_ASSERT:
            assert right_bound > left_bound
        candidate_bound = left_bound + (right_bound - left_bound) // 2
        for tainted_addr in tainted_addresses[candidate_bound:]:
            tmp_fuzzerstate.memview.data_t0[tainted_addr] = 0
        print(f"Testing {candidate_bound}.")
        if is_mismatch_t0(tmp_fuzzerstate, len(tmp_fuzzerstate.instr_objs_seq)-1):
            print(f"Leakage detected.")
            right_bound = candidate_bound
        else:
            print(f"Leakage disappeared. Restoring taint.")
            left_bound = candidate_bound

    if DO_ASSERT:
        assert left_bound + 1 == right_bound
        tmp_fuzzerstate = deepcopy(test_fuzzerstate)
        for tainted_addr in tainted_addresses[right_bound:]:
            tmp_fuzzerstate.memview.data_t0[tainted_addr] = 0
        assert is_mismatch_t0(tmp_fuzzerstate, len(tmp_fuzzerstate.instr_objs_seq)-1), f"Failed detecting leakage with right bound {right_bound}"
    return right_bound


def _find_left_taint_bound(test_fuzzerstate):
    tainted_addresses = [i for i,j in test_fuzzerstate.memview.data_t0.items() if j != 0]
    left_bound = 0
    right_bound = len(tainted_addresses)
    while right_bound - left_bound > 1:
        tmp_fuzzerstate = deepcopy(test_fuzzerstate)
        if DO_ASSERT:
            assert right_bound > left_bound
        candidate_bound = left_bound + (right_bound - left_bound) // 2
        for tainted_addr in tainted_addresses[:candidate_bound]:
            tmp_fuzzerstate.memview.data_t0[tainted_addr] = 0
        print(f"Testing {candidate_bound}.")
        if is_mismatch_t0(tmp_fuzzerstate, len(tmp_fuzzerstate.instr_objs_seq)-1):
            print(f"Leakage detected.")
            left_bound = candidate_bound
        else:
            print(f"Leakage disappeared. Restoring taint.")
            right_bound = candidate_bound

    if DO_ASSERT:
        assert left_bound + 1 == right_bound
        tmp_fuzzerstate = deepcopy(test_fuzzerstate)
        for tainted_addr in tainted_addresses[:right_bound-1]:
            tmp_fuzzerstate.memview.data_t0[tainted_addr] = 0
        assert is_mismatch_t0(tmp_fuzzerstate, len(tmp_fuzzerstate.instr_objs_seq)-1), f"Failed detecting leakage with left bound {left_bound}"

    return right_bound-1


# Does not remove taints off immediates!
def reduce_taint(fuzzerstate):
    # Only need to generate one elf and then just reduce simsramtaint
    test_fuzzerstate, rtl_elfpath, expected_regvals_pairs, numinstrs = gen_reduced_elf(fuzzerstate, len(fuzzerstate.instr_objs_seq)-1)
    test_fuzzerstate.expected_regvals = expected_regvals_pairs
    test_fuzzerstate.rtl_elfpath = rtl_elfpath

    tainted_addresses = [i for i,j in test_fuzzerstate.memview.data_t0.items() if j != 0]
    print("Starting with taint reduction...")
    # left_bound = _find_left_taint_bound(test_fuzzerstate)
    # print(f"Left bound is {left_bound}")
    # right_bound = _find_right_taint_bound(test_fuzzerstate)
    # print(f"Right bound is {right_bound}")
    right_bound = 3678 
    left_bound = 3678
    if DO_ASSERT:
        tmp_fuzzerstate = deepcopy(test_fuzzerstate)
        for tainted_addr in tainted_addresses[:left_bound]:
            tmp_fuzzerstate.memview.data_t0[tainted_addr] = 0
        for tainted_addr in tainted_addresses[right_bound+1:]:
            tmp_fuzzerstate.memview.data_t0[tainted_addr] = 0
        assert any(tmp_fuzzerstate.memview.data_t0.values())
        assert is_mismatch_t0(tmp_fuzzerstate, len(tmp_fuzzerstate.instr_objs_seq)-1), f"Failed detecting leakage with bounds {left_bound} and {right_bound}"

        leaked_addresses = [i for i,j in tmp_fuzzerstate.memview.data_t0.items() if j != 0]
        privs = [fuzzerstate.pagetablestate.ppn_leaf_to_priv_dict[i&PAGE_ALIGNMENT_MASK] for i in leaked_addresses]
    print(f"Found leaked data at {[hex(i) for i in leaked_addresses]}, belonging to {privs}")
    return leaked_addresses
# def _pick_matching_regs(fuzzerstate, instr_str, addr):
#     fuzzerstate.simulate_execution(False,addr) # execute until here to get register values
#     if instr_str == "beq":

# def _create_random_non_taken_brancu(fuzzerstate, addr):
#     instr_str = random.choice(BranchInstruction_t0.authorized_instr_strs)
#     BranchInstruction_t0(fuzzerstate, instr_str, rs1, rs2, imm, plan_taken, iscompressed)


# Flattens the control flow except for the initial block, the context setter and the final block.
def _try_flatten_cf(fuzzerstate, failing_bb, failing_instr, pillar_bb, pillar_instr, quiet: bool = False):
    flat_fuzzerstate = deepcopy(fuzzerstate)
    orig_fuzzerstate = fuzzerstate # Renaming to prevent accidental use of fuzzerstate
    del fuzzerstate

    # At this stage, we can increase the size of the memory, in case it was quite small. Be careful because it is a bit a hack.
    flat_fuzzerstate.memsize = max(flat_fuzzerstate.memsize, 2**20)
    flat_fuzzerstate.memview.memsize = max(flat_fuzzerstate.memview.memsize, 2**20)

    # num_flat_instrs: number of instructions in blocks, minus the cf instructions between them (fuzzerstate.instr_objs_seq - 2) + 1 for the final cf to the final block
    num_flat_instrs = sum(map(len, flat_fuzzerstate.instr_objs_seq[1:])) - len(flat_fuzzerstate.instr_objs_seq) + 2
    n_jal_instrs = sum([1 for bb in flat_fuzzerstate.instr_objs_seq[1:] if isinstance(bb[-1], (JALRInstruction_t0,JALInstruction_t0))])
    num_flat_instrs += n_jal_instrs*3 # 3 instrucions per jal/r for lui+addi sequence
    addr_flat_instrs = flat_fuzzerstate.memview.gen_random_free_addr(2, 4*num_flat_instrs, 0, flat_fuzzerstate.memsize)

    # copy the instructions of the BB to the single flattend BB and adjust their addresses
    new_flat_instrs = []
    for bb_id, bb in enumerate(flat_fuzzerstate.instr_objs_seq):
        if bb_id == 0:
            continue
        for instr in bb[:-1]:
            instr.paddr = addr_flat_instrs + 4*len(new_flat_instrs) + SPIKE_STARTADDR
            new_flat_instrs += [instr]

        last_instr = bb[-1]
        # If the last instruction is a JAL/R, we set rd to address of the JAL/R with a lui+add sequence
        # Maybe add non-taken branches to have similar effect on BPU?
        if isinstance(last_instr, (JALInstruction_t0,JALRInstruction_t0)):
            lui_imm,addi_imm = li_into_reg(last_instr.paddr-SPIKE_STARTADDR, False) # need to remove the spike offset because of sign-extension
            lui_instr = ImmRdInstruction_t0(flat_fuzzerstate,'lui',last_instr.rd,lui_imm)
            lui_instr.paddr = addr_flat_instrs + 4*len(new_flat_instrs) + SPIKE_STARTADDR
            new_flat_instrs += [lui_instr]
            addi_instr = RegImmInstruction_t0(flat_fuzzerstate, 'addi', last_instr.rd, last_instr.rd, addi_imm)
            addi_instr.paddr = addr_flat_instrs + 4*len(new_flat_instrs) + SPIKE_STARTADDR
            new_flat_instrs += [addi_instr]
            add_instr = R12DInstruction_t0(flat_fuzzerstate, 'add', last_instr.rd, last_instr.rd, RELOCATOR_REGISTER_ID)  # add the spike offset again
            add_instr.paddr = addr_flat_instrs + 4*len(new_flat_instrs) + SPIKE_STARTADDR
            new_flat_instrs += [add_instr]
            if bb_id == failing_bb:
                if failing_instr == len(bb)-1 and not quiet:
                    print(f"WARNING: Replacing failing instruction {last_instr.get_str()} with {lui_instr.get_str()}, {addi_instr.get_str()}")
            if bb_id == pillar_bb:
                if pillar_instr == len(bb)-1 and not quiet:
                    print(f"WARNING: Replacing pillar instruction {last_instr.get_str()} with {lui_instr.get_str()}, {addi_instr.get_str()}")
            if not quiet:
                print(f"Replacing jump instruction {last_instr.get_str()} with {lui_instr.get_str()}, {addi_instr.get_str()}")

    # Jump to the final block
    jal_inst = JALInstruction_t0(flat_fuzzerstate, "jal", 0, flat_fuzzerstate.final_bb_base_addr - 4*(len(new_flat_instrs)) - addr_flat_instrs)
    jal_inst.paddr = addr_flat_instrs +  4*len(new_flat_instrs) + SPIKE_STARTADDR
    new_flat_instrs.append(jal_inst)

    if DO_ASSERT:
        assert num_flat_instrs == len(new_flat_instrs), f"num_flat_instrs={num_flat_instrs} != len(new_flat_instrs)={len(new_flat_instrs)}"

    flat_fuzzerstate.instr_objs_seq = [flat_fuzzerstate.instr_objs_seq[0], new_flat_instrs]
    flat_fuzzerstate.bb_start_addr_seq = [flat_fuzzerstate.bb_start_addr_seq[0], addr_flat_instrs]
    # flat_fuzzerstate.instr_objs_seq[-1][-1] = JALInstruction("jal", 0, flat_fuzzerstate.bb_start_addr_seq[1] - 4*(len(flat_fuzzerstate.instr_objs_seq[0])-1))
    # print('Base addr guessed', hex(flat_fuzzerstate.ctxsv_bb_base_addr + 4*flat_fuzzerstate.ctxsv_bb_jal_instr_id))
    # print('Tgt addr', hex(flat_fuzzerstate.bb_start_addr_seq[1]))
    jal_inst = JALInstruction_t0(flat_fuzzerstate, "jal", 0, flat_fuzzerstate.bb_start_addr_seq[1] - (flat_fuzzerstate.ctxsv_bb_start_addr_seq[0] + 4*flat_fuzzerstate.ctxsv_bb_jal_instr_id))
    jal_inst.paddr = flat_fuzzerstate.ctxsv_bb_start_addr_seq[0] + 4*flat_fuzzerstate.ctxsv_bb_jal_instr_id + SPIKE_STARTADDR
    flat_fuzzerstate.ctxsv_bb[flat_fuzzerstate.ctxsv_bb_jal_instr_id] = jal_inst

    is_flattening_success = is_mismatch(flat_fuzzerstate, 1)

    if is_flattening_success:
        fuzzerstate = flat_fuzzerstate
    else:
        fuzzerstate = orig_fuzzerstate
    return fuzzerstate, is_flattening_success


# Returns the index of the first bb that fails.
# hint_left_bound_bb: when the bb with id `hint_left_bound_bb` is removed and all the subsequent bbs are removed, the bug should disappear.
# hint_right_bound_bb: when the bb with id `hint_right_bound_bb` is removed and all the subsequent bbs are removed, the bug should still be here.
# @return failing_bb_id is the index of the first bb that, when removed as well as the subsequent ones, makes the bug disappear.
def _find_failing_bb(fuzzerstate, hint_left_bound_bb: int = None, hint_right_bound_bb: int = None, quiet: bool = False):
    # Take the hints
    if hint_left_bound_bb is not None:
        if DO_ASSERT:
            # assert True # TODO Uncomment sanity check for user input: assert not is_mismatch(fuzzerstate, hint_left_bound_bb), f"Wrong left bound hint `{hint_left_bound_bb}`."
            assert not is_mismatch(fuzzerstate, hint_left_bound_bb, quiet=quiet), f"Wrong left bound hint `{hint_left_bound_bb}`."
        left_bound = hint_left_bound_bb
    else:
        left_bound = 0
    if hint_right_bound_bb is not None:
        if DO_ASSERT:
            # assert True # TODO Uncomment sanity check for user input: assert is_mismatch(fuzzerstate, hint_right_bound_bb), f"Wrong right bound hint `{hint_right_bound_bb}`."
            assert is_mismatch(fuzzerstate, hint_right_bound_bb, quiet=quiet), f"Wrong right bound hint `{hint_right_bound_bb}`."
        right_bound = hint_right_bound_bb
    else:
        right_bound = len(fuzzerstate.instr_objs_seq)

    # Binary search
    # Invariant:
    #   is_mismatch(fuzzerstate, left_bound)  always False
    #   is_mismatch(fuzzerstate, right_bound) always True
    while right_bound - left_bound > 1:
        if DO_ASSERT:
            assert right_bound > left_bound
        candidate_bound = (right_bound + left_bound) // 2
        if is_mismatch(fuzzerstate, candidate_bound, quiet=quiet):
            if not quiet:
                print(candidate_bound, 'bb mismatch')
            right_bound = candidate_bound
        else:
            if not quiet:
                print(candidate_bound, 'bb match')
            left_bound = candidate_bound

    if DO_ASSERT:
        assert left_bound + 1 == right_bound

    # Now,
    #   left_bound  contains the max bb chain size that is still ok.
    #   right_bound contains the min bb chain size that is wrong.

    return right_bound

# @param failing_bb_id is the index of the first bb that, when removed as well as the subsequent ones, makes the bug disappear.
# @param failing_instr_id is the index of the first instruction in the bb `failing_bb_id` that causes trouble, in the sense that when it is removed (and all the following instructions and bbs), the test case does not fail anymore. It is None if the failing instruction is actually the last one in the previous bb.
# @param pillar_bb_id is the index of the last bb such as the test case still succeeds when the bb `pillar_bb_id` is removed (and all the preceding instructions and bbs).
def _find_pillar_bb(fuzzerstate, failing_bb_id: int, failing_instr_id: int, fault_from_prev_bb: bool, hint_left_bound_pillar_bb: int = None, hint_right_bound_pillar_bb: int = None, quiet: bool = False):
    if DO_ASSERT:
        assert failing_bb_id > 0, f"In _find_pillar_bb, we assume that the initial block does not fail."
        assert failing_bb_id < len(fuzzerstate.instr_objs_seq)

    # Take the hints. Invariants: left bound always ok, right bound always wrong.
    if hint_left_bound_pillar_bb is not None:
        if DO_ASSERT:
            # assert True # TODO Uncomment sanity check for user input: assert not is_mismatch(fuzzerstate, failing_bb_id, hint_left_bound_pillar_bb), f"Wrong left bound hint `{hint_left_bound_pillar_bb}`."
            assert is_mismatch(fuzzerstate, failing_bb_id, failing_instr_id, hint_left_bound_pillar_bb, quiet=quiet), f"Wrong left bound hint `{hint_left_bound_pillar_bb}`."
        left_bound = hint_left_bound_pillar_bb
    else:
        left_bound = 0
    if hint_right_bound_pillar_bb is not None:
        if DO_ASSERT:
            # assert True # TODO Uncomment sanity check for user input: assert is_mismatch(fuzzerstate, failing_bb_id, hint_right_bound_pillar_bb), f"Wrong right bound hint `{hint_right_bound_pillar_bb}`."
            assert not is_mismatch(fuzzerstate, failing_bb_id, failing_instr_id, hint_right_bound_pillar_bb, quiet=quiet), f"Wrong right bound hint `{hint_right_bound_pillar_bb}`."
        right_bound = hint_right_bound_pillar_bb
    else:
        right_bound = failing_bb_id + 1

    if DO_ASSERT:
        assert right_bound <= failing_bb_id + 1, f"right_bound: `{right_bound}`, failing_bb_id: `{failing_bb_id}`"

    # Binary search
    # Invariant:
    #   is_mismatch(fuzzerstate, left_bound)  always False
    #   is_mismatch(fuzzerstate, right_bound) always True
    while right_bound - left_bound > 1:
        if DO_ASSERT:
            assert right_bound > left_bound
        candidate_bound = (right_bound + left_bound) // 2
        if is_mismatch(fuzzerstate, failing_bb_id, failing_instr_id, candidate_bound, quiet=quiet):
            if not quiet:
                print(candidate_bound, 'pillar bb mismatch')
            left_bound = candidate_bound
        else:
            if not quiet:
                print(candidate_bound, 'pillar bb match')
            right_bound = candidate_bound

    if DO_ASSERT:
        assert left_bound + 1 == right_bound

    # Now,
    #   left_bound  contains the max bb chain size that is still ok.
    #   right_bound contains the min bb chain size that is wrong.

    # print('A', is_mismatch(fuzzerstate, failing_bb_id, failing_instr_id, right_bound-2))
    # print('B', is_mismatch(fuzzerstate, failing_bb_id, failing_instr_id, right_bound-1))
    # print('C', is_mismatch(fuzzerstate, failing_bb_id, failing_instr_id, right_bound))

    return right_bound-1

# @param failing_bb_id is the index of the first bb that, when removed as well as the subsequent ones, makes the bug disappear.
# @return failing_instr_id is the index of the first instruction in the bb `failing_bb_id` that causes trouble, in the sense that when it is removed (and all the following instructions and bbs), the test case does not fail anymore. It is None if the failing instruction is actually the last one in the previous bb.
def _find_failing_instr_in_bb(fuzzerstate, failing_bb_id: int, hint_left_bound_instr: int = None, hint_right_bound_instr: int = None, quiet: bool = False):
    if DO_ASSERT:
        assert failing_bb_id > 0
        assert failing_bb_id < len(fuzzerstate.instr_objs_seq)
        assert hint_left_bound_instr is None or hint_left_bound_instr >= 0, f"Got left bound hint `{hint_left_bound_instr}`."
        assert hint_right_bound_instr is None or hint_right_bound_instr <= len(fuzzerstate.instr_objs_seq[failing_bb_id]), f"Got right bound hint `{hint_right_bound_instr}, expected no more than {len(fuzzerstate.instr_objs_seq[failing_bb_id])}`."

    if len(fuzzerstate.instr_objs_seq[failing_bb_id]) == 1:
        return None

    # Take the hints
    if hint_left_bound_instr is not None:
        if DO_ASSERT:
            assert not is_mismatch(fuzzerstate, failing_bb_id, hint_left_bound_instr, quiet=quiet), f"Wrong left bound hint `{hint_left_bound_instr}`."
        left_bound = hint_left_bound_instr
    else:
        left_bound = 0
    if hint_right_bound_instr is not None:
        if DO_ASSERT:
            assert is_mismatch(fuzzerstate, failing_bb_id, hint_right_bound_instr, quiet=quiet), f"Wrong right bound hint `{hint_right_bound_instr}`."
        right_bound = hint_right_bound_instr
    else: # TODO: set to -2?
        right_bound = len(fuzzerstate.instr_objs_seq[failing_bb_id])-1 # -1 because cannot be the last instruction of the bb (falls into the case where we look back for the previous bb)

    # Check whether the issue actually comes from the cf instruction from the previous bb.
    if right_bound == 0 or is_mismatch(fuzzerstate, failing_bb_id, 0, quiet=quiet):
        print('Issue comes from the previous bb')
        return None

    # Binary search
    # Invariant:
    #   is_mismatch(fuzzerstate, failing_bb_id, left_bound)  always False
    #   is_mismatch(fuzzerstate, failing_bb_id, right_bound) always True
    while right_bound - left_bound > 1:
        if DO_ASSERT:
            assert right_bound > left_bound
        candidate_bound = (right_bound + left_bound) // 2
        if is_mismatch(fuzzerstate, failing_bb_id, candidate_bound, quiet=quiet):
            if not quiet:
                print(candidate_bound, 'instr mismatch')
            right_bound = candidate_bound
        else:
            if not quiet:
                print(candidate_bound, 'instr match')
            left_bound = candidate_bound

    if DO_ASSERT:
        assert left_bound + 1 == right_bound, f"{left_bound}, {right_bound}"

    # print('is_mismatch(fuzzerstate, failing_bb_id, left_bound)', is_mismatch(fuzzerstate, failing_bb_id, right_bound-1))
    # print('is_mismatch(fuzzerstate, failing_bb_id, right_bound)', is_mismatch(fuzzerstate, failing_bb_id, right_bound))

    return right_bound

# @param failing_bb_id is the index of the first bb that, when removed as well as the subsequent ones, makes the bug disappear.
# @param failing_instr_id is the index of the first instruction in the bb `failing_bb_id` that causes trouble, in the sense that when it is removed (and all the following instructions and bbs), the test case does not fail anymore. It is None if the failing instruction is actually the last one in the previous bb.
# @return similarly to find_pillar_bb: returns the index of the first instruction in first_pillar_bb that, when removed, makes the bug disappear.
def _find_pillar_instr(fuzzerstate, failing_bb_id: int, failing_instr_id: int, pillar_bb_id: int, fault_from_prev_bb: bool, hint_left_pillar_instr: int = None, hint_right_pillar_instr: int = None, quiet: bool = False):
    if DO_ASSERT:
        assert pillar_bb_id <= failing_bb_id + 1
    # TODO Remove
    # if fault_from_prev_bb:
    #     raise NotImplementedError('TODO case where fault_from_prev_bb is True')

    # Take the hints
    if hint_left_pillar_instr is not None:
        if DO_ASSERT:
            # assert True # TODO Uncomment sanity check for user input: assert not is_mismatch(fuzzerstate, failing_bb_id, hint_left_pillar_instr), f"Wrong left bound hint `{hint_left_pillar_instr}`."
            assert is_mismatch(fuzzerstate, failing_bb_id, failing_instr_id, pillar_bb_id, hint_left_pillar_instr, quiet=quiet), f"Wrong left bound hint `{hint_left_pillar_instr}`."
        left_bound = hint_left_pillar_instr
    else:
        left_bound = 0
    if hint_right_pillar_instr is not None:
        if DO_ASSERT:
            # assert True # TODO Uncomment sanity check for user input: assert is_mismatch(fuzzerstate, failing_bb_id, hint_right_pillar_instr), f"Wrong right bound hint `{hint_right_pillar_instr}`."
            assert not is_mismatch(fuzzerstate, failing_bb_id, failing_instr_id, pillar_bb_id, hint_right_pillar_instr, quiet=quiet), f"Wrong right bound hint `{hint_right_pillar_instr}`."
        right_bound = hint_right_pillar_instr
    else:
        if pillar_bb_id == failing_bb_id:
            if not quiet:
                print('pillar_bb_id == failing_bb_id', pillar_bb_id, failing_bb_id)
            right_bound = failing_instr_id+1
        else:
            if not quiet:
                print('pillar_bb_id != failing_bb_id', pillar_bb_id, failing_bb_id)
            right_bound = len(fuzzerstate.instr_objs_seq[pillar_bb_id])

    if right_bound == left_bound:
        return right_bound

    if DO_ASSERT:
        assert right_bound > left_bound

    # Binary search
    # Invariant:
    #   is_mismatch(fuzzerstate, failing_bb_id, left_bound)  always False
    #   is_mismatch(fuzzerstate, failing_bb_id, right_bound) always True

    while right_bound - left_bound > 1:
        if not quiet:
            print('left_bound', left_bound, 'right_bound', right_bound, 'candidate_bound', (right_bound + left_bound) // 2)
        if DO_ASSERT:
            assert right_bound > left_bound
        candidate_bound = (right_bound + left_bound) // 2
        if is_mismatch(fuzzerstate, failing_bb_id, failing_instr_id, pillar_bb_id, candidate_bound, quiet=quiet):
            if not quiet:
                print(candidate_bound, 'pillar instr mismatch')
            left_bound = candidate_bound
        else:
            if not quiet:
                print(candidate_bound, 'pillar instr match')
            right_bound = candidate_bound

    if DO_ASSERT:
        assert left_bound + 1 == right_bound, f"{left_bound}, {right_bound}"

    return right_bound-1

# @param failing_bb_id is the index of the first bb that, when removed as well as the subsequent ones, makes the bug disappear.
# @param failing_instr_id is the index of the first instruction in the bb `failing_bb_id` that causes trouble, in the sense that when it is removed (and all the following instructions and bbs), the test case does not fail anymore. It is None if the failing instruction is actually the last one in the previous bb.
# Transforms unused instructions between the first pillar and the faulty instruction into nops.
def _turn_sandwich_instructions_into_nops(fuzzerstate, failing_bb_id: int, failing_instr_id: int, pillar_bb_id: int, pillar_instr: int, fault_from_prev_bb: bool, quiet: bool = False):
    if DO_ASSERT:
        assert pillar_bb_id <= failing_bb_id+1
    
    if pillar_bb_id == failing_bb_id and failing_instr_id == pillar_instr:
        return fuzzerstate

    if pillar_bb_id == failing_bb_id:
        raise NotImplementedError('TODO check the case where pillar_bb_id == failing_bb_id')
        for instr_id in range(pillar_instr, failing_instr_id+1):
            # Save the instruction before trying to turn it into a nop
            saved_instr = fuzzerstate.instr_objs_seq[failing_bb_id][instr_id]
            fuzzerstate.instr_objs_seq[failing_bb_id][instr_id] = RegImmInstruction("addi", 0, 0, 0, is_design_64bit=fuzzerstate.is_design_64bit)
            # For debug printing
            curr_addr = fuzzerstate.bb_start_addr_seq[failing_bb_id] + 4*instr_id # NO_COMPRESSED
            try:
                if is_mismatch(fuzzerstate, failing_bb_id, failing_instr_id, pillar_bb_id, pillar_instr):
                    print(f"(D) Addr {hex(curr_addr)}: Substituted with a nop.")
                else:
                    # If this nop substitution killed the mismatch, then we must keep this instruction as normal.
                    fuzzerstate.instr_objs_seq[failing_bb_id][instr_id] = saved_instr
                    print(f"(D) Addr {hex(curr_addr)}: Not substituted instruction with a nop.")
            except:
                # Possibly, the substitution killed the spike emulation, for example by changing a non-taken branch into a taken branch.
                fuzzerstate.instr_objs_seq[failing_bb_id][instr_id] = saved_instr
                print(f"(D) Addr {hex(curr_addr)}: Not substituted instruction with a nop (spike simulation died).")


    else:
        for instr_id in range(pillar_instr, len(fuzzerstate.instr_objs_seq[pillar_bb_id])-1):
            saved_instr = copy(fuzzerstate.instr_objs_seq[pillar_bb_id][instr_id]) # No deepcopy! Reference to fuzzerstate needs to be maintainted.
            # If this is already a nop, then pass
            nop_instr =  RegImmInstruction_t0(fuzzerstate,"addi", 0, 0, 0)
            nop_instr.paddr = saved_instr.paddr
            if saved_instr.gen_bytecode_int(USE_SPIKE_INTERM_ELF) == nop_instr.gen_bytecode_int(USE_SPIKE_INTERM_ELF):
                continue
            if is_placeholder(saved_instr):
                continue
            fuzzerstate.instr_objs_seq[pillar_bb_id][instr_id] = nop_instr
            if not quiet:
                print(f"(A) Trying to replace {saved_instr.get_str()} with a nop.")
            # For debug printing
            curr_addr = fuzzerstate.bb_start_addr_seq[pillar_bb_id] + 4*instr_id # NO_COMPRESSED
            assert curr_addr + SPIKE_STARTADDR == nop_instr.paddr, f"{saved_instr.get_str()} replaced with {nop_instr.get_str()} not placed at right addr {hex(curr_addr + SPIKE_STARTADDR)}"
            try:
                if is_mismatch(fuzzerstate, failing_bb_id, failing_instr_id, pillar_bb_id, pillar_instr, quiet=quiet):
                    if not quiet:
                        print(f"(A) {saved_instr.get_str()}: Substituted with a nop.")
                    del saved_instr
                    continue
                else:
                    # If this nop substitution killed the mismatch, then we must keep this instruction as normal.
                    fuzzerstate.instr_objs_seq[pillar_bb_id][instr_id] = saved_instr
                    if not quiet:
                        print(f"(A) {saved_instr.get_str()}: Not substituted instruction with a nop: Did not trigger bug.")
            except Exception as e:
                # Possibly, the substitution killed the spike or in-situ simulation, for example by changing a non-taken branch into a taken branch or tainting a source register for a cf-ambiguous instruction.
                if not quiet:
                    print(f"(A) {saved_instr.get_str()}: Not substituted instruction with a nop ({str(e)}).")
                fuzzerstate.instr_objs_seq[pillar_bb_id][instr_id] = saved_instr


        for bb_id in range(pillar_bb_id, failing_bb_id):
            # For each intermediate bb, first start by turning all instructions into nops (except the last one)
            coarse_saved_instrs = [copy(fuzzerstate.instr_objs_seq[bb_id][instr_id]) for instr_id in range(len(fuzzerstate.instr_objs_seq[bb_id])-1)] # No deepcopy! Reference to fuzzerstate needs to be maintainted.
            if DO_ASSERT:
                for coarse_saved_instr, original_instr in zip(coarse_saved_instrs,fuzzerstate.instr_objs_seq[bb_id][:-1]):
                    assert coarse_saved_instr.paddr == original_instr.paddr
                    assert coarse_saved_instr.fuzzerstate == original_instr.fuzzerstate

            for instr_id in range(len(fuzzerstate.instr_objs_seq[bb_id])-1):
                if is_placeholder(fuzzerstate.instr_objs_seq[bb_id][instr_id]): # Keep the placeholders as we risk tainting a source register for a cf ambiguous instruction otherwise.
                    continue
                nop_instr =  RegImmInstruction_t0(fuzzerstate,"addi", 0, 0, 0)
                nop_instr.paddr = fuzzerstate.instr_objs_seq[bb_id][instr_id].paddr
                fuzzerstate.instr_objs_seq[bb_id][instr_id] = nop_instr
            if not quiet:
                print(f"(B) Trying to replace instructions in BB at {hex(fuzzerstate.bb_start_addr_seq[bb_id])} with nops.")
            try:
                if is_mismatch(fuzzerstate, failing_bb_id, failing_instr_id, pillar_bb_id, pillar_instr, quiet=quiet):
                    if not quiet:
                        print(f"(B) BB {hex(fuzzerstate.bb_start_addr_seq[bb_id])}: Coarse grain nop substitution success.")
                    continue
                if not quiet:
                    print(f"(B) BB {hex(fuzzerstate.bb_start_addr_seq[bb_id])}: Coarse grain failure: Did not trigger bug. Falling back to fine grain nop substitution.")
            except Exception as e:
                # Possibly, the substitution killed the spike or in-situ simulation, for example by changing a non-taken branch into a taken branch or tainting a source register for a cf-ambiguous instruction.
                if not quiet:
                    print(f"(B) BB {hex(fuzzerstate.bb_start_addr_seq[bb_id])}: Coarse grain failure: {str(e)}. Falling back to fine grain nop substitution.")

            # In case the coarse grain substitution did not work, try fine grain substitution on each instruction
            # If this nop substitution killed the mismatch, then we must keep this instruction as normal.

            for instr_id in range(len(fuzzerstate.instr_objs_seq[bb_id])-1):
                fuzzerstate.instr_objs_seq[bb_id][instr_id] = coarse_saved_instrs[instr_id]

            for instr_id in range(len(fuzzerstate.instr_objs_seq[bb_id])-1):
                saved_instr = copy(fuzzerstate.instr_objs_seq[bb_id][instr_id])
                nop_instr =  RegImmInstruction_t0(fuzzerstate,"addi", 0, 0, 0)
                nop_instr.paddr = saved_instr.paddr
                if saved_instr.gen_bytecode_int(USE_SPIKE_INTERM_ELF) == nop_instr.gen_bytecode_int(USE_SPIKE_INTERM_ELF):
                    continue
                if is_placeholder(saved_instr):
                    continue
                fuzzerstate.instr_objs_seq[bb_id][instr_id] = nop_instr
                if not quiet:
                    print(f"(B) Replacing {saved_instr.get_str()} with {nop_instr.get_str()}")
                # For debug printing
                curr_addr = fuzzerstate.bb_start_addr_seq[bb_id] + 4*instr_id # NO_COMPRESSED
                assert curr_addr + SPIKE_STARTADDR == nop_instr.paddr, f"{saved_instr.get_str()} replaced with {nop_instr.get_str()} not placed at right addr {hex(curr_addr + SPIKE_STARTADDR)}"
                try:
                    if is_mismatch(fuzzerstate, failing_bb_id, failing_instr_id, pillar_bb_id, pillar_instr, quiet=quiet):
                        if not quiet:
                            print(f"(B) {saved_instr.get_str()}: Substituted with a nop.")
                    else:
                        # If this nop substitution killed the mismatch, then we must keep this instruction as normal.
                        fuzzerstate.instr_objs_seq[bb_id][instr_id] = saved_instr
                        if not quiet:
                            print(f"(B) {saved_instr.get_str()}: Not substituted instruction with a nop: Did not trigger bug.")
                except Exception as e:
                    # Possibly, the substitution killed the spike or in-situ simulation, for example by changing a non-taken branch into a taken branch or tainting a source register for a cf-ambiguous instruction.
                    fuzzerstate.instr_objs_seq[bb_id][instr_id] = saved_instr
                    if not quiet:
                        print(f"(B) {saved_instr.get_str()}: Not substituted instruction with a nop ({str(e)}).")

        for instr_id in range(failing_instr_id-1):
            saved_instr = copy(fuzzerstate.instr_objs_seq[failing_bb_id][instr_id])
            nop_instr =  RegImmInstruction_t0(fuzzerstate,"addi", 0, 0, 0)
            nop_instr.paddr = saved_instr.paddr
            if saved_instr.gen_bytecode_int(USE_SPIKE_INTERM_ELF) == nop_instr.gen_bytecode_int(USE_SPIKE_INTERM_ELF):
                continue
            if is_placeholder(saved_instr):
                continue
            fuzzerstate.instr_objs_seq[failing_bb_id][instr_id] = nop_instr
            print(f"(C) Replacing {saved_instr.get_str()} with {nop_instr.get_str()}")
            # For debug printing
            curr_addr = fuzzerstate.bb_start_addr_seq[failing_bb_id] + 4*instr_id # NO_COMPRESSED
            try:
                if is_mismatch(fuzzerstate, failing_bb_id, failing_instr_id, pillar_bb_id, pillar_instr, quiet=quiet):
                    if not quiet:
                        print(f"(C) {saved_instr.get_str()}: Substituted with a nop.")
                else:
                    # If this nop substitution killed the mismatch, then we must keep this instruction as normal.
                    fuzzerstate.instr_objs_seq[failing_bb_id][instr_id] = saved_instr
                    if not quiet:
                        print(f"(C) {saved_instr.get_str()}: Not substituted instruction with a nop.")
            except Exception as e:
                # Possibly, the substitution killed the spike or in-situ simulation, for example by changing a non-taken branch into a taken branch or tainting a source register for a cf-ambiguous instruction.
                fuzzerstate.instr_objs_seq[failing_bb_id][instr_id] = saved_instr
                if not quiet:
                    print(f"(C) {saved_instr.get_str()}: Not substituted instruction with a nop ({str(e)}).")

    if DO_ASSERT:
        assert is_mismatch(fuzzerstate, failing_bb_id, failing_instr_id, pillar_bb_id, pillar_instr,quiet=quiet)
        assert not is_mismatch(fuzzerstate, failing_bb_id, failing_instr_id-1, pillar_bb_id, pillar_instr, quiet=quiet)

    return fuzzerstate

# This is the main function in this file.
# First finds the problematic basic block.
# Second, finds the problematic instruction.
# Third, reduce some first basic blocks that are not involved in the problem.
# Fourth, reduce some initial instructions in the first problematic bb.
# @param target_dir: If not None, the directory where to save the generated files. Else, will be saved in the design's directory
# @param find_pillars: If false, the front of the test case will not be reduced.
# @return a boolean indicating whether the reduction was successful, a float measuring the elapesd time (in seconds), and the number of instructions in the test case.
def reduce_program(memsize: int, design_name: str, randseed: int, nmax_bbs: int, authorize_privileges: bool, find_pillars: bool = FIND_PILLARS, quiet: bool = False, target_dir: str = None, hint_left_bound_bb: int = None, hint_right_bound_bb: int = None, hint_left_bound_instr: int = None, hint_right_bound_instr: int = None, hint_left_bound_pillar_bb: int = None, hint_right_bound_pillar_bb: int = None, hint_left_bound_pillar_instr: int = None, hint_right_bound_pillar_instr: int = None, check_pc_spike_again: bool = False):
    from cascade.fuzzerstate import FuzzerState

    ###
    # Prepare the basic blocks
    ###

    if DO_ASSERT:
        assert nmax_bbs is None or nmax_bbs > 0

    start_time = time.time()

    random.seed(randseed)
    fuzzerstate = FuzzerState(get_design_boot_addr(design_name), design_name, memsize, randseed, nmax_bbs, authorize_privileges)

    gen_basicblocks(fuzzerstate)
    numinstrs = sum([len(bb) for bb in fuzzerstate.instr_objs_seq])


    # spike resolution
    expected_regvals = spike_resolution(fuzzerstate, check_pc_spike_again)

    if len(fuzzerstate.instr_objs_seq) == 1:
        print('Only one basic block. Trivial case.')
        print('Is mismatch', is_mismatch(fuzzerstate, 1, len(fuzzerstate.instr_objs_seq[0])-1, quiet=quiet))
        ret_msg = f"Reduction failed for seed {randseed}:\n"
        ret_msg += f"\t Trivial case for single BB."
        fuzzerstate.log(ret_msg)
        return ret_msg


    # Try to replace all FPU enable/disable instructions with nops, to make the FPU dumping possible.
    for block_id, instr_id in fuzzerstate.fpuendis_coords:
        if block_id >= len(fuzzerstate.instr_objs_seq):
            continue
        if DO_ASSERT:
            assert 'csr' in fuzzerstate.instr_objs_seq[block_id][instr_id].instr_str, f"Block id {block_id}, instr id {instr_id} was not a csr instruction but was {fuzzerstate.instr_objs_seq[block_id][instr_id].instr_str}"
        fuzzerstate.instr_objs_seq[block_id][instr_id] = RegImmInstruction_t0(fuzzerstate,"addi", 0, 0, 0)


    if REDUCE_TAINT:
        leaked_addresses = reduce_taint(fuzzerstate)


    ###
    # Find the first bb that causes trouble.
    ###

    # failing_bb_id is the index of the first basic block that causes trouble, in the sense that when it is removed (and all the following ones), the test case does not fail anymore.
    failing_bb_id = _find_failing_bb(fuzzerstate, hint_left_bound_bb, hint_right_bound_bb, quiet=quiet)
    # If fail even just with the initial block
    if failing_bb_id == 0:
        if is_mismatch(fuzzerstate, 1, len(fuzzerstate.instr_objs_seq[0])-1, quiet=quiet):
            if not quiet:
                print('Failure takes already place in the initial basic block. Copying the initial basic block.')
            test_fuzzerstate_larger, rtl_elfpath_larger, expected_regvals_pairs_larger, numinstrs = gen_reduced_elf(fuzzerstate, failing_bb_id, len(fuzzerstate.instr_objs_seq[0])-1)
            if target_dir is None:
                target_dir = os.path.join(get_design_cascade_path(design_name), 'sw', 'fuzzsample')
            if not quiet:
                Path(target_dir).mkdir(parents=True, exist_ok=True)
                shutil.copyfile(rtl_elfpath_larger, os.path.join(target_dir, 'app_buggy.elf'))
                subprocess.run(' '.join([f"riscv{os.environ['CASCADE_RISCV_BITWIDTH']}-unknown-elf-objdump", '-D', '--disassembler-options=numeric,no-aliases', os.path.join(target_dir, 'app_buggy.elf'), '>', os.path.join(target_dir, 'app_buggy.elf.dump')]), shell=True)
            ret_msg = f"Reduction failed for seed {randseed}:\n"
            ret_msg += f"\t Failed with only initial BB."
            fuzzerstate.log(ret_msg)
            return ret_msg


    # If no fail at all
    if failing_bb_id == len(fuzzerstate.instr_objs_seq) and not is_mismatch(fuzzerstate, failing_bb_id-1,quiet=quiet):
        if not quiet:
            print(f"Success (no failure at all with tuple: ({memsize}, design_name, {randseed}, {nmax_bbs})")
        ret_msg = f"Reduction failed for seed {randseed}:\n"
        ret_msg += f"\t No mismatch detected."
        fuzzerstate.log(ret_msg)
        return ret_msg


    ###
    # Find the specific problematic instruction in the bb.
    ###

    # failing_instr_id is the index of the first instruction in the bb `failing_bb_id` that causes trouble, in the sense that when it is removed (and all the following instructions and bbs), the test case does not fail anymore.
    # It is None if the failing instruction is actually the last one in the previous bb.
    failing_instr_id = _find_failing_instr_in_bb(fuzzerstate, failing_bb_id, hint_left_bound_instr, hint_right_bound_instr, quiet=quiet)
    # Regularize the case where the faulty instruction was a cf instruction at the end of a bb.
    # If the fault comes from the prev bb, by definition we keep failing_bb_id untouched, and we set failing_instr_id to -1.
    fault_from_prev_bb = False
    if failing_instr_id is None:
        fault_from_prev_bb = True

        # If this is due to an interaction between the last CF instruction and the first instruction of the failing_bb_id, we may want to have failing_instr_id=0
        failing_instr_id = -1
        if not is_mismatch(fuzzerstate, failing_bb_id, failing_instr_id,quiet=quiet):
            print('Detected interaction between CF instruction and the next block instruction')
            failing_instr_id = 0
            assert is_mismatch(fuzzerstate, failing_bb_id, failing_instr_id,quiet=quiet)
        # else:
        #     failing_bb_id = failing_bb_id-1
        #     failing_instr_id = len(fuzzerstate.instr_objs_seq[failing_bb_id])-1

    
    ret_msg = f"{fuzzerstate.instance_to_str()}:\n"
    if not fault_from_prev_bb:
        ret_msg += f"Failing bb id                    : {failing_bb_id}\n"
        ret_msg += f"Fault from previous BB           : {fault_from_prev_bb}\n"
        ret_msg += f"Failing bb start addr            : {hex(fuzzerstate.bb_start_addr_seq[failing_bb_id] + SPIKE_STARTADDR)}\n"
        ret_msg += f"Failing instr in bb excluding cf : {failing_instr_id}/{len(fuzzerstate.instr_objs_seq[failing_bb_id])-1}\n"
        ret_msg += f"Failing instr                    : {fuzzerstate.instr_objs_seq[failing_bb_id][failing_instr_id].get_str(color_taint=False)}\n"

        if not IGNORE_TAINT_MISMATCH and fuzzerstate.instr_objs_seq[failing_bb_id][failing_instr_id].priv_level not in fuzzerstate.taint_in_priv:
            ret_msg += f"\tLeakage from {[p.name for p in fuzzerstate.taint_in_priv]} to {fuzzerstate.instr_objs_seq[failing_bb_id][failing_instr_id].priv_level.name} found!\n"
    else:
        ret_msg += f"Fault from previous BB           : {fault_from_prev_bb}\n"
        ret_msg += f"Previous bb i                    : {failing_bb_id-1}\n"
        ret_msg += f"Previous bb start addr           : {hex(fuzzerstate.bb_start_addr_seq[failing_bb_id-1] + SPIKE_STARTADDR)}\n"
        ret_msg += f"Previous instr in bb excluding cf: {len(fuzzerstate.instr_objs_seq[failing_bb_id-1])-1}/{len(fuzzerstate.instr_objs_seq[failing_bb_id-1])-1}\n"
        ret_msg += f"Previous instr                   : {fuzzerstate.instr_objs_seq[failing_bb_id-1][-1].get_str(color_taint=False)}\n"

        ret_msg += f"Failing bb id                    : {failing_bb_id}\n"
        ret_msg += f"Failing bb start addr            : {hex(fuzzerstate.bb_start_addr_seq[failing_bb_id] + SPIKE_STARTADDR)}\n"
        ret_msg += f"Failing instr bb excluding cf    : {0}/{len(fuzzerstate.instr_objs_seq[failing_bb_id])-1}\n"
        ret_msg += f"Failing instr                    : {fuzzerstate.instr_objs_seq[failing_bb_id][0].get_str(color_taint=False)}\n"
        ret_msg += f"Failing instr id                 : {failing_instr_id}\n"

        if not IGNORE_TAINT_MISMATCH and fuzzerstate.instr_objs_seq[failing_bb_id][0].priv_level not in fuzzerstate.taint_in_priv:
            ret_msg += f"\tLeakage from {[p.name for p in fuzzerstate.taint_in_priv]} to {fuzzerstate.instr_objs_seq[failing_bb_id][0].priv_level.name} found!\n"
    if start_time is not None:
        ret_msg += f"\tTotal time for reduction : {time.time()-start_time}\n"
    if not quiet:
        print(ret_msg)
    
    if not find_pillars:
        return ret_msg
    ###
    # Cut the first bbs until the problem disappears.
    ###

    # pillar_bb_id: the index of the last bb such as the test case still succeeds when the bb `pillar_bb_id` is removed (and all the preceding instructions and bbs).
    # We have as an invariant: pillar_bb_id <= failing_bb_id
    if find_pillars:
        pillar_bb_id = 0
        prev_pillar_bb_id = 0
        fuzzerstate.last_bb_id_before_next_ctxsv_bb = prev_pillar_bb_id
        pillar_bb_id = _find_pillar_bb(fuzzerstate, failing_bb_id, failing_instr_id, fault_from_prev_bb, hint_left_bound_pillar_bb if pillar_bb_id == 0 else pillar_bb_id, hint_right_bound_pillar_bb, quiet=quiet)
        ###
        # Cut the first instructions of the pillar bb.
        ###
        if USE_MMU: # instruction level not implemented for virtual memory
            pillar_instr = 0
        else:
            pillar_instr = _find_pillar_instr(fuzzerstate, failing_bb_id, failing_instr_id, pillar_bb_id, fault_from_prev_bb, hint_left_bound_pillar_instr, hint_right_bound_pillar_instr, quiet=quiet)
        # We 
        fuzzerstate, _, _, _ = gen_reduced_elf(fuzzerstate, failing_bb_id, failing_instr_id, pillar_bb_id, pillar_instr)
        #  # We remove the BBs [1,pillar_bb_id) so the index of the last interesting BB needs to be adjusted and the pillar BB id becomes 1.
        failing_bb_id -= (pillar_bb_id-1)
        pillar_bb_id = 1
        if pillar_bb_id == failing_bb_id:
            # We remove the instructions [0,pillar_instr) in the BB so the index of the failing instruction shifts by pillar_instr-1.
            failing_instr_id -= pillar_instr
        pillar_instr = 0 # All instructions before the pillar instruction are removed, thus the index changes to 0.
    ###
    # Some debug printing.
    ###

    if not quiet:
        print(f"Failing bb id                    : {failing_bb_id}")
        print(f"Failing bb start addr            : {hex(fuzzerstate.bb_start_addr_seq[failing_bb_id] + SPIKE_STARTADDR)}")
        print(f"Failing instrs in bb excluding cf: {failing_instr_id}/{len(fuzzerstate.instr_objs_seq[failing_bb_id])}")
        print(f"Failing instr                    : {fuzzerstate.instr_objs_seq[failing_bb_id][failing_instr_id].get_str()}")
        if find_pillars:
            print(f"Pillar bb id                     : {pillar_bb_id}")
            print(f"Pillar bb addr                   : {hex(fuzzerstate.bb_start_addr_seq[pillar_bb_id] + SPIKE_STARTADDR)}")
            print(f"Pillar instr                     : {fuzzerstate.instr_objs_seq[pillar_bb_id][pillar_instr].get_str()}")



    ###
    # Transform some instructions into nops.
    ###

    if find_pillars and NOPIZE_SANDWICH_INSTRUCTIONS:
        # The advantage of doing this before the reduction of the ELF size is that we may successfully remove some load instructions targeting the instructions we will remove. The downside is that it is slower than cleaning up after the reduction.
        fuzzerstate = _turn_sandwich_instructions_into_nops(fuzzerstate, failing_bb_id, failing_instr_id, pillar_bb_id, pillar_instr, fault_from_prev_bb, quiet=quiet)
        fuzzerstate.verify_program(print_execution=False,print_trace=False)

        if not quiet:
            print(f"Failing bb id                    : {failing_bb_id}")
            print(f"Failing bb start addr            : {hex(fuzzerstate.bb_start_addr_seq[failing_bb_id] + SPIKE_STARTADDR)}")
            print(f"Failing instrs in bb excluding cf: {failing_instr_id}/{len(fuzzerstate.instr_objs_seq[failing_bb_id])}")
            print(f"Failing instr                    : {fuzzerstate.instr_objs_seq[failing_bb_id][failing_instr_id].get_str()}")
            if find_pillars:
                print(f"Pillar bb id                     : {pillar_bb_id}")
                print(f"Pillar bb addr                   : {hex(fuzzerstate.bb_start_addr_seq[pillar_bb_id] + SPIKE_STARTADDR)}")
                print(f"Pillar instr                     : {fuzzerstate.instr_objs_seq[pillar_bb_id][pillar_instr].get_str()}")

    # Not mature code yet.
    if FLATTEN_SANDWICH_INSTRUCTIONS and not pillar_bb_id == failing_bb_id:
        if not quiet:
            print('Flattening the control flow.')
        try:
            fuzzerstate, is_success_flattening = _try_flatten_cf(fuzzerstate, failing_bb_id, failing_instr_id, pillar_bb_id, pillar_instr, quiet=quiet)
        except Exception as e:
            print(f"Exception while flattening the control flow: {e}")
            is_success_flattening = False
            raise e
        # Warning: Flattening cf outdates the indices of problematic and pillar instructions.
        if not quiet:
            print('is_success_flattening', is_success_flattening)

        if is_success_flattening:
            failing_bb_id = 1
            pillar_bb_id = 1
            fault_from_prev_bb = False

            failing_instr_id = _find_failing_instr_in_bb(fuzzerstate, failing_bb_id, quiet=quiet)
            pillar_instr = _find_pillar_instr(fuzzerstate, failing_bb_id, failing_instr_id, pillar_bb_id, fault_from_prev_bb, quiet=quiet)
            # Remove the instructions after and before
            fuzzerstate.instr_objs_seq[failing_bb_id] = fuzzerstate.instr_objs_seq[failing_bb_id][:failing_instr_id+2]
            jal_instr = JALInstruction_t0(fuzzerstate, "jal", 0, fuzzerstate.bb_start_addr_seq[1] + 4*(pillar_instr) - (fuzzerstate.ctxsv_bb_start_addr_seq[0] + 4*fuzzerstate.ctxsv_bb_jal_instr_id))
            jal_instr.paddr = fuzzerstate.ctxsv_bb_base_addr + 4*fuzzerstate.ctxsv_bb_jal_instr_id + SPIKE_STARTADDR
            fuzzerstate.ctxsv_bb[fuzzerstate.ctxsv_bb_jal_instr_id] = jal_instr
            for instr_id in range(pillar_instr):
                nop_instr = RegImmInstruction_t0(fuzzerstate,"addi", 0, 0, 0) # RawDataWord(0)
                nop_instr.paddr = fuzzerstate.bb_start_addr_seq[failing_bb_id] + 4*instr_id + SPIKE_STARTADDR
                fuzzerstate.instr_objs_seq[pillar_bb_id][instr_id] = nop_instr

            # We can do this one more time
            fuzzerstate = _turn_sandwich_instructions_into_nops(fuzzerstate, failing_bb_id, failing_instr_id, pillar_bb_id, pillar_instr, fault_from_prev_bb, quiet=quiet)
            if not quiet:
                print(f"Failing bb id                    : {failing_bb_id}")
                print(f"Failing bb start addr            : {hex(fuzzerstate.bb_start_addr_seq[failing_bb_id] + SPIKE_STARTADDR)}")
                print(f"Failing instrs in bb excluding cf: {failing_instr_id}/{len(fuzzerstate.instr_objs_seq[failing_bb_id])}")
                print(f"Failing instr                    : {fuzzerstate.instr_objs_seq[failing_bb_id][failing_instr_id].get_str()}")
                if find_pillars:
                    print(f"Pillar bb id                     : {pillar_bb_id}")
                    print(f"Pillar bb addr                   : {hex(fuzzerstate.bb_start_addr_seq[pillar_bb_id] + SPIKE_STARTADDR)}")
                    print(f"Pillar instr                     : {fuzzerstate.instr_objs_seq[pillar_bb_id][pillar_instr].get_str()}")

            fuzzerstate.verify_program(print_execution=False,print_trace=False)

    if fault_from_prev_bb:
        # If the fault came from the previous bb, there are 2 possibilities:
        # 1. The fault came from the last instruction of the previous bb alone.
        # 2. The fault came from the last instruction of the previous bb and the first instruction of the failing bb.
        # In the first case, failing_instr_id = -1. In the second, failing_instr_id = 0.
        # Actually, all becomes perfectly regular in the 'larger' case, if I'm not mistaken.
        test_fuzzerstate_larger, rtl_elfpath_larger, expected_regvals_pairs_larger, numinstrs_larger = gen_reduced_elf(fuzzerstate, failing_bb_id, failing_instr_id)
        
    else:
        test_fuzzerstate_larger, rtl_elfpath_larger, expected_regvals_pairs_larger, numinstrs_larger = gen_reduced_elf(fuzzerstate, failing_bb_id, failing_instr_id)
    
    test_fuzzerstate_larger.expected_regvals = expected_regvals_pairs_larger
    test_fuzzerstate_larger.rtl_elfpath = rtl_elfpath_larger
    print(f"Larger: failing_bb_id: {failing_bb_id}, failing_instr_id: {failing_instr_id}, numinstrs_larger: {numinstrs_larger}")
    print(f"Larger ELF: {rtl_elfpath_larger}")

    if failing_instr_id == -1 and fault_from_prev_bb:
        ret = gen_reduced_elf(fuzzerstate, failing_bb_id-1)
        if ret is False:
            test_fuzzerstate_smaller, rtl_elfpath_smaller, expected_regvals_pairs_smaller, numinstrs_smaller = itertools.repeat(None,4)
            print('Warning: smaller is trivial. Error may come from initial block.')
            ret_msg = f"Reduction failed for seed {randseed}:\n"
            ret_msg += f"\t Smaller is trivial. Error from intial block."
            fuzzerstate.log(ret_msg)
            return ret_msg
        else:
            test_fuzzerstate_smaller, rtl_elfpath_smaller, expected_regvals_pairs_smaller, numinstrs_smaller = ret
    else:
        test_fuzzerstate_smaller, rtl_elfpath_smaller, expected_regvals_pairs_smaller, numinstrs_smaller = gen_reduced_elf(fuzzerstate, failing_bb_id, failing_instr_id-1)
    
    test_fuzzerstate_smaller.expected_regvals = expected_regvals_pairs_smaller
    test_fuzzerstate_smaller.rtl_elfpath = rtl_elfpath_smaller
    print(f"Smaller: failing_bb_id: {failing_bb_id}, failing_instr_id: {failing_instr_id-1}, numinstrs_smaller: {numinstrs_smaller}")
    print(f"Smaller ELF: {rtl_elfpath_smaller}")


    is_success_larger, rtl_msg_larger = runtest_simulator(test_fuzzerstate_larger, rtl_elfpath_larger, expected_regvals_pairs_larger, numinstrs_larger)
    if not quiet:
        print('Success larger:', is_success_larger)
        print('larger msg:', rtl_msg_larger)
    is_success_smaller, rtl_msg_smaller = runtest_simulator(test_fuzzerstate_smaller, rtl_elfpath_smaller, expected_regvals_pairs_smaller, numinstrs_smaller)
    if not quiet:
        print('Success smaller:', is_success_smaller)
        print('smaller msg:', rtl_msg_smaller)

    # assert is_success_smaller and not is_success_larger, f"Reduction failed."

    ret_msg = f"{fuzzerstate.instance_to_str()}:\n"
    ret_msg += f"\t Larger elf at {rtl_elfpath_larger}, success {is_success_larger}\n"
    ret_msg += f"\t Smaller elf at {rtl_elfpath_smaller}, success {is_success_smaller}\n"
    if FLATTEN_SANDWICH_INSTRUCTIONS:
        ret_msg += f"\t Flatten success: {is_success_flattening}\n"
    ret_msg += f"\t Failing bb id: {failing_bb_id}\n"
    ret_msg += f"\t Failing instr id: {failing_instr_id}\n"
    ret_msg += f"\t Failing instr: {fuzzerstate.instr_objs_seq[failing_bb_id][failing_instr_id].get_str()}\n"
    ret_msg += f"\t Pillar bb id: {pillar_bb_id}\n"
    ret_msg += f"\t Pillar instr id: {pillar_instr}\n"
    ret_msg += f"\t Pillar instr: {fuzzerstate.instr_objs_seq[pillar_bb_id][pillar_instr].get_str()}\n"
    ret_msg += f"\t Total number of bbs: {failing_bb_id-pillar_bb_id}\n"
    if NOPIZE_SANDWICH_INSTRUCTIONS:
        numinstrs = sum(map(len, fuzzerstate.instr_objs_seq[1:]))
        n_nops =  _count_n_nops(fuzzerstate,pillar_bb_id,failing_bb_id)
        ret_msg += f"\t Total number of non-nop instructions: {numinstrs-n_nops} ({numinstrs} instructions - {n_nops} nops)\n"
    # if TAINT_EN: # analyze_writeback_trace depricated.
    #     n_tainted_bits, n_untainted_bits, n_tainted_writes, total_writes = fuzzerstate.intregpickstate.analyze_writeback_trace(use_final=True)
    #     ret_msg += f"\t Ratio of tainted/total writeback bits {n_tainted_bits}/{n_untainted_bits+n_tainted_bits} -> {n_tainted_bits/(n_untainted_bits+n_tainted_bits)}\n"
    #     ret_msg += f"\t Ratio of tainted/total writebacks {n_tainted_writes}/{total_writes} -> {n_tainted_writes/total_writes}\n"
    if not quiet:
        print(ret_msg)
    fuzzerstate.log(ret_msg)
    return ret_msg

def _count_n_nops(fuzzerstate, min_bb, max_bb):
    nop_instr_bytecode =  RegImmInstruction_t0(fuzzerstate,"addi", 0, 0, 0).gen_bytecode_int(USE_SPIKE_INTERM_ELF)
    n_nops = 0
    for bb in fuzzerstate.instr_objs_seq[min_bb:max_bb]:
        for instr in bb:
            if instr.gen_bytecode_int(USE_SPIKE_INTERM_ELF) == nop_instr_bytecode:
                n_nops += 1

    return n_nops
