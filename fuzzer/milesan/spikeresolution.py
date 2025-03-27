# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

from params.runparams import DO_ASSERT, NO_REMOVE_TMPFILES
from params.fuzzparams import RELOCATOR_REGISTER_ID, RDEP_MASK_REGISTER_ID, USE_COMPRESSED
from common.designcfgs import get_design_march_flags, get_design_march_flags_nocompressed
from common.spike import run_trace_all_pcs, run_trace_regs_at_pc_locs, SPIKE_STARTADDR, FPREG_ABINAMES

from milesan.cfinstructionclasses import *
from milesan.genelf import gen_elf_from_bbs
from milesan.util import IntRegIndivState

from milesan.mmu_utils import phys2virt
from milesan.privilegestate import PrivilegeStateEnum
from common.exceptions import InvalidProgramException

import os
import random
import itertools

###
# Utility functions
###

def get_current_layout(bb_instr, curr_addr_layout, curr_priv_state):
    if isinstance(bb_instr, PrivilegeDescentInstruction) or isinstance(bb_instr, ExceptionInstruction):
        curr_addr_layout = bb_instr.va_layout_after_op
        curr_priv_state = bb_instr.priv_level_after_op
    elif isinstance(bb_instr, CSRRegInstruction): # when we write to SATP
        is_satp_smode, layout = bb_instr.is_satp_smode
        if is_satp_smode: curr_addr_layout = layout
    elif isinstance(bb_instr, JALRInstruction): # when the JALR jumps to a new layout
        if bb_instr.to_new_layout:
            curr_addr_layout = bb_instr.va_layout_after_op
            curr_priv_state = bb_instr.priv_level
    
    return curr_addr_layout, curr_priv_state


# @brief generates the register dump requests made to spike
# @return the register dump requests: an iterable of pairs (pc, reg to dump) in program order
def gen_regdump_reqs(fuzzerstate):
    if DO_ASSERT:
        assert len(fuzzerstate.instr_objs_seq) == len(fuzzerstate.bb_start_addr_seq)

    ret = []
    curr_addr_layout = -1
    curr_priv_state = PrivilegeStateEnum.MACHINE
    for bb_start_addr, bb_instrs in zip(fuzzerstate.bb_start_addr_seq, fuzzerstate.instr_objs_seq):
        for bb_instr_id, bb_instr in enumerate(bb_instrs):
            # curr_addr = bb_start_addr + 4*bb_instr_id # NO_COMPRESSED

            # All we need is the value of the dependent register at consumption time.
            if isinstance(bb_instr, PlaceholderConsumerInstr):
                # if USE_MMU:
                #     curr_addr = phys2virt(curr_addr, curr_priv_state, curr_addr_layout, fuzzerstate, False)
                curr_addr = bb_instr.vaddr if USE_MMU  and bb_instr.va_layout != -1 else bb_instr.paddr
                ret.append((curr_addr, False, bb_instr.rdep))
            # For branches, we need to know the val of both operands to generate a suitable opcode later.
            if isinstance(bb_instr, BranchInstruction):
                # if USE_MMU:
                #     curr_addr = phys2virt(curr_addr, curr_priv_state, curr_addr_layout, fuzzerstate, False)
                # if not bb_instr.plan_taken:
                curr_addr = bb_instr.vaddr if USE_MMU  and bb_instr.va_layout != -1 else bb_instr.paddr
                ret.append((curr_addr, False, bb_instr.rs1)) # rs1 is the first  dependent register.
                ret.append((curr_addr, False, bb_instr.rs2)) # rs2 is the second dependent register.

            # We have to keep track of the current address space layout
            # curr_addr_layout, curr_priv_state = get_current_layout(bb_instr, curr_addr_layout, curr_priv_state)
    return ret

def get_dumps_from_instr(bb_instr):
    ret = []
    addr = bb_instr.vaddr if USE_MMU else bb_instr.paddr
    assert addr is not None, f"Address of {bb_instr.get_str()} was None!"
    if isinstance(bb_instr, R12DInstruction):
        ret.append((addr, False, bb_instr.rd))
        ret.append((addr, False, bb_instr.rs1))
        ret.append((addr, False, bb_instr.rs2))
    elif isinstance(bb_instr, RegImmInstruction):
        ret.append((addr, False, bb_instr.rd))
        ret.append((addr, False, bb_instr.rs1))
    elif isinstance(bb_instr, ImmRdInstruction):
        ret.append((addr, False, bb_instr.rd))
    elif isinstance(bb_instr, JALInstruction):
        ret.append((addr, False, bb_instr.rd))
    elif isinstance(bb_instr, JALRInstruction):
        ret.append((addr, False, bb_instr.rd))
    elif isinstance(bb_instr, PlaceholderProducerInstr0):
        ret.append((addr, False, bb_instr.rd))
    elif isinstance(bb_instr, PlaceholderProducerInstr1):
        ret.append((addr, False, bb_instr.rd))
    elif isinstance(bb_instr, PlaceholderPreConsumerInstr):
        ret.append((addr, False, bb_instr.rdep))
        ret.append((addr, False, RDEP_MASK_REGISTER_ID))
    elif isinstance(bb_instr, PlaceholderConsumerInstr):
        ret.append((addr, False, bb_instr.rd))
        ret.append((addr, False, bb_instr.rprod))
        ret.append((addr, False, RELOCATOR_REGISTER_ID))
    elif isinstance(bb_instr, IntLoadInstruction):
        ret.append((addr, False, bb_instr.rd))
        ret.append((addr, False, bb_instr.rs1))
    elif isinstance(bb_instr, IntStoreInstruction):
        ret.append((addr, False, bb_instr.rs1))
        ret.append((addr, False, bb_instr.rs2))
    elif isinstance(bb_instr, CSRRegInstruction): # Ignore CSRs for now.
        ret.append((addr, False, bb_instr.rd))
        ret.append((addr, False, bb_instr.rs1))
    elif isinstance(bb_instr, CSRImmInstruction):
        ret.append((addr, False, bb_instr.rd))
    elif isinstance(bb_instr, BranchInstruction):
        ret.append((addr, False, bb_instr.rs1))
        ret.append((addr, False, bb_instr.rs2))
    elif isinstance(bb_instr, (TvecWriterInstruction, EPCWriterInstruction,GenericCSRWriterInstruction)):
        assert isinstance(bb_instr.csr_instr, CSRRegInstruction)
        ret.append((addr, False, bb_instr.csr_instr.rd))
        ret.append((addr, False, bb_instr.csr_instr.rs1))

    return ret

# @brief generates the register dump requests made to spike
# @return the register dump requests: an iterable of pairs (pc, reg to dump) in program order
def gen_regdump_reqs_all_rds(fuzzerstate, max_bb_id: int = None, max_instr_id: int = None, index_first_bb_to_consider: int = 0, first_instr_id_in_first_bb_to_consider: int = 0):
    if DO_ASSERT:
        assert max_bb_id is None or (max_bb_id >= 0 and max_bb_id <= len(fuzzerstate.instr_objs_seq))
        assert max_instr_id is None or max_instr_id >= 0
        assert len(fuzzerstate.instr_objs_seq) == len(fuzzerstate.bb_start_addr_seq)

    ret = []
    for bb_id, (bb_start_addr, bb_instrs) in enumerate(zip(fuzzerstate.bb_start_addr_seq, fuzzerstate.instr_objs_seq)):
        if bb_id > 0 and bb_id < index_first_bb_to_consider: #  we always generate the dumps for the initial and ctxsv BBs
            continue
        if max_bb_id is not None and bb_id >= max_bb_id-1:
            break
        for bb_instr_id, bb_instr in enumerate(bb_instrs):
            # print(f"{bb_instr.get_str()} (BB {bb_id})")
            if bb_id == index_first_bb_to_consider and bb_instr_id < first_instr_id_in_first_bb_to_consider:
                continue
            if max_instr_id is not None and bb_instr_id >= max_instr_id and max_bb_id is not None and bb_id >= max_bb_id:
                break
            [ret.append(d) for d in get_dumps_from_instr(bb_instr)]
        if bb_id == fuzzerstate.last_bb_id_before_ctx_saver:
            for bb_instr_id, bb_instr in enumerate(fuzzerstate.ctxsv_bb):
                if not isinstance(bb_instr, RawDataWord):
                    [ret.append(d) for d in get_dumps_from_instr(bb_instr)]
                    # bb_instr.print()

    return ret

# @brief generates the register dump requests made to spike for pruning.
# @param max_bb_id: if not None, only consider basic blocks with id < max_bb_id. Used with pruning for finding the instruction that caused the mismatch.
# @param max_instr_id: if not None, only consider instructions with id < max_instr_id. Used with pruning for finding the instruction that caused the mismatch.
# @return the register dump requests: an iterable of pairs (pc, reg to dump) in program order
def gen_regdump_reqs_reduced(fuzzerstate, max_bb_id: int = None, max_instr_id: int = None, index_first_bb_to_consider: int = 1, first_instr_id_in_first_bb_to_consider: int = 0):
    if DO_ASSERT:
        assert max_bb_id is None or (max_bb_id >= 0 and max_bb_id <= len(fuzzerstate.instr_objs_seq))
        assert max_instr_id is None or max_instr_id >= 0
        assert len(fuzzerstate.instr_objs_seq) == len(fuzzerstate.bb_start_addr_seq)

    ret = []
    for bb_id, (bb_start_addr, bb_instrs) in enumerate(zip(fuzzerstate.bb_start_addr_seq, fuzzerstate.instr_objs_seq)):
        if bb_id < index_first_bb_to_consider:
            continue
        if max_bb_id is not None and bb_id >= max_bb_id-1:
            break
        for bb_instr_id, bb_instr in enumerate(bb_instrs):
            if bb_id == index_first_bb_to_consider and bb_instr_id < first_instr_id_in_first_bb_to_consider:
                continue
            if max_instr_id is not None and bb_instr_id >= max_instr_id and max_bb_id is not None and bb_id >= max_bb_id:
                break
            # curr_addr = bb_start_addr + 4*bb_instr_id + SPIKE_STARTADDR # NO_COMPRESSED
            curr_addr = bb_start_addr + sum([2+2*int(not instr.iscompressed) for instr in bb_instrs[:bb_instr_id]])
            assert curr_addr+SPIKE_STARTADDR == bb_instr.paddr, f"Address mismatch: Expected {hex(curr_addr+SPIKE_STARTADDR)}, got {hex(bb_instr.paddr)}"
            
            # All we need is the value of the dependent register at consumption time.
            if isinstance(bb_instr, PlaceholderConsumerInstr):
                ret.append((bb_instr.vaddr if USE_MMU else bb_instr.paddr, False, bb_instr.rdep))
            # For branches, we need to know the val of both operands to generate a suitable opcode later.
            if isinstance(bb_instr, BranchInstruction):
                # if not bb_instr.plan_taken:
                ret.append((bb_instr.vaddr if USE_MMU else bb_instr.paddr, False, bb_instr.rs1)) # rs1 is the first  dependent register.
                ret.append((bb_instr.vaddr if USE_MMU else bb_instr.paddr, False, bb_instr.rs2)) # rs2 is the second dependent register.
    return ret

# @brief generates the register dump requests made to spike for saving the architectural state.
# @return a pair (the register dump requests: an iterable of pairs (pc, reg to dump) in program order, and store byte sizes in program order)
def gen_ctx_regdump_reqs(fuzzerstate, index_first_bb_to_consider: int, first_instr_id_in_first_bb_to_consider: int = 0, tgt_pc: int = -1):
    if DO_ASSERT:
        assert index_first_bb_to_consider > 0
        assert index_first_bb_to_consider <= len(fuzzerstate.instr_objs_seq)
        assert first_instr_id_in_first_bb_to_consider >= 0
        assert first_instr_id_in_first_bb_to_consider < len(fuzzerstate.instr_objs_seq[index_first_bb_to_consider])

    ret_dumpreqs = []
    ret_storesizes = []
    insts = []
    # Get the addresses and values of all the store instructions until the target PC.
    for bb_start_addr, bb_instrs in zip(fuzzerstate.bb_start_addr_seq[:index_first_bb_to_consider], fuzzerstate.instr_objs_seq[:index_first_bb_to_consider]):
        for bb_instr_id, bb_instr in enumerate(bb_instrs):
            curr_addr = bb_start_addr + 4*bb_instr_id + SPIKE_STARTADDR
            assert curr_addr == bb_instr.paddr, f"Address mismatch: Expected {hex(curr_addr)}, got {bb_instr.paddr}"
            if isinstance(bb_instr, IntStoreInstruction):
                ret_dumpreqs.append((bb_instr.paddr if not USE_MMU else bb_instr.vaddr, False, bb_instr.rs1))
                ret_dumpreqs.append((bb_instr.paddr if not USE_MMU else bb_instr.vaddr, False, bb_instr.rs2))
                insts += [bb_instr] # twice so it matches the dumpreqs
                insts += [bb_instr]
                if bb_instr.instr_str == 'sb':
                    ret_storesizes.append(1)
                elif bb_instr.instr_str == 'sh':
                    ret_storesizes.append(2)
                elif bb_instr.instr_str == 'sw':
                    ret_storesizes.append(4)
                elif bb_instr.instr_str == 'sd':
                    ret_storesizes.append(8)
                else:
                    raise Exception('Unknown store instruction: ' + bb_instr.instr_str)
            elif isinstance(bb_instr, FloatStoreInstruction):
                raise NotImplementedError
                ret_dumpreqs.append((bb_instr.paddr if not USE_MMU else bb_instr.vaddr, False, bb_instr.rs1))
                ret_dumpreqs.append((bb_instr.paddr if not USE_MMU else bb_instr.vaddr, True, FPREG_ABINAMES[bb_instr.frs2]))
                if bb_instr.instr_str == 'fsb':
                    ret_storesizes.append(1)
                elif bb_instr.instr_str == 'fsh':
                    ret_storesizes.append(2)
                elif bb_instr.instr_str == 'fsw':
                    ret_storesizes.append(4)
                elif bb_instr.instr_str == 'fsd':
                    ret_storesizes.append(8)
                else:
                    raise Exception('Unknown store instruction: ' + bb_instr.instr_str)

    # Prompt for CSRs
    ret_dumpreqs.append((tgt_pc, False, 'fcsr'))
    ret_dumpreqs.append((tgt_pc, False, 'mepc'))
    ret_dumpreqs.append((tgt_pc, False, 'sepc'))
    ret_dumpreqs.append((tgt_pc, False, 'mcause'))
    ret_dumpreqs.append((tgt_pc, False, 'scause'))
    ret_dumpreqs.append((tgt_pc, False, 'mscratch'))
    ret_dumpreqs.append((tgt_pc, False, 'sscratch'))
    ret_dumpreqs.append((tgt_pc, False, 'mtvec'))
    ret_dumpreqs.append((tgt_pc, False, 'stvec'))
    ret_dumpreqs.append((tgt_pc, False, 'medeleg'))
    ret_dumpreqs.append((tgt_pc, False, 'mstatus'))
    ret_dumpreqs.append((tgt_pc, False, 'minstret'))
    if USE_MMU: 
        ret_dumpreqs.append((tgt_pc, False, 'satp'))
        ret_dumpreqs.append((tgt_pc, False, RPROD_MASK_REGISTER_ID)) # Special register, used to produce virtual address, dynamic at runtime
    if not fuzzerstate.is_design_64bit:
        ret_dumpreqs.append((tgt_pc, False, 'minstreth'))

    ret_dumpreqs.append((tgt_pc, False, 'priv'))

    # Prompt for floating point registers
    for float_reg_id in range(fuzzerstate.num_pickable_floating_regs):
        ret_dumpreqs.append((tgt_pc, True, FPREG_ABINAMES[float_reg_id]))
    # Prompt for integer registers
    for int_reg_id in range(fuzzerstate.num_pickable_regs):
        ret_dumpreqs.append((tgt_pc, False, int_reg_id))

    return ret_dumpreqs, ret_storesizes, insts

# @return a regdump request for all PCs
def gen_pc_trace(fuzzerstate):
    ret = []
    # NO_COMPRESSED
    for bb_start_addr, bb_instrs in zip(fuzzerstate.bb_start_addr_seq, fuzzerstate.instr_objs_seq):
        for bb_instr in bb_instrs:
            # ret.append(bb_start_addr + 4*instr_id + fuzzerstate.design_base_addr)
            ret.append(bb_instrs.vaddr if USE_MMU else bb_instr.paddr)
    return ret

# @brief from the output of the regdump, distributes the values to the instructions
# @return nothing
def _feed_regdump_to_instrs(fuzzerstate, regdumps: list):
    if DO_ASSERT:
        assert len(fuzzerstate.instr_objs_seq) == len(fuzzerstate.bb_start_addr_seq)

    producer_id_to_rdepval = dict() # producer_id_to_rdepval[producer_id] = tgt_addr

    index_in_regdump = 0
    for bb_start_addr, bb_instrs in zip(fuzzerstate.bb_start_addr_seq, fuzzerstate.instr_objs_seq):
        for bb_instr_id, bb_instr in enumerate(bb_instrs):
            # curr_addr = bb_start_addr + 4*bb_instr_id # NO_COMPRESSED, for debug only
            # For consumers, we just place the register value for the producers
            if isinstance(bb_instr, PlaceholderConsumerInstr):
                # if DO_ASSERT:
                #     if fuzzerstate.is_design_64bit:
                #         assert regdumps[index_in_regdump] < 1 << 30, f"For more efficient offset generation, we ask the dependent register to be strictly less than 1 << 30. This is typically ensured by the pre-consumer. Producer id: {bb_instr.producer_id}"

                producer_id_to_rdepval[bb_instr.producer_id] = regdumps[index_in_regdump]
                index_in_regdump += 1

            if isinstance(bb_instr, BranchInstruction):
                # First, we get rs1.
                branch_rs1_content = regdumps[index_in_regdump]
                index_in_regdump += 1
                # Second, we get rs2.
                branch_rs2_content = regdumps[index_in_regdump]
                index_in_regdump += 1
                # Now, we can redetermine the branch opcode depending on the register values
                bb_instr.select_suitable_opcode(branch_rs1_content, branch_rs2_content)

    # Feed the consumer-level information into the producers
    for bb_instrlist in fuzzerstate.instr_objs_seq:
        for bb_instr in bb_instrlist:
            if isinstance(bb_instr, PlaceholderProducerInstr0) or isinstance(bb_instr, PlaceholderProducerInstr1):
                if bb_instr.producer_id in producer_id_to_rdepval:
                    # Rationale: target_addr = rdep ^ rprod, where target_addr is spike_resolution_offset
                    if bb_instr.produce_va_layout != -1:
                        # No need for spike base address offset in virtual memory
                        bb_instr.rtl_offset = producer_id_to_rdepval[bb_instr.producer_id] ^ bb_instr.spike_resolution_offset
                    else:
                        bb_instr.rtl_offset = producer_id_to_rdepval[bb_instr.producer_id] ^ bb_instr.spike_resolution_offset ^ SPIKE_STARTADDR
                else:
                    # If this producer is never used, then we need to ensure that it remains the same as in the Spike resolution
                    bb_instr.rtl_offset = bb_instr.spike_resolution_offset

def _transmit_addrs_to_producers_for_spike_resolution(fuzzerstate):
    for bb_instrlist in fuzzerstate.instr_objs_seq:
        for bb_instr in bb_instrlist:
            if isinstance(bb_instr, PlaceholderProducerInstr0):
                if bb_instr.producer_id not in fuzzerstate.producer_id_to_tgtaddr:
                    # We cannot provide a totally random value in all cases. Some CSRs will not tolerate it.
                    # So far, I think the only CSR that does not tolerate random values and that has a producer id is tvec.
                    # In the future, we may want to check the type of instruction that has this producer id
                    fuzzerstate.producer_id_to_tgtaddr[bb_instr.producer_id] = random.randrange(1 << 30) << 2
                    fuzzerstate.consumer_inst_va_layout[bb_instr.producer_id] = (-1, PrivilegeStateEnum.MACHINE)
                bb_instr.spike_resolution_offset = fuzzerstate.producer_id_to_tgtaddr[bb_instr.producer_id]
                bb_instr.produce_va_layout, bb_instr.produce_priv_level = fuzzerstate.consumer_inst_va_layout[bb_instr.producer_id]
            elif isinstance(bb_instr, PlaceholderProducerInstr1):
                # print('Determ for prod id', bb_instr.producer_id, hex(fuzzerstate.producer_id_to_tgtaddr[bb_instr.producer_id]))
                bb_instr.produce_va_layout, bb_instr.produce_priv_level = fuzzerstate.consumer_inst_va_layout[bb_instr.producer_id]
                bb_instr.spike_resolution_offset = fuzzerstate.producer_id_to_tgtaddr[bb_instr.producer_id]
            elif isinstance(bb_instr, PlaceholderConsumerInstr):
                bb_instr.produce_va_layout, bb_instr.produce_priv_level = fuzzerstate.consumer_inst_va_layout[bb_instr.producer_id]
            elif isinstance(bb_instr, PlaceholderPreConsumerInstr):
                bb_instr.produce_va_layout, bb_instr.produce_priv_level = fuzzerstate.consumer_inst_va_layout[bb_instr.producer_id]

# Check that the PC trace from spike matches with the expected PC trace
def _check_pc_trace_from_spike(fuzzerstate, spike_pc_seq):
    # assert not USE_COMPRESSED, f"Not supported with compressed instructions"
    # Check that the PC sequence corresponds to the expected addresses
    curr_id_in_spike_pc_seq = 0
    prev_pc = -1
    curr_addr_layout = -1
    curr_priv_state = PrivilegeStateEnum.MACHINE
    # if USE_COMPRESSED:
        # spike_pc_seq = [i for i in spike_pc_seq if not i%4]
    for bb_id, bb_instrlist in enumerate(fuzzerstate.instr_objs_seq):
        for bb_instr_id, bb_instr in enumerate(bb_instrlist):
            if isinstance(bb_instr, SpeculativeInstructionEncapsulator):
                continue
            assert curr_id_in_spike_pc_seq < len(spike_pc_seq), f"Not all spike PCs checked:  {curr_id_in_spike_pc_seq-1}/{len(spike_pc_seq)}, {len([i for j in fuzzerstate.instr_objs_seq for i in j])} instructions."
            spike_pc = spike_pc_seq[curr_id_in_spike_pc_seq]
            curr_id_in_spike_pc_seq += 1
            # expected_pc = SPIKE_STARTADDR + fuzzerstate.bb_start_addr_seq[bb_id] + 4*bb_instr_id # NO_COMPRESSED
            expected_pc = SPIKE_STARTADDR + fuzzerstate.bb_start_addr_seq[bb_id] + sum([int(not i.iscompressed)*2+2 for i in bb_instrlist[:bb_instr_id]]) # NO_COMPRESSED
            if curr_addr_layout != -1: expected_pc = phys2virt(expected_pc, curr_priv_state, curr_addr_layout, fuzzerstate, False)
            assert expected_pc == (bb_instr.vaddr if USE_MMU else bb_instr.paddr)
            # print(f"{hex(spike_pc)}/{hex(expected_pc)}")
            # bb_instr.print()
            # When writing to SATP, we have a subsquent sfence and spike needs an extra "r" in that case, so we need to increase the counter by one.
            if USE_COMPRESSED and spike_pc == expected_pc-2 and bb_instr.instr_str == "sfence.vma":
                spike_pc = spike_pc_seq[curr_id_in_spike_pc_seq]
                curr_id_in_spike_pc_seq += 1

            if spike_pc != expected_pc:
                raise ValueError(f"PC mismatch: spike said `{hex(spike_pc)}`, but we expected `{hex(expected_pc)}`. instr: {bb_instr.get_str()} BB id: `{hex(bb_id)}`, instr id: `{hex(bb_instr_id)}`. Prev pc: `{hex(prev_pc)}`. Spike instr id: {curr_id_in_spike_pc_seq}. Fuzzerstate identification: {fuzzerstate.instance_to_str()}")
            prev_pc = expected_pc

            # We have to keep track of the current address space layout
            curr_addr_layout, curr_priv_state = get_current_layout(bb_instr, curr_addr_layout, curr_priv_state)

    # Check that the final bb is reached FIXME does not work with virtual addresses
    #assert(spike_pc_seq[id_in_spike_pc_seq] == SPIKE_STARTADDR + fuzzerstate.final_bb_base_addr), f"spike_pc_seq[id_in_spike_pc_seq]: `{hex(spike_pc_seq[id_in_spike_pc_seq])}`, fuzzerstate.final_bb_base_addr: {hex(SPIKE_STARTADDR + fuzzerstate.final_bb_base_addr)}"


# Takes a fuzzerstate after its basic blocks were generated.
# Does the address resolution in place in the fuzzerstate, and returns the list of expected register values.
# @return a list of fuzzerstate.num_pickable_regs
# 1 (does not contain the zero register)
def spike_resolution(fuzzerstate, check_pc_spike_again: bool = False, return_interm: bool = True):
    design_name = fuzzerstate.design_name
    _transmit_addrs_to_producers_for_spike_resolution(fuzzerstate)
    # print('start addrs', list(map(hex, fuzzerstate.bb_start_addr_seq)))
    spike_resolution_elfpath = gen_elf_from_bbs(fuzzerstate, True, 'spikeresol', fuzzerstate.instance_to_str(), SPIKE_STARTADDR)
    # print('Spike resolution elfpath:', spike_resolution_elfpath)
    regdump_reqs = gen_regdump_reqs(fuzzerstate)
    flat_instr_objs = list(itertools.chain.from_iterable(fuzzerstate.instr_objs_seq))
    flat_instr_objs = [i for i in flat_instr_objs if not isinstance(i, SpeculativeInstructionEncapsulator)]

    final_addr = fuzzerstate.final_bb_base_addr+SPIKE_STARTADDR
    last_instr = fuzzerstate.instr_objs_seq[-1][-1]
    if USE_MMU:
        va_layout, priv_level = get_current_layout(last_instr, last_instr.va_layout, last_instr.priv_level)
        if va_layout != -1:
            final_addr = phys2virt(fuzzerstate.final_bb_base_addr, priv_level, va_layout, fuzzerstate, True)
            # print(f"Final addr: {hex(final_addr)} at {hex(fuzzerstate.final_bb_base_addr)} in layout {va_layout} and priv {priv_level.name}. Last instr: {last_instr.get_str()}")
    # # len(flat_instr_objs)+1: the +1 is to reach the final basic block and thereby overwrite the potential destination register of a jal/jalr
    # for i in range(len(regdump_reqs)):
    #     print(f"until {hex(regdump_reqs[i][0])}")
    #     run_trace_regs_at_pc_locs(fuzzerstate.instance_to_str(), spike_resolution_elfpath, get_design_march_flags(design_name), SPIKE_STARTADDR, regdump_reqs[:i+1], False, final_addr, fuzzerstate.num_pickable_floating_regs if fuzzerstate.design_has_fpu else 0, fuzzerstate.design_has_fpud)

    march_flags = get_design_march_flags_nocompressed(design_name) if not USE_COMPRESSED else get_design_march_flags(design_name)
    regvals, (finalintregvals_spikeresol, finalfpuregvals_spikeresol) = run_trace_regs_at_pc_locs(fuzzerstate.instance_to_str(), spike_resolution_elfpath, march_flags, SPIKE_STARTADDR, regdump_reqs, True, final_addr, fuzzerstate.num_pickable_floating_regs if fuzzerstate.design_has_fpu else 0, fuzzerstate.design_has_fpud)

    # retrieves the register value stream throughout execution to compare to in-situ sim
    rd_regdump_reqs = gen_regdump_reqs_all_rds(fuzzerstate)
    # for i in range(1,len(rd_regdump_reqs)):
        # print(f"testing {hex(rd_regdump_reqs[i-1][0])}")
    rd_regvals = run_trace_regs_at_pc_locs(fuzzerstate.instance_to_str(), spike_resolution_elfpath,march_flags, SPIKE_STARTADDR, rd_regdump_reqs, False, fuzzerstate.final_bb_base_addr+SPIKE_STARTADDR, fuzzerstate.num_pickable_floating_regs if fuzzerstate.design_has_fpu else 0, fuzzerstate.design_has_fpud)

    if not NO_REMOVE_TMPFILES and not return_interm:
        os.remove(spike_resolution_elfpath)
        del spike_resolution_elfpath

    # IMPORTANT: We reset the randomness here to have deterministic branch instructions.
    # (Rare) example where it matters: assume we need to pop the last bb, say with id 20. Then we could have a bug with request size 19 but not with request size 20, or vice versa.
    random.seed(fuzzerstate.randseed) # We could as well seed with zero here.
    _feed_regdump_to_instrs(fuzzerstate, regvals)

    # Use spike to check the rtl elf if requested
    if check_pc_spike_again:
        # Generate the RTL ELF, but located for spike at SPIKE_STARTADDR
        rtl_spike_elfpath = gen_elf_from_bbs(fuzzerstate, False, 'spikedoublecheck', fuzzerstate.instance_to_str(), SPIKE_STARTADDR)
        rtl_spike_pc_seq, (finalintregvals_spikecheck, finalfpuregvals_spikecheck) = run_trace_all_pcs(fuzzerstate.instance_to_str(), rtl_spike_elfpath, march_flags, len(flat_instr_objs), SPIKE_STARTADDR, True,  fuzzerstate.num_pickable_floating_regs if fuzzerstate.design_has_fpu else 0, fuzzerstate.design_has_fpud, fuzzerstate)
        if not NO_REMOVE_TMPFILES:
            os.remove(rtl_spike_elfpath)
            del rtl_spike_elfpath

        # Check PC sequence
        _check_pc_trace_from_spike(fuzzerstate, rtl_spike_pc_seq)
        # Check register matching
        try:
            for reg_id in range(1, fuzzerstate.num_pickable_regs):
                # The transient registers are not expected to match.
                if fuzzerstate.intregpickstate.get_regstate(reg_id) in (IntRegIndivState.FREE, IntRegIndivState.CONSUMED):
                    assert finalintregvals_spikeresol[reg_id] == finalintregvals_spikecheck[reg_id], f"Mismatch in x{reg_id} value. Resolution: `{hex(finalintregvals_spikeresol[reg_id])}`, check: `{hex(finalintregvals_spikecheck[reg_id])}`. Reg state: `{fuzzerstate.intregpickstate.get_regstate(reg_id)}`."
            if fuzzerstate.design_has_fpu:
                for reg_id in range(fuzzerstate.num_pickable_floating_regs):
                    assert finalfpuregvals_spikeresol[reg_id] == finalfpuregvals_spikecheck[reg_id], f"Mismatch in f{reg_id} value. Resolution: `{hex(finalfpuregvals_spikeresol[reg_id])}`, check: `{hex(finalintregvals_spikecheck[reg_id])}`."
        except:
            InvalidProgramException(fuzzerstate,"There was a register mismatch between the spike resolution and the final program. It is most likly due to to a program with many \
                instructions. We have to add some instructions to the debug commands beacuse the page fault exceptions do not immediatly go to the next instruction \
                if we pop some blocks, we might end up with too many r 1 commands in the doublecheck")
            

    return (finalintregvals_spikeresol[1:], finalfpuregvals_spikeresol, rd_regdump_reqs, rd_regvals), spike_resolution_elfpath


def spike_resolution_return_interm(fuzzerstate, check_pc_spike_again: bool = False):
    raise NotImplementedError("Depricated, use spike_resolution instead.")
    design_name = fuzzerstate.design_name
    _transmit_addrs_to_producers_for_spike_resolution(fuzzerstate)
    # _transmit_noreloc_to_consumers_for_spike_resolution(fuzzerstate)
    # print('start addrs', list(map(hex, fuzzerstate.bb_start_addr_seq)))
    spike_resolution_elfpath = gen_elf_from_bbs(fuzzerstate, True, 'spikeresol', fuzzerstate.instance_to_str(), SPIKE_STARTADDR)
    # print('Spike resolution elfpath:', spike_resolution_elfpath)
    regdump_reqs = gen_regdump_reqs(fuzzerstate)
    flat_instr_objs = list(itertools.chain.from_iterable(fuzzerstate.instr_objs_seq))
    # len(flat_instr_objs)+1: the +1 is to reach the final basic block and thereby overwrite the potential destination register of a jal/jalr
    regvals, (finalintregvals_spikeresol, finalfpuregvals_spikeresol) = run_trace_regs_at_pc_locs(fuzzerstate.instance_to_str(), spike_resolution_elfpath, get_design_march_flags(design_name), SPIKE_STARTADDR, regdump_reqs, True, fuzzerstate.final_bb_base_addr+SPIKE_STARTADDR, fuzzerstate.num_pickable_floating_regs if fuzzerstate.design_has_fpu else 0, fuzzerstate.design_has_fpud)

    # retrieves the rd stream throughout execution to compare to milesan sim
    rd_regdump_reqs = gen_regdump_reqs_all_rds(fuzzerstate)
    rd_regvals = run_trace_regs_at_pc_locs(fuzzerstate.instance_to_str(), spike_resolution_elfpath, get_design_march_flags(design_name), SPIKE_STARTADDR, rd_regdump_reqs, False, fuzzerstate.final_bb_base_addr+SPIKE_STARTADDR, fuzzerstate.num_pickable_floating_regs if fuzzerstate.design_has_fpu else 0, fuzzerstate.design_has_fpud)

    # IMPORTANT: We reset the randomness here to have deterministic branch instructions.
    # (Rare) example where it matters: assume we need to pop the last bb, say with id 20. Then we could have a bug with request size 19 but not with request size 20, or vice versa.
    random.seed(fuzzerstate.randseed) # We could as well seed with zero here.
    _feed_regdump_to_instrs(fuzzerstate, regvals)

    # Use spike to check the rtl elf if requested
    if check_pc_spike_again:
        # Generate the RTL ELF, but located for spike at SPIKE_STARTADDR
        rtl_spike_elfpath = gen_elf_from_bbs(fuzzerstate, False, 'spikedoublecheck', fuzzerstate.instance_to_str(), SPIKE_STARTADDR)
        # if NO_REMOVE_TMPFILES:
        #     print('rtl_spike_elfpath:', rtl_spike_elfpath)
        rtl_spike_pc_seq, (finalintregvals_spikecheck, finalfpuregvals_spikecheck) = run_trace_all_pcs(fuzzerstate.instance_to_str(), rtl_spike_elfpath, get_design_march_flags(design_name), len(flat_instr_objs)+1, SPIKE_STARTADDR, True,  fuzzerstate.num_pickable_floating_regs if fuzzerstate.design_has_fpu else 0, fuzzerstate.design_has_fpud, fuzzerstate)
        if not NO_REMOVE_TMPFILES:
            os.remove(rtl_spike_elfpath)
            del rtl_spike_elfpath

        # Check PC sequence
        _check_pc_trace_from_spike(fuzzerstate, rtl_spike_pc_seq)
        # Check register matching
        for reg_id in range(1, fuzzerstate.num_pickable_regs):
            # The transient registers are not expected to match.
            if fuzzerstate.intregpickstate.get_regstate(reg_id) in (IntRegIndivState.FREE, IntRegIndivState.CONSUMED):
                assert finalintregvals_spikeresol[reg_id] == finalintregvals_spikecheck[reg_id], f"Mismatch in x{reg_id} value. Resolution: `{hex(finalintregvals_spikeresol[reg_id])}`, check: `{hex(finalintregvals_spikecheck[reg_id])}`. Reg state: `{fuzzerstate.intregpickstate.get_regstate(reg_id)}`."
        if fuzzerstate.design_has_fpu:
            for reg_id in range(fuzzerstate.num_pickable_floating_regs):
                assert finalfpuregvals_spikeresol[reg_id] == finalfpuregvals_spikecheck[reg_id], f"Mismatch in f{reg_id} value. Resolution: `{hex(finalfpuregvals_spikeresol[reg_id])}`, check: `{hex(finalintregvals_spikecheck[reg_id])}`."

    return (finalintregvals_spikeresol[1:], finalfpuregvals_spikeresol, rd_regdump_reqs, rd_regvals), spike_resolution_elfpath

