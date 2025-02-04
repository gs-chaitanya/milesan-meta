# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script is responsible for generating the basic blocks

from params.runparams import DO_ASSERT
from common.spike import SPIKE_STARTADDR
from rv.csrids import CSR_IDS
from params.fuzzparams import BRANCH_TAKEN_PROBA, LIMIT_MEM_SATURATION_RATIO, RANDOM_DATA_BLOCK_MIN_SIZE_BYTES, RANDOM_DATA_BLOCK_MAX_SIZE_BYTES, FENCE_CF_INSTR
from params.fuzzparams import USE_MMU, P_RANDOM_DATA_TAINTED, MIN_N_RANDOM_DATA_BLOCKS, MAX_N_RANDOM_DATA_BLOCKS, P_PAGE_HAS_TAINT, TAINT_EN, ALLOW_NONTAKEN_BRANCHES_IN_TAINT_SOURCE_PRIVS, ALLOW_NONTAKEN_BRANCHES_IN_TAINT_SINK_PRIVS, ALLOW_NONTAKEN_BRANCHES_IN_NEUTRAL_PRIVS, ALLOW_JALR_IN_NEUTRAL_PRIVS, ALLOW_BRANCH_IN_NEUTRAL_PRIVS
from params.fuzzparams import FILL_MEM_WITH_DEAD_CODE, NUM_MAX_N_INSTRS
from params.runparams import INSERT_REGDUMPS, INSERT_FENCE, GET_DATA, DEBUG_PRINT
from milesan.randomize.createcfinstr import create_instr, create_regfsm_instrobjs, create_memfsm_instrobjs
from milesan.randomize.pickinstrtype import gen_next_instrstr_from_isaclass
from milesan.randomize.pickisainstrclass import gen_next_isainstrclass, ISAInstrClass
from milesan.randomize.pickmemop import get_alignment_bits, is_instrstr_load
from milesan.randomize.pickfpuop import gen_fpufsm_instrs
from milesan.randomize.pickexceptionop import gen_exception_instr, gen_tvecfill_instr, gen_epcfill_instr, gen_medeleg_instr, gen_ppfill_instrs
from milesan.randomize.pickrandomcsrop import gen_random_csr_op
from milesan.randomize.pickprivilegedescentop import gen_priv_descent_instr
from milesan.randomize.forbidden_random_value import is_forbidden_random_value
from milesan.randomize.pickcleartaintops import clear_taints_with_random_instructions
from milesan.randomize.createspeculativeinstr import create_speculative_instrs
from milesan.cfinstructionclasses import is_placeholder, JALInstruction, JALRInstruction, BranchInstruction, ExceptionInstruction, TvecWriterInstruction, EPCWriterInstruction, GenericCSRWriterInstruction, MisalignedMemInstruction, PrivilegeDescentInstruction, MstatusWriterInstruction, SimpleExceptionEncapsulator, SpeculativeInstructionEncapsulator
from milesan.util import get_range_bits_per_instrclass, IntRegIndivState, BASIC_BLOCK_MIN_SPACE, INSTRUCTIONS_BY_ISA_CLASS, MmuState
from milesan.finalblock import get_finalblock_max_size,finalblock
from milesan.initialblock import gen_initial_basic_block
from milesan.blacklist import blacklist_changing_instructions, blacklist_final_block, blacklist_context_setter
from milesan.privilegestate import PrivilegeStateEnum
from milesan.toleratebugs import is_tolerate_ras1
from milesan.mmu_utils import phys2virt
from milesan.randomize.pickmmuop import update_mmu_fsm_rv32, update_mmu_fsm_rv64
from milesan.mmu_utils import PHYSICAL_PAGE_SIZE, PAGE_ALIGNMENT_SHIFT, PAGE_ALIGNMENT_MASK, PAGE_ALIGNMENT_BITS

from milesan.gen_ctxt_final_block import *

import numpy as np
import random
CURR_ALLOC_CURSOR_INC = 12 if INSERT_FENCE and INSERT_REGDUMPS else 8 if INSERT_REGDUMPS else 4
MAX_N_TRIES_FOR_BB_ADDR = 500
# Given the provided control flow instruction, finds a location for a new block, but does not allocate it.
# @return False if could not find a next bb address
def gen_next_bb_addr(fuzzerstate, isa_class: ISAInstrClass, curr_addr: int):
    range_bits_each_direction = get_range_bits_per_instrclass(isa_class)

    # We must select the next basic block address before the resolution. 
    # It is selected before allocating the next cf-instruction, so we must ensure it is not placed right at the current PC or the PCs occupied by inserted helper instructions.
    next_bb_addr = None
    curr_paddr = fuzzerstate.get_curr_paddr(add_spike_offset=False)
    n_tries = 0
    while next_bb_addr is None or curr_paddr in range(next_bb_addr,next_bb_addr+BASIC_BLOCK_MIN_SPACE):
        next_bb_addr = fuzzerstate.memview.gen_random_free_addr(4, BASIC_BLOCK_MIN_SPACE, curr_addr - (1 << range_bits_each_direction), curr_addr + (1 << range_bits_each_direction), priv = fuzzerstate.privilegestate.privstate)
        n_tries += 1
        if n_tries > MAX_N_TRIES_FOR_BB_ADDR:
            return False
    fuzzerstate.next_bb_addr = next_bb_addr
    # print(f"Next BB at {hex(fuzzerstate.next_bb_addr)}, checked free until {hex(fuzzerstate.next_bb_addr+BASIC_BLOCK_MIN_SPACE)} curr paddr at {hex(fuzzerstate.get_curr_paddr(add_spike_offset=False))}")

    # if DO_ASSERT:
    #     assert next_bb_addr not in range(curr_paddr,curr_paddr+4*(1+int(INSERT_REGDUMPS)+int(INSERT_FENCE))), f"{hex(next_bb_addr)} not allowed."
    #     assert next_bb_addr+BASIC_BLOCK_MIN_SPACE not in range(curr_paddr,curr_paddr+4*(1+int(INSERT_REGDUMPS)+int(INSERT_FENCE))),  f"{hex(next_bb_addr)} not allowed."

    # If we could not find a new address where to place the next basic block, then return and consider this stage complete.
    if fuzzerstate.next_bb_addr is None:
        return False

    if USE_MMU and DO_ASSERT:
        assert fuzzerstate.privilegestate.privstate in fuzzerstate.pagetablestate.ppn_leaf_to_priv_dict[(fuzzerstate.next_bb_addr&PAGE_ALIGNMENT_MASK)+SPIKE_STARTADDR], f"Generated BB addr does not match required privilege: {fuzzerstate.privilegestate.privstate.name} not in {[p.name for p in fuzzerstate.pagetablestate.ppn_leaf_to_priv_dict[(fuzzerstate.next_bb_addr&PAGE_ALIGNMENT_MASK)+SPIKE_STARTADDR]]}"

    # print(f"Next BB at {hex(fuzzerstate.next_bb_addr)} : {hex(fuzzerstate.next_bb_addr+BASIC_BLOCK_MIN_SPACE)}")
    # assert fuzzerstate.memview.is_mem_range_free(fuzzerstate.next_bb_addr, fuzzerstate.next_bb_addr+BASIC_BLOCK_MIN_SPACE)
    return True

def is_there_more_space_for_bb(fuzzerstate, required_space: int = BASIC_BLOCK_MIN_SPACE):
    if  NUM_MAX_N_INSTRS > 0 and sum([len(i) for i in fuzzerstate.instr_objs_seq]) >= NUM_MAX_N_INSTRS:
        return False
    if USE_MMU:
        ret = fuzzerstate.memview.get_available_contig_space() > required_space and fuzzerstate.privilegestate.privstate in fuzzerstate.pagetablestate.ppn_leaf_to_priv_dict[((fuzzerstate.get_curr_paddr(add_spike_offset=False)+required_space)&PAGE_ALIGNMENT_MASK)+SPIKE_STARTADDR]
        return ret
    return fuzzerstate.memview.get_available_contig_space() > required_space
# The first BASIC_BLOCK_MIN_SPACE must be pre-allocated. The rationale is that we want to pre-allocate at least for the first basic block, to prevent the store data from landing exactly there.
# @return True iff the creation is successful
def gen_basicblock(fuzzerstate):
    fuzzerstate.init_new_bb() # Update fuzzer state to support a new basic block
    if DO_ASSERT:
        if USE_MMU:
            assert fuzzerstate.privilegestate.privstate in fuzzerstate.pagetablestate.ppn_leaf_to_priv_dict[(fuzzerstate.curr_bb_start_addr&PAGE_ALIGNMENT_MASK)+SPIKE_STARTADDR], f"Trying to allocate BB in page that does not match it's privilege: {fuzzerstate.privilegestate.privstate.name} not in {[p.name for p in fuzzerstate.pagetablestate.ppn_leaf_to_priv_dict[(fuzzerstate.curr_bb_start_addr&PAGE_ALIGNMENT_MASK)+SPIKE_STARTADDR]]}"
    # This points to the first address after the current basic block allocation. The block allocation takes 16 bytes in advance, to avoid storing and then not being able to continue expanding the basic block.
    # curr_alloc_cursor = fuzzerstate.curr_bb_start_addr + BASIC_BLOCK_MIN_SPACE
    curr_isa_class = None # This is used in case there is only space for control flow

    # We stop the instruction generation either when there is no more space available, or when we encounter an end-of-state instruction
    while is_there_more_space_for_bb(fuzzerstate):
        if fuzzerstate.num_instr_to_stay_in_prv > 0:
            fuzzerstate.num_instr_to_stay_in_prv -= 1
        if fuzzerstate.num_instr_to_stay_in_layout > 0:
            fuzzerstate.num_instr_to_stay_in_layout -= 1

        # Allocate the next 4 bytes
        # fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+CURR_ALLOC_CURSOR_INC)
        # curr_alloc_cursor += CURR_ALLOC_CURSOR_INC

        # curr_addr = fuzzerstate.curr_bb_start_addr + 4*len(fuzzerstate.instr_objs_seq[-1])
        curr_addr = fuzzerstate.get_curr_paddr(add_spike_offset = False)

        # Get the next instruction class
        curr_isa_class = gen_next_isainstrclass(fuzzerstate, curr_addr)

        # If this is an MMU operation
        if curr_isa_class == ISAInstrClass.MMU:
            # Update MMU fsm
            if fuzzerstate.is_design_64bit:
                new_instrobjs = update_mmu_fsm_rv64(fuzzerstate, curr_addr)
            else:
                new_instrobjs = update_mmu_fsm_rv32(fuzzerstate, curr_addr)
            if new_instrobjs != None:
                fuzzerstate.append_and_execute_instr(new_instrobjs[0])
                # We always need more than 1 instruction to switch address space
                for next_instrobj_id in range(1, len(new_instrobjs)):
                    # fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+CURR_ALLOC_CURSOR_INC)
                    # curr_alloc_cursor += CURR_ALLOC_CURSOR_INC
                    fuzzerstate.append_and_execute_instr(new_instrobjs[next_instrobj_id])
                if GET_DATA and fuzzerstate.effective_curr_layout != -1:
                    fuzzerstate.num_virt_pc += len(new_instrobjs)
                del new_instrobjs # For safety, we prevent accidental reuse of this variable
                continue
            # for rv32, if we only change layouts
            else:
                curr_isa_class = gen_next_isainstrclass(fuzzerstate, curr_addr, True)


        # If this is an instruction that influences offset register states
        if curr_isa_class == ISAInstrClass.REGFSM:
            new_instrobjs = create_regfsm_instrobjs(fuzzerstate)
            fuzzerstate.append_and_execute_instr(new_instrobjs[0])
            # For consumers, we may need to insert one more instruction
            for new_instrobj in new_instrobjs[1:]:
                # fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+CURR_ALLOC_CURSOR_INC)
                # curr_alloc_cursor += CURR_ALLOC_CURSOR_INC
                fuzzerstate.append_and_execute_instr(new_instrobj)
            del new_instrobjs
            continue

        if curr_isa_class == ISAInstrClass.CLEARTAINT:
            new_instrobjs = clear_taints_with_random_instructions(fuzzerstate)
            fuzzerstate.append_and_execute_instr(new_instrobjs[0])
            # For consumers, we may need to insert one more instruction
            for new_instrobj in new_instrobjs[1:]:
                # fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+CURR_ALLOC_CURSOR_INC)
                # curr_alloc_cursor += CURR_ALLOC_CURSOR_INC
                fuzzerstate.append_and_execute_instr(new_instrobj)
            del new_instrobjs
            continue

        
        # If this is an FPU enable-disable instruction or a rounding mode change
        elif curr_isa_class == ISAInstrClass.FPUFSM:
            assert False, "not implemented"
            new_instrobjs = gen_fpufsm_instrs(fuzzerstate)
            if len(new_instrobjs) == 1: # Equivalent to FPU enable/disable
                fuzzerstate.fpuendis_coords.append((len(fuzzerstate.instr_objs_seq)-1, len(fuzzerstate.instr_objs_seq[-1])))
            if DO_ASSERT:
                assert len(new_instrobjs) * 4 < BASIC_BLOCK_MIN_SPACE # NO_COMPRESSED
            for new_instrobj in new_instrobjs:
                fuzzerstate.append_and_execute_instr(new_instrobj, True)
            if len(new_instrobjs) > 1:
                fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+CURR_ALLOC_CURSOR_INC*(len(new_instrobjs)-1)) # NO_COMPRESSED
                curr_alloc_cursor += CURR_ALLOC_CURSOR_INC*(len(new_instrobjs)-1) # NO_COMPRESSED
            del new_instrobjs # For safety, we prevent accidental reuse of this variable
            continue

        # If this is a privilege descent instruction or an mpp/spp write instruction
        elif curr_isa_class == ISAInstrClass.DESCEND_PRV:
            # print('Priv descent at addr', hex(curr_addr+SPIKE_STARTADDR), 'privstate', fuzzerstate.privilegestate.privstate)
            # print('  New privstate', fuzzerstate.privilegestate.privstate)
            # Create space for the next basic block.
            new_instrobjs = gen_priv_descent_instr(fuzzerstate)
            # First generate the instrucion, only then allocate for the next BB s.t. we allocate for the right privilege.
            if not gen_next_bb_addr(fuzzerstate, curr_isa_class, curr_addr):
                # Abort the bb
                fuzzerstate.instr_objs_seq.pop()
                fuzzerstate.bb_start_addr_seq.pop()
                fuzzerstate.restore_states()
                return False

            fuzzerstate.append_and_execute_instr(new_instrobjs[0])
            for new_instrobj_id in range(1, len(new_instrobjs)):
                # fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+CURR_ALLOC_CURSOR_INC)
                # curr_alloc_cursor += CURR_ALLOC_CURSOR_INC
                fuzzerstate.append_and_execute_instr(new_instrobjs[new_instrobj_id])
                
            if DEBUG_PRINT: print(f"priv change at addr: {hex(curr_addr+SPIKE_STARTADDR)} to ", fuzzerstate.privilegestate.privstate)

            del new_instrobjs
            return True

        elif curr_isa_class == ISAInstrClass.PPFSM:
            # assert False, "not implemented"
            new_instrobjs = gen_ppfill_instrs(fuzzerstate)
            # if DO_ASSERT:
            #     assert len(new_instrobjs) * CURR_ALLOC_CURSOR_INC < BASIC_BLOCK_MIN_SPACE # NO_COMPRESSED
            fuzzerstate.append_and_execute_instr(new_instrobjs[0])
            for new_instrobj_id in range(1, len(new_instrobjs)):
                # fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+CURR_ALLOC_CURSOR_INC)
                # curr_alloc_cursor += CURR_ALLOC_CURSOR_INC
                fuzzerstate.append_and_execute_instr(new_instrobjs[new_instrobj_id])
            del new_instrobjs
            continue

        elif curr_isa_class == ISAInstrClass.EXCEPTION:
            # Create space for the next basic block.
            # print('exception at addr', hex(curr_addr), 'privstate', fuzzerstate.privilegestate.privstate)
            new_instrobjs = gen_exception_instr(fuzzerstate)
            # First generate the instructions, only then allocate for the next BB s.t. we allocate for the right privilege.
            if not gen_next_bb_addr(fuzzerstate, curr_isa_class, curr_addr):
                # Abort the bb
                fuzzerstate.instr_objs_seq.pop()
                fuzzerstate.bb_start_addr_seq.pop()
                # fuzzerstate.intregpickstate.restore_state(fuzzerstate.saved_reg_states[-1])
                fuzzerstate.restore_states()
                return False
            # print('  New priv:', fuzzerstate.privilegestate.privstate)
            fuzzerstate.append_and_execute_instr(new_instrobjs[0])
            for new_instrobj_id in range(1, len(new_instrobjs)):
                # fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+CURR_ALLOC_CURSOR_INC)
                # curr_alloc_cursor += CURR_ALLOC_CURSOR_INC
                fuzzerstate.append_and_execute_instr(new_instrobjs[new_instrobj_id])
            del new_instrobjs # For safety, we prevent accidental reuse of this variable
            return True
        
        elif curr_isa_class == ISAInstrClass.MEMFSM:
            new_instrobjs = create_memfsm_instrobjs(fuzzerstate)
            fuzzerstate.append_and_execute_instr(new_instrobjs[0])
            for new_instrobj_id in range(1, len(new_instrobjs)):
                # fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+CURR_ALLOC_CURSOR_INC)
                # curr_alloc_cursor += CURR_ALLOC_CURSOR_INC
                fuzzerstate.append_and_execute_instr(new_instrobjs[new_instrobj_id])
            del new_instrobjs
            continue

        # Discriminate non-taken branches
        fuzzerstate.curr_branch_taken = False
        if curr_isa_class == ISAInstrClass.BRANCH:
            if fuzzerstate.privilegestate.privstate in fuzzerstate.taint_source_privs and not ALLOW_NONTAKEN_BRANCHES_IN_TAINT_SOURCE_PRIVS or \
                fuzzerstate.privilegestate.privstate in fuzzerstate.taint_sink_privs and not ALLOW_NONTAKEN_BRANCHES_IN_TAINT_SINK_PRIVS or \
                fuzzerstate.privilegestate.privstate not in fuzzerstate.taint_source_privs|fuzzerstate.taint_sink_privs and not ALLOW_NONTAKEN_BRANCHES_IN_NEUTRAL_PRIVS:
                fuzzerstate.curr_branch_taken = True
            else:
                fuzzerstate.curr_branch_taken = random.random() < BRANCH_TAKEN_PROBA

        # Compute the address of the next basic block if we are exiting the current
        if curr_isa_class in (ISAInstrClass.JAL, ISAInstrClass.JALR) or fuzzerstate.curr_branch_taken:
            # Gen the next bb addr
            if not gen_next_bb_addr(fuzzerstate, curr_isa_class, curr_addr):
                # Abort the bb
                fuzzerstate.instr_objs_seq.pop()
                fuzzerstate.bb_start_addr_seq.pop()
                # fuzzerstate.intregpickstate.restore_state(fuzzerstate.saved_reg_states[-1])
                fuzzerstate.restore_states()
                # deallocate memory region?
                return False

        # Get an instruction string for this ISA class
        # We have some special cases for instructions that are not entirely characterized by an instruction string
        next_instr = None # Just a safety measure to ensure we don't use a stale one by mistake
        if curr_isa_class == ISAInstrClass.MEDELEG:
            if DO_ASSERT:
                assert fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE, "medeleg can only be used in machine mode, and we do not an exception here."
            next_instr = gen_medeleg_instr(fuzzerstate)
        elif curr_isa_class == ISAInstrClass.TVECFSM:
            # print('tvec writer at addr', hex(curr_addr), 'privstate', fuzzerstate.privilegestate.privstate)
            next_instr = gen_tvecfill_instr(fuzzerstate)
        elif curr_isa_class == ISAInstrClass.EPCFSM:
            next_instr = gen_epcfill_instr(fuzzerstate)
        elif curr_isa_class == ISAInstrClass.RANDOM_CSR:
            next_instr = gen_random_csr_op(fuzzerstate)
        else:
            if FENCE_CF_INSTR and curr_isa_class in (ISAInstrClass.JALR, ISAInstrClass.BRANCH):
                # curr_addr = fuzzerstate.curr_bb_start_addr + 4*len(fuzzerstate.instr_objs_seq[-1])
                curr_addr = fuzzerstate.get_curr_paddr(add_spike_offset = False)
                next_instr = create_instr('fence', fuzzerstate, curr_addr)
                fuzzerstate.append_and_execute_instr(next_instr)
            
            # curr_addr = fuzzerstate.curr_bb_start_addr + 4*len(fuzzerstate.instr_objs_seq[-1])
            curr_addr = fuzzerstate.get_curr_paddr(add_spike_offset = False)
            instr_str = gen_next_instrstr_from_isaclass(curr_isa_class, fuzzerstate)
            next_instr = create_instr(instr_str, fuzzerstate, curr_addr)
        fuzzerstate.append_and_execute_instr(next_instr)

        if curr_isa_class in (ISAInstrClass.JAL, ISAInstrClass.JALR) or fuzzerstate.curr_branch_taken:
            return True
        # If this is the end of the basic block, then we quit this function. The part after the loop is reserved for cases where we need to urgently change control flow.

    # This is reached if we need to urgently jump to the next basic block, either because we ran out of available contiguous memory
    # or because we've reached a page boundary, and the next page is reserved for a different privelege.
    # The algorithm is the following: if there is a possibility to jump immediately, then do so. Else, prepare the registers as fast as possible.

    # If the regfsm is not IDLE, we cannot use JALR. Bringing it to maturity would increase the minimal ammount of instr, 
    # so we dont chhose JALR in this case
    curr_addr = fuzzerstate.get_curr_paddr(add_spike_offset = False)
    if fuzzerstate.curr_mmu_state != MmuState.IDLE:
        curr_isa_class = random.choices([ISAInstrClass.JAL, ISAInstrClass.BRANCH], [1, 1], k=1)[0]
    elif fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE:
        curr_isa_class = random.choices([ISAInstrClass.JAL, ISAInstrClass.JALR, ISAInstrClass.BRANCH], [1, int(ALLOW_JALR_IN_NEUTRAL_PRIVS), int(ALLOW_BRANCH_IN_NEUTRAL_PRIVS)], k=1)[0]
    else:
        curr_isa_class = random.choices([ISAInstrClass.JAL, ISAInstrClass.JALR, ISAInstrClass.BRANCH], [1, 1, 1], k=1)[0]


    # No need for any preparation if jal, because it has no true dependency
    if curr_isa_class in (ISAInstrClass.JAL, ISAInstrClass.BRANCH):
        # Gen the next bb addr
        # curr_addr = fuzzerstate.curr_bb_start_addr + 4*len(fuzzerstate.instr_objs_seq[-1])
        curr_addr = fuzzerstate.get_curr_paddr(add_spike_offset = False)
        if not gen_next_bb_addr(fuzzerstate, curr_isa_class, curr_addr):
            # Abort the bb
            fuzzerstate.instr_objs_seq.pop()
            fuzzerstate.bb_start_addr_seq.pop()
            # fuzzerstate.intregpickstate.restore_state(fuzzerstate.saved_reg_states[-1])
            fuzzerstate.restore_states()
            return False
        if curr_isa_class == ISAInstrClass.JAL:
            # curr_addr = fuzzerstate.curr_bb_start_addr + 4*len(fuzzerstate.instr_objs_seq[-1])
            curr_addr = fuzzerstate.get_curr_paddr(add_spike_offset = False)
            next_instr = create_instr('jal', fuzzerstate, curr_addr)
            fuzzerstate.append_and_execute_instr(next_instr)
        elif curr_isa_class == ISAInstrClass.BRANCH:
            if FENCE_CF_INSTR:
                # curr_addr = fuzzerstate.curr_bb_start_addr + 4*len(fuzzerstate.instr_objs_seq[-1])
                curr_addr = fuzzerstate.get_curr_paddr(add_spike_offset = False)
                next_instr = create_instr('fence', fuzzerstate, curr_addr)
                fuzzerstate.append_and_execute_instr(next_instr)
            fuzzerstate.curr_branch_taken = True
            # The branch type does not matter because it will be re-determined once the operand values are known
            # curr_addr = fuzzerstate.curr_bb_start_addr + 4*len(fuzzerstate.instr_objs_seq[-1])
            curr_addr = fuzzerstate.get_curr_paddr(add_spike_offset = False)
            next_instr = create_instr('bne', fuzzerstate, curr_addr)
            fuzzerstate.append_and_execute_instr(next_instr)
        else:
            raise ValueError(f"Unexpected isa class `{curr_isa_class}`")

    else:
        # For JALR, bring some reg to maturity, and then insert the control flow instruction
        if DO_ASSERT:
            assert curr_isa_class == ISAInstrClass.JALR

        # We allocated too many instructions in one go and now have to abort BB generation since there's not enough space left to jump to another BB.
        # This can happen e.g. when clearing register taints and several instructions are added without checking how much contiguos space is left. 
        if not fuzzerstate.memview.get_available_contig_space() > BASIC_BLOCK_MIN_SPACE:
            # Abort the bb
            fuzzerstate.instr_objs_seq.pop()
            fuzzerstate.bb_start_addr_seq.pop()
            # fuzzerstate.intregpickstate.restore_state(fuzzerstate.saved_reg_states[-1])
            fuzzerstate.restore_states()
            # deallocate memory region?
            return False

        fuzzerstate.intregpickstate.bring_some_reg_to_state(IntRegIndivState.CONSUMED, fuzzerstate)

        if FENCE_CF_INSTR:
            # curr_addr = fuzzerstate.curr_bb_start_addr + 4*len(fuzzerstate.instr_objs_seq[-1])
            curr_addr = fuzzerstate.get_curr_paddr(add_spike_offset = False)
            next_instr = create_instr('fence', fuzzerstate, curr_addr)
            fuzzerstate.append_and_execute_instr(next_instr)

        # curr_addr = fuzzerstate.curr_bb_start_addr + 4*len(fuzzerstate.instr_objs_seq[-1]) # NO_COMPRESSED
        curr_addr = fuzzerstate.get_curr_paddr(add_spike_offset = False)
        # Gen the next bb addr
        if not gen_next_bb_addr(fuzzerstate, curr_isa_class, curr_addr):
            # Abort the bb
            fuzzerstate.instr_objs_seq.pop()
            fuzzerstate.bb_start_addr_seq.pop()
            # fuzzerstate.intregpickstate.restore_state(fuzzerstate.saved_reg_states[-1])
            fuzzerstate.restore_states()
            return False

        next_instr = create_instr('jalr', fuzzerstate, curr_addr)
        fuzzerstate.append_and_execute_instr(next_instr)

# This must be done early, say, just after generating the first basic block, to ensure that we have enough space.
# @param: page_has_taint: allow that this page contains tainted data. Parameter is ignored if taint is disabled.
def gen_random_data_block(fuzzerstate, page_has_taint = False):
    # The rng should have randomness that follows from the system random state but not have any reciprocal effects
    # This is necessary s.t. the bugs can be enabled/disabled without further influencing program construction 
    rng = np.random.RandomState(random.randrange(0,2**31)) 
    # lenbytes = random.randrange(RANDOM_DATA_BLOCK_MIN_SIZE_BYTES, RANDOM_DATA_BLOCK_MAX_SIZE_BYTES)
    lenbytes = PHYSICAL_PAGE_SIZE # We only allocate pages the size of a frame (i.e. physical page) for now.
    # fuzzerstate.random_data_block_start_addr = fuzzerstate.memview.gen_random_free_addr(2, lenbytes, 0, fuzzerstate.memsize)
    # fuzzerstate.random_data_block_end_addr = fuzzerstate.random_data_block_start_addr + lenbytes
    random_data_block_start_addr = fuzzerstate.memview.gen_random_free_addr(PAGE_ALIGNMENT_SHIFT, lenbytes, 0, fuzzerstate.memsize)
    if DO_ASSERT:
        assert random_data_block_start_addr is not None, f"Could not allocate random block of size {hex(lenbytes)} bytes."
        assert random_data_block_start_addr&PAGE_ALIGNMENT_BITS == 0 ,"Random data block needs to be page aligned."
    random_data_block_end_addr = random_data_block_start_addr + lenbytes
    if TAINT_EN:
        fuzzerstate.random_data_block_has_taint[random_data_block_start_addr] = page_has_taint
    fuzzerstate.random_data_block_ranges += [(random_data_block_start_addr, random_data_block_end_addr)]
    random_block_content4by4bytes = []
    fuzzerstate.memview.alloc_mem_range(random_data_block_start_addr, random_data_block_end_addr)
    # Generate the random data
    for addr in range(random_data_block_start_addr, random_data_block_end_addr, 4):
        rand_val = None
        while rand_val is None or is_forbidden_random_value(rand_val, 4) and not is_tolerate_ras1(fuzzerstate.design_name):
            rand_val = rng.randint(0, 2**32)
        random_block_content4by4bytes.append(rand_val)
        fuzzerstate.memview.write(addr+SPIKE_STARTADDR, rand_val, 4)
        if TAINT_EN and page_has_taint and random.random() < P_RANDOM_DATA_TAINTED:
            rand_val_t0 = rng.randint(0, 2**32)
            fuzzerstate.memview.write_t0(addr+SPIKE_STARTADDR, rand_val_t0, 4)
    fuzzerstate.random_block_contents4by4bytes.append(random_block_content4by4bytes)

# This must be done early, say, just after generating the first basic block, to ensure that we have enough space.
def alloc_final_basic_block(fuzzerstate):
    lenbytes = get_finalblock_max_size() * 4 # NO_COMPRESSED
    # fuzzerstate.final_bb_base_addr = fuzzerstate.memview.gen_random_free_addr(2, lenbytes, 0, fuzzerstate.memsize)
    final_bb_page_addr = fuzzerstate.memview.gen_random_free_addr(PAGE_ALIGNMENT_SHIFT, PHYSICAL_PAGE_SIZE, 0, fuzzerstate.memsize)
    if DO_ASSERT:
        assert final_bb_page_addr is not None, f"Maybe you should create the final basic block earlier in the creation of the test case."
    fuzzerstate.final_bb_base_addr = random.randrange(final_bb_page_addr, final_bb_page_addr+PHYSICAL_PAGE_SIZE-lenbytes, 4)
    fuzzerstate.memview.alloc_mem_range(final_bb_page_addr, final_bb_page_addr+PHYSICAL_PAGE_SIZE)


def alloc_initial_basic_block(fuzzerstate):
    fuzzerstate.reset()
    # Setup the address of the initial BB and allocate a page for it. This way we avoid that any PTEs are written to the same page.
    fuzzerstate.init_new_bb() # Update fuzzer state to support a new basic block.
    fuzzerstate.memview.alloc_mem_range(fuzzerstate.curr_bb_start_addr&PAGE_ALIGNMENT_MASK, (fuzzerstate.curr_bb_start_addr&PAGE_ALIGNMENT_MASK)+PHYSICAL_PAGE_SIZE) # NO_COMPRESSED

# This must be done early, say, just after generating the final basic block, to ensure that we have enough space.
def alloc_context_saver_bb(fuzzerstate):
    n_pages = fuzzerstate.ctxsv_size_upperbound//PHYSICAL_PAGE_SIZE+1
    fuzzerstate.ctxsv_bb_base_addr = fuzzerstate.memview.gen_random_free_addr(PAGE_ALIGNMENT_SHIFT, n_pages*PHYSICAL_PAGE_SIZE, 0, fuzzerstate.memsize)
    if DO_ASSERT:
        assert fuzzerstate.ctxsv_bb_base_addr is not None, f"Maybe you should create the ctx saver block earlier in the creation of the test case."
    # Cannot have any other code or data in CTX saver pages
    fuzzerstate.memview.alloc_mem_range(fuzzerstate.ctxsv_bb_base_addr, fuzzerstate.ctxsv_bb_base_addr+n_pages*PHYSICAL_PAGE_SIZE)

def free_context_saver_bb(fuzzerstate, ctxsv_bb_id):
    raise NotImplementedError("not implemented yet")
# This function is a bit tricky. The objective is to remove the final basic blocks until we find a basic block that can reach the final block. For example, a far JAL may not be able to each the final block.
# This should be done once all the basic blocks have been inserted until a stop condition was met, such as no more space found for another bb, or memory usage above a certain percentage.
# @return True iff the insertion succeeded. If False, the whole test case generation is considered failed.
def pop_last_bbs_to_connect_with_final_block(fuzzerstate):
    popped_at_least_once = False
    while fuzzerstate.instr_objs_seq:
        # Remove the trailing speculative instructions from the basic block to find the cf instruction.
        while isinstance(fuzzerstate.instr_objs_seq[-1][-1],SpeculativeInstructionEncapsulator):
            fuzzerstate.instr_objs_seq[-1].pop()
        
        # Check whether the last element can target the final bb
        # last_cf_instr_base_addr = # NO_COMPRESSED
        last_cf_instr_base_addr = fuzzerstate.instr_objs_seq[-1][-1].paddr - SPIKE_STARTADDR
        if isinstance(fuzzerstate.instr_objs_seq[-1][-1], JALInstruction):
            range_bits = get_range_bits_per_instrclass(ISAInstrClass.JAL)
        elif isinstance(fuzzerstate.instr_objs_seq[-1][-1], JALRInstruction):
            range_bits = get_range_bits_per_instrclass(ISAInstrClass.JALR)
        elif isinstance(fuzzerstate.instr_objs_seq[-1][-1], BranchInstruction) and fuzzerstate.instr_objs_seq[-1][-1].plan_taken:
            range_bits = get_range_bits_per_instrclass(ISAInstrClass.BRANCH)
        elif isinstance(fuzzerstate.instr_objs_seq[-1][-1], PrivilegeDescentInstruction):
            range_bits = get_range_bits_per_instrclass(ISAInstrClass.DESCEND_PRV)
        elif isinstance(fuzzerstate.instr_objs_seq[-1][-1], ExceptionInstruction):
            range_bits = get_range_bits_per_instrclass(ISAInstrClass.EXCEPTION)
        else:
            raise ValueError(f"Unexpectedly got instruction `{fuzzerstate.instr_objs_seq[-1][-1]}`")
        if fuzzerstate.final_bb_base_addr >= last_cf_instr_base_addr - (1 << range_bits) and fuzzerstate.final_bb_base_addr < last_cf_instr_base_addr + (1 << range_bits):
            # The last basic block of the series is a candidate for jumping to the final block.
            # The target address of the last cf instruction will be injected later.
            if popped_at_least_once:
                # fuzzerstate.intregpickstate.restore_state(fuzzerstate.saved_reg_states[-1])
                fuzzerstate.restore_states()
            return True
        # else, in case the last block could not reach the final block, then we discard it and try with the previous one.
        popped_at_least_once = True
        fuzzerstate.instr_objs_seq.pop()
        fuzzerstate.bb_start_addr_seq.pop()
        # fuzzerstate.saved_reg_states.pop()
        fuzzerstate.pop_states()


        if USE_MMU:
            if DEBUG_PRINT: print(f"Updating fuzzerstate after a pop, old layout: {fuzzerstate.effective_curr_layout}, old_priv: ",fuzzerstate.privilegestate.privstate)
            bb_id, instr_id = len(fuzzerstate.instr_objs_seq)-1, len(fuzzerstate.instr_objs_seq[-1])-1
            layout_id, priv_level = get_last_bb_layout_and_priv(fuzzerstate, bb_id, instr_id)
            # assert layout_id == fuzzerstate.instr_objs_seq[-1][-1].va_layout_after_op
            # assert priv_level == fuzzerstate.instr_objs_seq[-1][-1].priv_level_after_op
            fuzzerstate.privilegestate.privstate = priv_level
            fuzzerstate.effective_curr_layout = layout_id
            if priv_level == PrivilegeStateEnum.MACHINE:
                fuzzerstate.real_curr_layout = get_last_real_layout(fuzzerstate, bb_id, instr_id)
            else:
                fuzzerstate.real_curr_layout = fuzzerstate.effective_curr_layout
            # Get the last mpp
            fuzzerstate.privilegestate.curr_mstatus_mpp = get_last_mpp(fuzzerstate, bb_id, instr_id)
            # Update sum and mprv bits
            fuzzerstate.status_sum_mprv = get_last_sum_mprv(fuzzerstate, bb_id, instr_id)

    return False

# # @return a list of addresses for the memory operations, in their order of occurrence
# def gen_memop_addrs(fuzzerstate):
#     ret = []
#     for bb_instrlist in fuzzerstate.instr_objs_seq:
#         for bb_instr in bb_instrlist:
#             if is_placeholder(bb_instr):
#                 continue
#             elif bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.MEM] or bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.MEM64] or bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.MEMFPU] or bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.MEMFPUD]:
#                 ret.append(pick_memop_addr(fuzzerstate, is_instrstr_load(bb_instr.instr_str), get_alignment_bits(bb_instr.instr_str)))
#     return ret

# @brief This function generates the producer_id_to_tgtaddr dictionary and the producer_id_to_noreloc_spike dictionaries.
def gen_producer_id_to_tgtaddr(fuzzerstate):
    # Two steps. First, generate producer_id_to_tgtaddr. Then, use it to populate the producers with target addresses. The second step is done in another function.

    # Step 1
    index_in_memaddr_array = 0
    index_in_bb_start_addr_seq = 1 # This variable lets us know to which address we wish to jump when some CF instruction is taken
    producer_id_to_tgtaddr = dict() # producer_id_to_tgtaddr[producer_id] = tgt_addr
    producer_id_to_noreloc_spike = dict() # producer_id_to_noreloc_spike[producer_id] = bool, where bool is true if the value we want to specify should not be relocated for spike
    consumer_inst_va_layout = dict() 

    # To facilitate backward propagation of addresses during exceptions, we recall the tvec writes.
    # When they are consumed, we forget them.
    last_mtvec = None # last_mtvec is a tuple (bb_id, instr_id)
    last_stvec = None # last_stvec is a tuple (bb_id, instr_id)
    last_mepc = None  # last_mepc  is a tuple (bb_id, instr_id)
    last_sepc = None  # last_sepc  is a tuple (bb_id, instr_id)

    curr_addr_layout = -1
    curr_priv_state = PrivilegeStateEnum.MACHINE

    for bb_id, bb_instrlist in enumerate(fuzzerstate.instr_objs_seq):
        for bb_instr_id, bb_instr in enumerate(bb_instrlist):
            ###
            # For producer_id_to_noreloc_spike
            ###

            if isinstance(bb_instr, GenericCSRWriterInstruction) and bb_instr.csr_instr.csr_id == CSR_IDS.MEDELEG:
                producer_id_to_noreloc_spike[bb_instr.producer_id] = True

            ###
            # First check for instructions that do not have an instruction string, such as placeholder instructions or some CSR write instructions.
            ###

            if is_placeholder(bb_instr):
                continue

            if isinstance(bb_instr, MstatusWriterInstruction):
                if DO_ASSERT:
                    assert bb_instr.producer_id == -1 or not bb_instr.producer_id in producer_id_to_tgtaddr, "producer_id `{}` of instruction `{}` already of in producer_id_to_tgtaddr".format(bb_instr.producer_id, bb_instr.get_str())
                producer_id_to_tgtaddr[bb_instr.producer_id] = bb_instr.mstatus_mask
                consumer_inst_va_layout[bb_instr.producer_id] = (-1, bb_instr.priv_level)
                continue

            # To facilitate backward propagation of addresses during exceptions
            if isinstance(bb_instr, TvecWriterInstruction):
                if bb_instr.producer_id == -1: continue # Skip the EPC that are not produced (exception handler)
                if bb_instr.is_mtvec:
                    last_mtvec = (bb_id, bb_instr_id)
                else:
                    last_stvec = (bb_id, bb_instr_id)
                continue

            # To facilitate backward propagation of addresses during trap returns
            if isinstance(bb_instr, EPCWriterInstruction):
                if bb_instr.producer_id == -1: continue # Skip the EPC that are not produced (exception handler)
                if bb_instr.is_mepc:
                    last_mepc = (bb_id, bb_instr_id)
                else:
                    last_sepc = (bb_id, bb_instr_id)
                continue

            # To facilitate backward propagation of addresses during exceptions
            if isinstance(bb_instr, GenericCSRWriterInstruction):
                if DO_ASSERT:
                    assert bb_instr.producer_id == -1 or not bb_instr.producer_id in producer_id_to_tgtaddr, "producer_id `{}` of instruction `{}` already of in producer_id_to_tgtaddr".format(bb_instr.producer_id, bb_instr.get_str())
                producer_id_to_tgtaddr[bb_instr.producer_id] = bb_instr.val_to_write_cpu
                consumer_inst_va_layout[bb_instr.producer_id] = (-1, PrivilegeStateEnum.MACHINE)
                continue

            # In case of a privilege descent instruction
            if isinstance(bb_instr, PrivilegeDescentInstruction):
                # Extremely similar to handling exception instruction below
                # Check that a corresponding xepc has been setup
                if DO_ASSERT:
                    assert (bb_instr.is_mret and last_mepc) or (not bb_instr.is_mret and last_sepc), "No epc found for privilege descent instruction. Values are: last_mepc = {}, last_sepc = {}, bb_instr.is_mret = {}".format(last_mepc, last_sepc, bb_instr.is_mret)
                

                # Get the epc instr's producer id
                if bb_instr.is_mret:
                    epc_producer_id = fuzzerstate.instr_objs_seq[last_mepc[0]][last_mepc[1]].producer_id
                    # We have to set the layout id of the EPCWriterInstruction instruction based of the new layout
                    # fuzzerstate.instr_objs_seq[last_mepc[0]][last_mepc[1]].va_layout = bb_instr.va_layout_after_op
                    # fuzzerstate.instr_objs_seq[last_mepc[0]][last_mepc[1]].priv_level = bb_instr.priv_level_after_op
                else:
                    epc_producer_id = fuzzerstate.instr_objs_seq[last_sepc[0]][last_sepc[1]].producer_id
                    # We have to set the layout id of the EPCWriterInstruction instruction based of the new layout
                    # fuzzerstate.instr_objs_seq[last_sepc[0]][last_sepc[1]].va_layout = bb_instr.va_layout_after_op
                    # fuzzerstate.instr_objs_seq[last_sepc[0]][last_sepc[1]].priv_level = bb_instr.priv_level_after_op
                # Get the next bb's start address
                if epc_producer_id > 0: # if -1 it is for the MMU
                    if index_in_bb_start_addr_seq == len(fuzzerstate.bb_start_addr_seq):
                        if DO_ASSERT:
                            assert fuzzerstate.final_bb_base_addr is not None and fuzzerstate.final_bb_base_addr >= 0
                        addr = fuzzerstate.final_bb_base_addr # Final basic block
                    else:
                        addr = fuzzerstate.bb_start_addr_seq[index_in_bb_start_addr_seq]
                        index_in_bb_start_addr_seq += 1
                    if DO_ASSERT:
                        assert epc_producer_id > 0
                else:
                    # if prod id is -1, it is the end of a bb that switches address space
                    index_in_bb_start_addr_seq += 1
                    continue

                if DO_ASSERT:
                    assert epc_producer_id == -1 or not epc_producer_id in producer_id_to_tgtaddr, "producer_id `{}` of instruction `{}` already of in producer_id_to_tgtaddr".format(bb_instr.producer_id, bb_instr.get_str())
                
                producer_id_to_tgtaddr[epc_producer_id] = phys2virt(addr, bb_instr.priv_level_after_op, bb_instr.va_layout_after_op, fuzzerstate)
                consumer_inst_va_layout[epc_producer_id] = (bb_instr.va_layout_after_op, bb_instr.priv_level_after_op)
                if DEBUG_PRINT: print(f"xEPC will be {hex(producer_id_to_tgtaddr[epc_producer_id])} ({hex(addr)}) ", bb_instr.priv_level_after_op)

                # Do not use twice the same epc value because we want to jump to a new basic block.
                if bb_instr.is_mret:
                    last_mepc = None
                else:
                    last_sepc = None

            # In case of an exception instruction, find the last corresponding tvec and transmit the target address
            if isinstance(bb_instr, ExceptionInstruction):

                # Check that a corresponding tvec has been setup
                if DO_ASSERT:
                    assert (bb_instr.is_mtvec and last_mtvec) or (not bb_instr.is_mtvec and last_stvec), "No tvec found for exception instruction. Values are: last_mtvec = {}, last_stvec = {}, bb_instr.is_mtvec = {}".format(last_mtvec, last_stvec, bb_instr.is_mtvec)

                # Get the tvec instr's producer id
                if bb_instr.is_mtvec:
                    tvec_producer_id = fuzzerstate.instr_objs_seq[last_mtvec[0]][last_mtvec[1]].producer_id
                    # fuzzerstate.instr_objs_seq[last_mtvec[0]][last_mtvec[1]].va_layout = bb_instr.va_layout_after_op
                else:
                    tvec_producer_id = fuzzerstate.instr_objs_seq[last_stvec[0]][last_stvec[1]].producer_id
                    # fuzzerstate.instr_objs_seq[last_stvec[0]][last_stvec[1]].va_layout = bb_instr.va_layout_after_op

                # Get the next bb's start address
                if index_in_bb_start_addr_seq == len(fuzzerstate.bb_start_addr_seq):
                    if DO_ASSERT:
                        assert fuzzerstate.final_bb_base_addr is not None and fuzzerstate.final_bb_base_addr >= 0
                    addr = fuzzerstate.final_bb_base_addr # Final basic block
                else:
                    addr = fuzzerstate.bb_start_addr_seq[index_in_bb_start_addr_seq]
                    index_in_bb_start_addr_seq += 1
                if DO_ASSERT:
                    assert tvec_producer_id > 0

                if DO_ASSERT:
                    assert tvec_producer_id == -1 or not tvec_producer_id in producer_id_to_tgtaddr, "producer_id `{}` of instruction `{}` already of in producer_id_to_tgtaddr".format(bb_instr.producer_id, bb_instr.get_str())
                producer_id_to_tgtaddr[tvec_producer_id] = phys2virt(addr, bb_instr.priv_level_after_op, bb_instr.va_layout_after_op, fuzzerstate)
                consumer_inst_va_layout[tvec_producer_id] = (bb_instr.va_layout_after_op, bb_instr.priv_level_after_op)
                if DEBUG_PRINT:
                    print(f"xTVEC will be {hex(producer_id_to_tgtaddr[tvec_producer_id])} ({hex(addr)})")

                # Do not use twice the same tvec value because we want to jump to a new basic block.
                if bb_instr.is_mtvec:
                    last_mtvec = None
                else:
                    last_stvec = None

                # Some exceptions also require their own produced register, not only for tvec but also to make a targeted memory operation
                if bb_instr.producer_id is not None:
                    del addr
                    if isinstance(bb_instr, MisalignedMemInstruction):
                        addr = bb_instr.misaligned_addr
                    elif isinstance(bb_instr, SimpleExceptionEncapsulator):
                        addr = bb_instr.paddr
                    else:
                        raise Exception("We expected only MisalignedMemInstruction to have a producer_id.")

                    if DO_ASSERT:
                        assert bb_instr.producer_id == -1 or not bb_instr.producer_id in producer_id_to_tgtaddr, "producer_id `{}` of instruction `{}` already of in producer_id_to_tgtaddr".format(bb_instr.producer_id, bb_instr.get_str())
                    producer_id_to_tgtaddr[bb_instr.producer_id] = phys2virt(addr, bb_instr.priv_level_after_op, bb_instr.va_layout_after_op, fuzzerstate)
                    consumer_inst_va_layout[bb_instr.producer_id] = (bb_instr.va_layout_after_op, bb_instr.priv_level_after_op)

            ###
            # Else, check for "traditional" instructions, which have an instruction string.
            ###

            if isinstance(bb_instr,JALRInstruction):
                if bb_instr.producer_id > 0:
                    if index_in_bb_start_addr_seq == len(fuzzerstate.bb_start_addr_seq):
                        if DO_ASSERT:
                            assert fuzzerstate.final_bb_base_addr is not None and fuzzerstate.final_bb_base_addr >= 0
                        addr = fuzzerstate.final_bb_base_addr # Final basic block
                    else:
                        addr = fuzzerstate.bb_start_addr_seq[index_in_bb_start_addr_seq]
                        index_in_bb_start_addr_seq += 1
                    if DO_ASSERT:
                        assert bb_instr.producer_id > 0
                        assert bb_instr.producer_id == -1 or not bb_instr.producer_id in producer_id_to_tgtaddr, "producer_id `{}` of instruction `{}` already of in producer_id_to_tgtaddr".format(bb_instr.producer_id, bb_instr.get_str())
                    producer_id_to_tgtaddr[bb_instr.producer_id] = phys2virt(addr, bb_instr.priv_level, bb_instr.va_layout, fuzzerstate)
                    consumer_inst_va_layout[bb_instr.producer_id] = (bb_instr.va_layout, bb_instr.priv_level)

            elif isinstance(bb_instr, JALInstruction) or (isinstance(bb_instr,BranchInstruction) and bb_instr.plan_taken):
                # If this is the last before the final block, we need to steer toward the final block.
                if index_in_bb_start_addr_seq == len(fuzzerstate.bb_start_addr_seq):
                    if DO_ASSERT:
                        assert fuzzerstate.final_bb_base_addr is not None and fuzzerstate.final_bb_base_addr >= 0
                    # curr_addr = fuzzerstate.bb_start_addr_seq[bb_id] + bb_instr_id * 4 # NO_COMPRESSED
                    curr_addr =  fuzzerstate.bb_start_addr_seq[bb_id] + sum([int(not i.iscompressed)*2+2 for i in bb_instrlist[:bb_instr_id]])
                    # bb_instr.print()
                    # Offset calculation, no need for virtual address handling
                    bb_instr.imm = fuzzerstate.final_bb_base_addr - curr_addr

                index_in_bb_start_addr_seq += 1

            elif bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.SPECIAL]:
                pass


    assert len(consumer_inst_va_layout) == len(producer_id_to_tgtaddr), f"lenghts {len(consumer_inst_va_layout)}, {len(producer_id_to_tgtaddr)}"
    # assert index_in_bb_start_addr_seq == len(fuzzerstate.bb_start_addr_seq)+1, f"{index_in_bb_start_addr_seq} != {len(fuzzerstate.bb_start_addr_seq)+1}"
    return consumer_inst_va_layout, producer_id_to_tgtaddr, producer_id_to_noreloc_spike

        
# @brief Generates a series of basic blocks.
# Does not transmit the next bb address to the control flow instructions.
# @param fuzzerstate a freshly created fuzzerstate.
def gen_basicblocks(fuzzerstate):
    # Until the generation succeeds
    while True:
        # Reserve space for initial block.
        alloc_initial_basic_block(fuzzerstate)
        # Reserve space for the final basic block.
        alloc_final_basic_block(fuzzerstate)
        # Reserve space for the context setter basic block, but do not instantiate it because we do not know yet what it will look like until we have a concrete context to restore. Until then, we just know arbitrary bounds.
        alloc_context_saver_bb(fuzzerstate)

        # We need at least one random data block with taint and one without s.t. all privileges can read and write memory
        gen_random_data_block(fuzzerstate, False)
        gen_random_data_block(fuzzerstate, True)
        # Generate the random data blocks
        for _ in range(2, random.randint(MIN_N_RANDOM_DATA_BLOCKS, MAX_N_RANDOM_DATA_BLOCKS)):
            gen_random_data_block(fuzzerstate, random.random() < P_PAGE_HAS_TAINT)

        # Set up the page tables and map the initial, final and context block. All other pages are distributed randomly among the privileges.
        if USE_MMU and not fuzzerstate.design_has_no_mmu:
            if not fuzzerstate.pagetablestate.gen_mmu_dependencies(fuzzerstate): continue #if there is not enough contiguous space for the last page table level skip to the next block
            fuzzerstate.pagetablestate.gen_pt_in_mem(fuzzerstate)

        # Now we have setup the page tables and can generate the program.
        if not gen_initial_basic_block(fuzzerstate, SPIKE_STARTADDR): continue

        # Reserve space for the second basic block (whose address is already fixed).
        # fuzzerstate.memview.alloc_mem_range(fuzzerstate.next_bb_addr, fuzzerstate.next_bb_addr+BASIC_BLOCK_MIN_SPACE)
        fuzzerstate.save_states()

        while True:
            # print('len(fuzzerstate.instr_objs_seq)', len(fuzzerstate.instr_objs_seq))
            gen_basicblock(fuzzerstate)
            if fuzzerstate.next_bb_addr is None:
                # This corresponds to failing to find space for a new basic block. In this case, this block may also not have completed, and we drop it.
                break
            # Save the states
            fuzzerstate.save_states()
            if fuzzerstate.nmax_bbs is not None and len(fuzzerstate.instr_objs_seq) >= fuzzerstate.nmax_bbs or fuzzerstate.memview.get_allocated_ratio() >= LIMIT_MEM_SATURATION_RATIO or NUM_MAX_N_INSTRS and sum([len(i) for i in fuzzerstate.instr_objs_seq]) > NUM_MAX_N_INSTRS:
                break
            # fuzzerstate.memview.alloc_mem_range(fuzzerstate.next_bb_addr, fuzzerstate.next_bb_addr+BASIC_BLOCK_MIN_SPACE)

            # print('Mem occupation:', fuzzerstate.memview.get_allocated_ratio(), end='\r')
        # print()

        pop_success = pop_last_bbs_to_connect_with_final_block(fuzzerstate)
        if pop_success:
            break
        # Staying in the external loop is typically extremely rare. Staying corresponds to not being able to jump to the final bb despite popping any number of bbs. This may happen mostly with large memories and with a very high prevalence of direct control flow instructions (JAL or branches)
    # Generate the content of the final basic block, now that we know the final privilege level.
    fuzzerstate.final_bb = finalblock(fuzzerstate, fuzzerstate.design_name)
    if DO_ASSERT:
        assert not NUM_MAX_N_INSTRS or sum(len(i) for i in fuzzerstate.instr_objs_seq) < NUM_MAX_N_INSTRS+BASIC_BLOCK_MIN_SPACE//4, f"Program has {sum(len(i) for i in fuzzerstate.instr_objs_seq)} > {NUM_MAX_N_INSTRS+BASIC_BLOCK_MIN_SPACE//4} instructions."
    # # Forbid loads from addresses where instructions change between spike resolution and RTL sim.
    # blacklist_changing_instructions(fuzzerstate)
    # blacklist_final_block(fuzzerstate) # Must be done once the bb is created, else we could also blacklist upper bounds over the basic block size.
    # blacklist_context_setter(fuzzerstate)
    if FILL_MEM_WITH_DEAD_CODE:
        fuzzerstate.fill_mem_with_dead_code()
    fuzzerstate.consumer_inst_va_layout, fuzzerstate.producer_id_to_tgtaddr, fuzzerstate.producer_id_to_noreloc_spike = gen_producer_id_to_tgtaddr(fuzzerstate)

    return fuzzerstate





