# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script defines the memory allocation.

# For the moment, MemoryView is not designed to be thread-safe.
# MemoryView is a data structure that represents allocated and free memory.
# MemoryView is not yet designed to free any memory. Only more memory can be further allocated.

# A design assumption is that we will use the available memory very sparsely.

# Internally, MemoryView is implemented as a sorted iterable of pairs (free_start_addr, free_end_addr_plus_one)
# Internally, it offers the guarantee that if (a, b) and (c, d) are in the iterable in this order, then b < c (i.e., no superposition and no juxtaposition)

import random
from copy import deepcopy
import numpy as np
# from params.runparams import DO_ASSERT
from params.fuzzparams import P_TAINT_REG, TAINT_EN, MAX_NUM_INIT_TAINTED_REGS, P_UNTAINT_BIT, USE_MMU
from params.runparams import CHECK_MEM_T0_PRECISE, PRINT_MEM_STORES, PRINT_MEM_STORES_T0, PRINT_MEM_LOADS, PRINT_MEM_LOADS_T0, INSERT_REGDUMPS
from milesan.mmu_utils import PAGE_ALIGNMENT_MASK, PAGE_ALIGNMENT_BITS, PHYSICAL_PAGE_SIZE
from milesan.spikeresolution import SPIKE_STARTADDR
from milesan.registers import MAX_32b, MAX_64b
from milesan.privilegestate import PrivilegeStateEnum
from milesan.mmu_utils import virt2phys
from common.designcfgs import get_design_reg_dump_addr, get_design_fpreg_dump_addr, get_design_reg_stream_addr, get_design_cl_size
from common.exceptions import MemReadException, MemWriteException

DO_ASSERT = True

MEMVIEW_ALLOC_MAX_ATTEMPTS = 100

class MemoryView:
    # @param memsize should be at least 4, typically much higher. It is also typically a power of 2.
    def __init__(self, fuzzerstate):
        self.memsize = fuzzerstate.memsize
        self.freepairs = [(0, self.memsize)]
        self.occupied_addrs = 0 # Follow the number of occupied addresses.
        self.data = {} # Keep track of load/store operations. Holds the addr-byte pairs in little endian format.
        self.data_t0 = {} # Keep track of load/store operations' taints. Holds the addr-byte_t0 pairs in little endian format.
        self.states = []
        self.fuzzerstate = fuzzerstate
        self.cl_size = get_design_cl_size(self.fuzzerstate.design_name)
    # In particular, returns False if it goes beyond the memory boundaries.
    def is_mem_free(self, addr: int):
        for curr_pair in self.freepairs:
            if addr < curr_pair[1]:
                return curr_pair[0] <= addr
        return False

    # @param start: first address of the range
    # @param end:   last address of the range, excluded
    # In particular, returns False if it goes beyond the memory boundaries.
    def is_mem_range_free(self, start: int, end: int):
        # Find the pair to which `start` belongs, and then check that `end` is still in the same pair.
        for curr_pair in self.freepairs:
            if start < curr_pair[1]:
                return start >= curr_pair[0] and end <= curr_pair[1]
        return False

    def is_mem_range_in_priv(self, priv:PrivilegeStateEnum, start: int, end:int): 
        assert (start&PAGE_ALIGNMENT_MASK)+SPIKE_STARTADDR in self.fuzzerstate.pagetablestate.ppn_leaf_to_priv_dict, f"Start page {hex((start&PAGE_ALIGNMENT_MASK)+SPIKE_STARTADDR)} not in in ppn_leaf_to_priv_dict!"
        assert (end&PAGE_ALIGNMENT_MASK)+SPIKE_STARTADDR in self.fuzzerstate.pagetablestate.ppn_leaf_to_priv_dict, f"End page {hex((end&PAGE_ALIGNMENT_MASK)+SPIKE_STARTADDR)} not in in ppn_leaf_to_priv_dict!"
        start_in_priv = priv in self.fuzzerstate.pagetablestate.ppn_leaf_to_priv_dict[(start&PAGE_ALIGNMENT_MASK)+SPIKE_STARTADDR]
        end_in_priv = priv in self.fuzzerstate.pagetablestate.ppn_leaf_to_priv_dict[(end&PAGE_ALIGNMENT_MASK)+SPIKE_STARTADDR]

        return start_in_priv & end_in_priv

    def is_cl_free(self, addr: int):
        cl_addr = addr - addr%self.cl_size
        return self.is_mem_range_free(cl_addr,cl_addr+self.cl_size)

    # @param addr: the current address
    # @return: the number of addresses, including addr, that are free until the next allocated address (or until the end of the memory).
    def get_available_contig_space(self, addr: int = None):
        # Find the pair to which `start` belongs, and then check that `end` is still in the same pair.
        if addr is None:
            addr = self.fuzzerstate.get_curr_paddr(add_spike_offset=False)
        for curr_pair in self.freepairs:
            if addr < curr_pair[1]:
                if (addr >= curr_pair[0]):
                    # print(f"Free from {hex(addr)} until {hex(curr_pair[1])} ({curr_pair[1] - addr} bytes)")
                    return curr_pair[1] - addr
                else:
                    return 0
        return 0
        

    # @param start:    first address of the range.
    # @param end:      last address of the range, excluded.
    def alloc_mem_range(self, start: int, end: int):
        # print(f"Allocating {hex(start)} - {hex(end)}")
        # if 0xd8080 >= start and 0xd8080 < end:
        #     print(f"HERE Allocating {hex(start)} - {hex(end)}")
            # exit(0)
        if DO_ASSERT:
            assert end > start, f"Expected start ({start}) > end ({end}) in alloc_mem_range."
        self.occupied_addrs += end-start
        for curr_pair_id, curr_pair in enumerate(self.freepairs):
            if start < curr_pair[1]:
                # Check that the range is initially free.
                if DO_ASSERT:
                    assert start >= curr_pair[0] and end <= curr_pair[1], f"The memory range {hex(start)} - {hex(end)} is not free."
                # Remove the tuple and replace it with at most two smaller tuples. This will automatically coalesce.
                if start == curr_pair[0] and end == curr_pair[1]:
                    self.freepairs = self.freepairs[:curr_pair_id] + self.freepairs[curr_pair_id+1:]
                    break
                elif start == curr_pair[0]:
                    self.freepairs = self.freepairs[:curr_pair_id] + [(end, curr_pair[1])] + self.freepairs[curr_pair_id+1:]
                    break
                elif end == curr_pair[1]:
                    self.freepairs = self.freepairs[:curr_pair_id] + [(curr_pair[0], start)] + self.freepairs[curr_pair_id+1:]
                    break
                else:
                    self.freepairs = self.freepairs[:curr_pair_id] + [(curr_pair[0], start)] + [(end, curr_pair[1])] + self.freepairs[curr_pair_id+1:]
                    break
        else:
            raise ValueError("Trying to allocate a memory range that was already not free.")
        # print(self.to_string())

    # @param store_instr_str: for example `sw`.
    # @param addr may be outside of memview
    def alloc_from_store_instruction(self, store_instr_str: str, addr: int):
        # Get the width from the opcode
        if store_instr_str == "sb":
            opwidth = 1
        elif store_instr_str == "sh":
            opwidth = 2
        elif store_instr_str in ("sw", "fsw"):
            opwidth = 4
        elif store_instr_str in ("sd", "fsd"):
            opwidth = 8
        else:
            raise ValueError(f"Unexpected store instruction string: `{store_instr_str}`")

        # Cap to the memory bounds
        left_bound = max(addr, 0) # Included
        right_bound = min(addr+opwidth, self.memsize) # Excluded

        if DO_ASSERT:
            assert left_bound <= right_bound

        if right_bound == left_bound:
            return
        self.alloc_mem_range(left_bound, right_bound)

    # @param alignment_bits: bits of alignment. For example, 0 for no specific alignment, 1 for 2-byte alignment, 2 for 4-byte, etc. 
    # @param min_space:      the minimal number of memory addresses that are free, starting from the returned address 
    # @param left_bound:     byte address. Included. May exceed memory bounds, in which case will be brought back to memory boundaries.
    # @param right_bound:    byte address. Excluded. May exceed memory bounds, in which case will be brought back to memory boundaries.
    # @param max_attempts:   max random attempts. After this number of unsuccessful attempts, the function will return None. Must be strictly positive.
    # @return None if no corresponding address was found in max_attempts. Else, return the address
    def gen_random_free_addr(self, alignment_bits: int, min_space: int, left_bound: int, right_bound: int, max_attempts: int = MEMVIEW_ALLOC_MAX_ATTEMPTS, priv: int = PrivilegeStateEnum.MACHINE):
        left_bound  = max(left_bound, 0)
        right_bound = min(right_bound, self.memsize)
        if DO_ASSERT:
            assert max_attempts > 0
            assert min_space >= 0
            assert left_bound >= 0
            assert right_bound <= self.memsize
            assert left_bound < right_bound, f"{hex(left_bound)} >= {hex(right_bound)}"
            # The bounds must be sufficiently spaced. In our use case, this is not at all a problem.
            assert ((left_bound+(1 << alignment_bits)-1) >> alignment_bits) < ((right_bound-min_space) >> alignment_bits), f"Alignment bits: {alignment_bits}"

        for _ in range(max_attempts):
            picked_addr = random.randrange((left_bound+(1 << alignment_bits)-1) >> alignment_bits, ((right_bound-min_space) >> alignment_bits)) << alignment_bits
            if min_space == 0 or self.is_mem_range_free(picked_addr, picked_addr+min_space) and \
                 (not USE_MMU or len(self.fuzzerstate.pagetablestate.ppn_leaf_to_priv_dict) == 0 or self.is_mem_range_in_priv(priv, picked_addr, picked_addr+min_space)):
                if DO_ASSERT:
                    assert picked_addr >= 0
                    assert picked_addr + min_space <= self.memsize
                    assert picked_addr % (1 << alignment_bits) == 0
                # print(f"BB at addr {hex(picked_addr+SPIKE_STARTADDR)} at page at addr {hex((picked_addr&PAGE_ALIGNMENT_MASK)+SPIKE_STARTADDR)} in priv {priv.name}")
                return picked_addr
        return None

    def gen_random_addr_from_randomblock(self, alignment_bits: int = 2, min_space: int = 4, max_attempts: int = MEMVIEW_ALLOC_MAX_ATTEMPTS, tainted: bool = False):
        for _ in range(max_attempts):
            allowed_pages = [addr for addr in self.fuzzerstate.random_data_block_ranges] # All pages
            if USE_MMU:
                if tainted: # Remove untainted pages
                    allowed_pages = [page_start_end_addr for page_start_end_addr in allowed_pages if self.fuzzerstate.random_data_block_has_taint[page_start_end_addr[0]]]
                else:
                    allowed_pages = [page_start_end_addr for page_start_end_addr in allowed_pages if not self.fuzzerstate.random_data_block_has_taint[page_start_end_addr[0]]]
                assert len(allowed_pages), f"No pages matched required criteria: tainted: {tainted}"
            page_start_end_addr = random.choice(allowed_pages)
            picked_addr = random.choice([addr for addr in range(page_start_end_addr[0], page_start_end_addr[1]) if addr % (1 << alignment_bits) == 0 and addr+min_space<page_start_end_addr[1]])

            if min_space == 0 or picked_addr+min_space<page_start_end_addr[1]:
                if DO_ASSERT:
                    assert picked_addr >= 0
                    assert picked_addr + min_space <= self.memsize, f"{hex(picked_addr+min_space)} exceeds memsize {hex(self.memsize)}"
                    assert picked_addr % (1 << alignment_bits) == 0
                    if USE_MMU:
                        if tainted:
                            assert self.fuzzerstate.random_data_block_has_taint[picked_addr&PAGE_ALIGNMENT_MASK]
                        else:
                            assert not self.fuzzerstate.random_data_block_has_taint[picked_addr&PAGE_ALIGNMENT_MASK]
                return picked_addr
        return None

    def gen_random_page_addr_from_randomblocks(self, max_attempts: int = MEMVIEW_ALLOC_MAX_ATTEMPTS, tainted: bool = False):
        for _ in range(max_attempts):
            allowed_pages = [addr for addr in self.fuzzerstate.random_data_block_ranges] # All pages
            if tainted: # Remove untainted pages
                allowed_pages = [page_start_end_addr[0] for page_start_end_addr in allowed_pages if self.fuzzerstate.random_data_block_has_taint[page_start_end_addr[0]]]
            else:
                allowed_pages = [page_start_end_addr[0] for page_start_end_addr in allowed_pages if not self.fuzzerstate.random_data_block_has_taint[page_start_end_addr[0]]]
            assert len(allowed_pages), f"No pages matched required criteria: tainted: {tainted}"
            picked_addr = random.choice(allowed_pages)
            # print(f"Picked addr {hex(picked_addr)} in page {hex(page_start_end_addr[0])}")
            if DO_ASSERT:
                assert picked_addr >= 0
                assert picked_addr + PHYSICAL_PAGE_SIZE <= self.memsize, f"{hex(picked_addr+PHYSICAL_PAGE_SIZE)} exceeds memsize {hex(self.memsize)}"
                assert picked_addr & PAGE_ALIGNMENT_BITS == 0, f"Picked addr not aligned: {hex(picked_addr)}"
                if USE_MMU:
                    if tainted:
                        assert self.fuzzerstate.random_data_block_has_taint[picked_addr]
                    else:
                        assert not self.fuzzerstate.random_data_block_has_taint[picked_addr]
            return picked_addr + PHYSICAL_PAGE_SIZE//2
        return None

    def gen_random_addr_from_randomblock_from_rng(self,rng: np.random.RandomState, alignment_bits: int = 2, min_space: int = 4, max_attempts: int = MEMVIEW_ALLOC_MAX_ATTEMPTS, tainted_ok: bool = True, not_tainted_ok: bool = True):
        for _ in range(max_attempts):
            allowed_pages = [addr for addr in self.fuzzerstate.random_data_block_ranges] # All pages
            if USE_MMU:
                assert tainted_ok or not_tainted_ok, f"At least one must be true."
                if not tainted_ok: # Remove tainted pages
                    allowed_pages = [page_start_end_addr for page_start_end_addr in allowed_pages if not self.fuzzerstate.random_data_block_has_taint[page_start_end_addr[0]]]
                if not not_tainted_ok: # Remove untainted pages
                    allowed_pages = [page_start_end_addr for page_start_end_addr in allowed_pages if self.fuzzerstate.random_data_block_has_taint[page_start_end_addr[0]]]
            page_start_end_addr = rng.choice(allowed_pages)
            picked_addr = int(rng.choice([addr for addr in range(page_start_end_addr[0], page_start_end_addr[1]) if addr % (1 << alignment_bits) == 0]))
            # print(f"Picked addr {hex(picked_addr)} in page {hex(page_start_end_addr[0])}")
            if min_space == 0 or picked_addr+min_space<page_start_end_addr[1]:
                if DO_ASSERT:
                    assert picked_addr >= 0
                    assert picked_addr + min_space <= self.memsize, f"{hex(picked_addr+min_space)} exceeds memsize {hex(self.memsize)}"
                    assert picked_addr % (1 << alignment_bits) == 0
                    if USE_MMU:
                        if not tainted_ok:
                            assert not self.fuzzerstate.random_data_block_has_taint[picked_addr&PAGE_ALIGNMENT_MASK]
                        if not not_tainted_ok:
                            assert self.fuzzerstate.random_data_block_has_taint[picked_addr&PAGE_ALIGNMENT_MASK]
                return picked_addr
        return None

    def is_addr_tainted(self,addr,n_bytes):
        is_tainted = False
        for i in range(n_bytes):
            is_tainted |= addr+i in self.data_t0 and self.data_t0[addr+i]
        return is_tainted

    def is_cl_tainted(self, addr):
        cl_addr = addr - addr%self.cl_size
        return self.is_addr_tainted(cl_addr,self.cl_size)

    # @brief Computes the percentage of the memory that is allocated
    def get_allocated_ratio(self):
        free_sum = sum(map(lambda p: p[1] - p[0], self.freepairs))
        return (self.memsize - free_sum)/self.memsize

    def to_string(self):
        return str(self.freepairs)

    def read(self, addr, n_bytes: int = 4, priv_level: PrivilegeStateEnum = PrivilegeStateEnum.MACHINE, va_layout: int = -1):
        if USE_MMU:
            addr = virt2phys(addr, priv_level, va_layout, self.fuzzerstate,absolute_addr=False)
        if DO_ASSERT:
            try:
                assert addr >= SPIKE_STARTADDR or INSERT_REGDUMPS
                assert addr < SPIKE_STARTADDR + self.fuzzerstate.memsize or INSERT_REGDUMPS, f"{hex(addr)} exceeds memory range."
                assert addr&PAGE_ALIGNMENT_MASK in self.fuzzerstate.pagetablestate.ppn_leaf_to_priv_dict or va_layout == -1, f"Memory at {hex(addr)} not mapped with layout {va_layout}"
                assert not USE_MMU or  priv_level == PrivilegeStateEnum.MACHINE or priv_level in self.fuzzerstate.pagetablestate.ppn_leaf_to_priv_dict[addr&PAGE_ALIGNMENT_MASK], f"{priv_level.name} does not have read permissions for page at {hex(addr&PAGE_ALIGNMENT_MASK)} in layout {va_layout}. Allowed ar {self.fuzzerstate.pagetablestate.ppn_leaf_to_priv_dict[addr&PAGE_ALIGNMENT_MASK]}"
            except AssertionError as e:
                raise MemReadException(self.fuzzerstate, addr, n_bytes,e)
        val = 0
        for i in range(n_bytes):
            assert addr+i in self.data, f"Read request from invalid address {hex(addr+i)}."
            b = self.data[addr+i]
            assert b <= 0xFF
            val |= (b << (i*8))
        if PRINT_MEM_LOADS:
            print(f"VAL: Reading {n_bytes} bytes {hex(val)} from {hex(addr)}")
        return val

    def read_t0(self, addr, n_bytes: int = 4, priv_level: PrivilegeStateEnum = PrivilegeStateEnum.MACHINE, va_layout: int = -1):
        if USE_MMU:
            addr = virt2phys(addr, priv_level, va_layout, self.fuzzerstate,absolute_addr=False)
        if DO_ASSERT:
            try:
                assert addr >= SPIKE_STARTADDR or INSERT_REGDUMPS
                assert addr < SPIKE_STARTADDR + self.fuzzerstate.memsize or INSERT_REGDUMPS
                assert addr&PAGE_ALIGNMENT_MASK in self.fuzzerstate.pagetablestate.ppn_leaf_to_priv_dict or va_layout == -1, f"Memory at {hex(addr)} not mapped with layout {va_layout}"
                assert not USE_MMU or priv_level == PrivilegeStateEnum.MACHINE or priv_level in self.fuzzerstate.pagetablestate.ppn_leaf_to_priv_dict[addr&PAGE_ALIGNMENT_MASK], f"{priv_level.name} does not have read permissions for page at {hex(addr&PAGE_ALIGNMENT_MASK)} in layout {va_layout}. Allowed ar {self.fuzzerstate.pagetablestate.ppn_leaf_to_priv_dict[addr&PAGE_ALIGNMENT_MASK]}"
            except AssertionError as e:
                raise MemReadException(self.fuzzerstate, addr, n_bytes,e)
        
        val_t0 = 0
        for i in range(n_bytes):
            assert addr+i in self.data_t0, f"Taint read request from invalid address {hex(addr+i)}."
            b = self.data_t0[addr+i]
            assert b <= 0xFF
            val_t0 |= (b << (i*8))
        if PRINT_MEM_LOADS_T0:
            print(f"TAINT: Reading {n_bytes} bytes {hex(val_t0)} from {hex(addr)}")
        if DO_ASSERT:
            assert not USE_MMU or va_layout == -1 or priv_level in self.fuzzerstate.taint_source_privs or val_t0 == 0, f"Write from unauthorized privilege: {priv_level.name}, allowed are {self.fuzzerstate.taint_source_privs}"
            assert not USE_MMU or va_layout == -1  or va_layout in self.fuzzerstate.taint_source_layouts or val_t0 == 0, f"Write from unmapped layout: {va_layout}, allowed are {self.fuzzerstate.taint_source_layouts}"
        return val_t0

    def write(self, addr, val, n_bytes, priv_level: PrivilegeStateEnum = PrivilegeStateEnum.MACHINE, va_layout: int = -1):
        if USE_MMU:
            addr = virt2phys(addr, priv_level, va_layout, self.fuzzerstate,absolute_addr=False)
        if DO_ASSERT:
            try:
                assert addr >= SPIKE_STARTADDR or INSERT_REGDUMPS
                assert addr < SPIKE_STARTADDR + self.fuzzerstate.memsize or INSERT_REGDUMPS
                assert addr&PAGE_ALIGNMENT_MASK in self.fuzzerstate.pagetablestate.ppn_leaf_to_priv_dict or va_layout == -1, f"Memory at {hex(addr)} not mapped with layout {va_layout}"
                assert not USE_MMU or priv_level == PrivilegeStateEnum.MACHINE or priv_level in self.fuzzerstate.pagetablestate.ppn_leaf_to_priv_dict[addr&PAGE_ALIGNMENT_MASK], f"{priv_level.name} does not have write permissions for page at {hex(addr&PAGE_ALIGNMENT_MASK)} in layout {va_layout}. Allowed ar {self.fuzzerstate.pagetablestate.ppn_leaf_to_priv_dict[addr&PAGE_ALIGNMENT_MASK]}"
            except AssertionError as e:
                raise MemWriteException(self.fuzzerstate, addr, n_bytes,e)


        if PRINT_MEM_STORES: 
            print(f"VAL: Writing {n_bytes} bytes {hex(val)} to {hex(addr)}")
        for i in range(n_bytes):
            b = (val&(0xFF<<(i*8)))>>(i*8)
            # print(f"Writing to {hex(addr+i)}: {hex(b)}")
            self.data[addr+i] = b # little endian
            if addr+i not in self.data_t0:
                self.data_t0[addr+i] = 0

    def write_t0(self, addr, val_t0, n_bytes, priv_level: PrivilegeStateEnum = PrivilegeStateEnum.MACHINE, va_layout: int = -1):
        if USE_MMU:
            addr = virt2phys(addr, priv_level, va_layout, self.fuzzerstate,absolute_addr=False)
        if DO_ASSERT:
            try:
                assert addr >= SPIKE_STARTADDR or INSERT_REGDUMPS
                assert addr < SPIKE_STARTADDR + self.fuzzerstate.memsize or INSERT_REGDUMPS
                assert addr&PAGE_ALIGNMENT_MASK in self.fuzzerstate.pagetablestate.ppn_leaf_to_priv_dict or va_layout == -1, f"Memory at {hex(addr)} not mapped with layout {va_layout}"
                assert not USE_MMU or priv_level == PrivilegeStateEnum.MACHINE or priv_level in self.fuzzerstate.pagetablestate.ppn_leaf_to_priv_dict[addr&PAGE_ALIGNMENT_MASK], f"{priv_level.name} does not have write permissions for page at {hex(addr&PAGE_ALIGNMENT_MASK)} in layout {va_layout}. Allowed ar {self.fuzzerstate.pagetablestate.ppn_leaf_to_priv_dict[addr&PAGE_ALIGNMENT_MASK]}"
            except AssertionError as e:
                raise MemWriteException(self.fuzzerstate, addr, n_bytes,e)


        if PRINT_MEM_STORES_T0: 
            print(f"TAINT: Writing {n_bytes} bytes {hex(val_t0)} to {hex(addr)}")
        for i in range(n_bytes):
            b = (val_t0&(0xFF<<(i*8)))>>(i*8)
            # print(f"Writing to {hex(addr+i)}: {hex(b)}")
            self.data_t0[addr+i] = b # little endian



    def set_initial_register_values(self,fuzzerstate, start_addr):
        n_tainted_regs = 0
        for i,reg_data_content in enumerate(fuzzerstate.initial_reg_data_content):
            addr = start_addr + i*8 # Stride for double is used even if design is 32bit.
            n_bytes = 8 if self.fuzzerstate.is_design_64bit else 4
            self.write(addr, reg_data_content, n_bytes)
            if TAINT_EN and n_tainted_regs < MAX_NUM_INIT_TAINTED_REGS:
                if random.random() < P_TAINT_REG:
                    rand_val = random.randint(1,MAX_64b if fuzzerstate.is_design_64bit else MAX_32b)
                    n_tainted_regs += 1
                    self.write_t0(addr, rand_val, n_bytes)
            else:
                self.write_t0(addr, 0, n_bytes)

    def store_state(self): 
        self.states += [(deepcopy(self.data), deepcopy(self.data_t0))]  # deepcopy important so we can restore and execute multiple times

    def set_as_initial_state(self):
        self.states[0] = (deepcopy(self.data), deepcopy(self.data_t0))

    def restore_and_reduce_taint(self, mismatch):
        # print([hash(frozenset(state[1].items())) for state in self.states])
        if mismatch:
            h = hash(frozenset(self.states[-1][1].items()))
            h_ = hash(frozenset(self.data_t0.items()))
            print(f"Mismatch still there for {h_}, continue reducing from {h}.")
            self.restore()
        else:
            h = hash(frozenset(self.states[-2][1].items()))
            h_ = hash(frozenset(self.data_t0.items()))
            print(f"No mismatch detected for {h_}, restoring to {h}.")
            del self.states[-1]
            self.restore()

        for addr, val_t0 in self.data.items():
            if val_t0:
                for i in range(8): # access at byte-granularity
                    if (self.data_t0[addr]>>i)&1 and np.random.choice([1,0],p=[P_UNTAINT_BIT, 1-P_UNTAINT_BIT]):
                        self.data_t0[addr] &= ~(1<<i) # untained single bits
                # break
        n_total_tainted_bits = 0
        for addr, val_t0 in self.data.items():
            n_total_tainted_bits += val_t0.bit_count()
        
        self.states.append((deepcopy(self.data), deepcopy(self.data_t0)))
        return n_total_tainted_bits

    def restore(self, bb_id: int = -1):# TODO: the index wont correspond to bb_id as we store before that already?
        self.data = deepcopy(self.states[bb_id][0]) # deepcopy important so we can restore and execute multiple times
        self.data_t0 = deepcopy(self.states[bb_id][1])

    def reset(self):
        self.data.clear()
        self.data_t0.clear()

    def dump_taint(self, path):
        dumped_waddrs = []
        wlen = 8 if self.fuzzerstate.is_design_64bit else 4
        with open(path, "w") as f:
            for addr in self.data_t0.keys():
                if DO_ASSERT:
                    assert addr >= SPIKE_STARTADDR
                    assert addr < SPIKE_STARTADDR + self.fuzzerstate.memsize
                if self.data_t0[addr]:
                    waddr = addr - addr % wlen
                    if waddr not in dumped_waddrs:
                        dumped_waddrs += [waddr]
                        wordstring = "".join(["{:02x}".format(self.data_t0[waddr+i]) if waddr+i in self.data_t0 else "00" for i in range(wlen)]) 
                        f.write("0 {:x} {:x} ".format(waddr, wlen) + wordstring + "\n")

    def print(self):
        row = ["ADDRESS","VALUE","VALUE_T0"]
        print("{: >30} {: >30} {: >30}".format(*row))
        row = ["*"*30,"*"*30,"*"*30]
        print("{: >30} {: >30} {: >30}".format(*row))
        addresses = self.data_t0.keys()
        printed_addresses = []
        for addr in addresses:
            if addr in printed_addresses: continue
            val = 0
            val_t0 = 0
            for i in range(8 if self.fuzzerstate.is_design_64bit else 4):
                if addr+i in self.data:
                    assert addr+i in self.data_t0
                    val |= self.data[addr+i]<<(i*8)
                    val_t0 |= self.data_t0[addr+i]<<(i*8)
                    printed_addresses += [addr+i]
            row = ["0x{:08x}".format(addr), "0x{:08x}".format(val), "0x{:08x}".format(val_t0)]
            print("{: >30} {: >30} {: >30}".format(*row))
    

    def print_and_compare(self,rtl_values):
        row = ["ADDRESS","VALUE (sim/rtl)","VALUE_T0 (sim/rtl)"]
        print("{: >30} {: >30} {: >30}".format(*row))
        row = ["*"*30,"*"*30,"*"*30]
        print("{: >30} {: >30} {: >30}".format(*row))
        addresses = self.data_t0.keys()
        printed_addresses = []
        for addr in addresses:
            if addr in printed_addresses: continue
            val = 0
            val_t0 = 0
            for i in range(8 if self.fuzzerstate.is_design_64bit else 4):
                if addr+i in self.data:
                    assert addr+i in self.data_t0
                    val |= self.data[addr+i]<<(i*8)
                    val_t0 |= self.data_t0[addr+i]<<(i*8)
                    printed_addresses += [addr+i]
            if addr in rtl_values:
                rtl_val = rtl_values[addr]["val"]
                rtl_val_t0 = rtl_values[addr]["val_t0"]
            else:
                rtl_val = None
                rtl_val_t0 = None
            if rtl_val == val:
                val_str =  "0x{:08x}".format(val)
            else:
                val_str = "0x{:08x} != 0x{:08x}".format(val,rtl_val) if rtl_val is not None else "0x{:08x} (NONE)".format(val)

            if rtl_val_t0 == val_t0:
                val_t0_str =  "0x{:08x}".format(val_t0)
            else:
                val_t0_str = "0x{:08x} != 0x{:08x}".format(val_t0,rtl_val_t0) if rtl_val_t0 is not None else "0x{:08x} (NONE)".format(val_t0)

            row = ["0x{:08x}".format(addr), val_str,val_t0_str]
            print("{: >30} {: >30} {: >30}".format(*row))


    def check(self, rtl_values, precise = CHECK_MEM_T0_PRECISE):
        addresses = self.data_t0.keys()
        checked_addresses = []
        # Skip the checks of the addresses we dump the register values to as we dont simluate the final block as of now.
        regdump_addr = get_design_reg_dump_addr(self.fuzzerstate.design_name) + SPIKE_STARTADDR
        fpregdump_addr = get_design_fpreg_dump_addr(self.fuzzerstate.design_name) + SPIKE_STARTADDR

        for addr in addresses:
            assert addr in self.data
            if addr in checked_addresses: continue
            val = 0
            val_t0 = 0
            for i in range(8 if self.fuzzerstate.is_design_64bit else 4):
                if addr+i in self.data:
                    assert addr+i in self.data_t0
                    val |= self.data[addr+i]<<(i*8)
                    val_t0 |= self.data_t0[addr+i]<<(i*8)
                    checked_addresses += [addr+i]

            assert addr in rtl_values or val_t0 == 0, f"Address {hex(addr)} not found."
            if addr in rtl_values:
                rtl_val = rtl_values[addr]["val"]
                rtl_val_t0 = rtl_values[addr]["val_t0"]

                mismatch_val = rtl_val != val
                mismatch_val_t0 = rtl_val_t0 != val_t0 if precise else ~val_t0&rtl_val_t0 != 0
            
                assert not mismatch_val, f"Value mismatch at address {hex(addr)}: {hex(val)} != {hex(rtl_val)}"
                if TAINT_EN:
                    assert not mismatch_val_t0, f"Taint mismatch at address {hex(addr)}: {hex(val_t0)} != {hex(rtl_val_t0)}"
        if TAINT_EN:
            for addr in rtl_values.keys():
                assert addr in addresses or rtl_values[addr]["val_t0"] == 0 or addr in [regdump_addr,fpregdump_addr] , f"Memory at untracked address {hex(addr)} tainted in RTL simulation: {hex(rtl_values[addr]['val_t0'])}/{hex(rtl_values[addr]['val'])} (val_t0/val)."

    def flip_tainted_bits(self):
        assert TAINT_EN
        for addr,val_t0 in self.data_t0.items():
            if val_t0:
                self.data[addr] ^= val_t0

