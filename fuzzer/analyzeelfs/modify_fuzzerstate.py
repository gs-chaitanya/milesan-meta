#%%
import sys
sys.path.append("../")
%env  ASSERT_WRITEBACK_TRACE=0
# %env NO_REMOVE_TMPFILES=1
# %env PRINT_ENVIRONMENT=1
%env MILESAN_DATADIR=pickletest-mod
from milesan.fuzzerstate import FuzzerState
from milesan.cfinstructionclasses_t0 import *
from milesan.genelf import gen_elf_from_bbs
import pickle
from milesan.fuzzsim import runtest_simulator
from milesan.spikeresolution import SPIKE_STARTADDR
from milesan.registers import ABI_INAMES
#%% BOOM 275: transient page fault
FUZZERSTATE_PATH = "/mnt/milesan-data/boom/729549_boom_275_73/rtlreduce_reducestart729549_boom_275_73_7_28_7_0.fuzzerstate.pickle"
# %%
with open(FUZZERSTATE_PATH, "rb") as f:
    fuzzerstate = pickle.load(f)
# %%
# Also change page addr?
OFFSETS = range(-(2**11),2**11-1,1)
# OFFSETS = [-1587]
# OFFSETS = [-1588,-1589]
N_BYTES = 1
n_bytes_to_instr = {
    # 1: "lb",
    # 2: "lh",
    # 4: "lw",
    8: "ld"
}
PAGE_ADDR = SPIKE_STARTADDR + 0x98800
leak_success = {offset:{n_bytes:False for n_bytes in n_bytes_to_instr.keys() } for offset in OFFSETS}
for offset in OFFSETS:
    for n_bytes, instr_str in n_bytes_to_instr.items():
    # find speculative instr and change offset
        for i,spec_instr in enumerate(fuzzerstate.spec_instr_objs_seq):
            if spec_instr.paddr == 0x28e00:
                spec_instr.instr.imm = offset
                spec_instr.instr.instr_str = instr
                spec_instr.print()
            # elif spec_instr.paddr == 0x28e04:
            #     instr = R12DInstruction_t0(fuzzerstate, "and",ABI_INAMES.index("sp"),ABI_INAMES.index("sp"), ABI_INAMES.index("t4"))
            #     instr.paddr = spec_instr.paddr
            #     fuzzerstate.spec_instr_objs_seq[i] = SpeculativeInstructionEncapsulator(fuzzerstate,instr)
            #     fuzzerstate.spec_instr_objs_seq[i].print()
            elif spec_instr.paddr == 0x28e04:
                instr = IntLoadInstruction_t0(fuzzerstate, instr_str,ABI_INAMES.index("s1"),ABI_INAMES.index("sp"),0,-1)
                instr.paddr = spec_instr.paddr
                fuzzerstate.spec_instr_objs_seq[i] = SpeculativeInstructionEncapsulator(fuzzerstate,instr)
                fuzzerstate.spec_instr_objs_seq[i].print()

        # zero out all other addresses
        fuzzerstate.memview.data_t0 = {key:0 for key in fuzzerstate.memview.data_t0.keys()}
        for i in range(n_bytes):
            fuzzerstate.memview.data_t0[PAGE_ADDR+offset+i] = 0xff
        for i in range(n_bytes):
            fuzzerstate.memview.data[PAGE_ADDR+offset+i] = (0xdeadbeef&(0xff<<i*8))>>i*8

        # remove all non-explicit taints
        for bb_instrs in fuzzerstate.instr_objs_seq:
            for next_instr in bb_instrs:
                if isinstance(next_instr, (ImmRdInstruction_t0, RegImmInstruction_t0, BranchInstruction_t0)):
                    if next_instr.imm_t0:
                        next_instr.imm = 0
                        next_instr.imm_t0 = 0

        for next_instr in fuzzerstate.ctxsv_bb:
            if isinstance(next_instr, (ImmRdInstruction_t0, RegImmInstruction_t0, BranchInstruction_t0)):
                if next_instr.imm_t0:
                    next_instr.imm = 0
                    next_instr.imm_t0 = 0

        # Write 0xdeadbeef to the leaking memory address
        for random_block_id, random_block_content4by4bytes in enumerate(fuzzerstate.random_block_contents4by4bytes):
            for word_id, word_content in enumerate(random_block_content4by4bytes):
                curr_bytecode = word_content.to_bytes(4, 'little')
                for curr_byte_id, curr_byte in enumerate(curr_bytecode):
                    curr_addr = fuzzerstate.random_data_block_ranges[random_block_id][0] + 4*word_id + curr_byte_id # NO_COMPRESSED
                    if SPIKE_STARTADDR + curr_addr == PAGE_ADDR+offset:
                        print(f"Overwriting {hex(fuzzerstate.random_block_contents4by4bytes[random_block_id][word_id])}")
                        fuzzerstate.random_block_contents4by4bytes[random_block_id][word_id] = 0xdeadbeef

        # gen new elf with modified speculative instructions
        fuzzerstate.rtl_elfpath = gen_elf_from_bbs(fuzzerstate, False, f'{n_bytes}bytes-from-{hex(PAGE_ADDR+offset)}-', fuzzerstate.instance_to_str(), fuzzerstate.design_base_addr)

        # check if it leaks
        is_success, exception = runtest_simulator(fuzzerstate, fuzzerstate.rtl_elfpath, fuzzerstate.expected_regvals, sum([len(i) for i in fuzzerstate.instr_objs_seq]))
        # print(f"Leaking from addr {hex(PAGE_ADDR+offset)}. Success: {not is_success}")
        if not is_success:
            print(f"Leaked {n_bytes} bytes from addr {hex(PAGE_ADDR+offset)} at offset {hex(offset)}!")
        else:
            print(f"Failed leaking {n_bytes} bytes from addr {hex(PAGE_ADDR+offset)} at offset {hex(offset)}!")

        leak_success[offset][n_bytes] = not is_success
    break


# %%
#%% BOOM 275: transient page fault
FUZZERSTATE_PATH = "/mnt/milesan-data/boom/729549_boom_275_73/rtlreduce_reducestart729549_boom_275_73_7_28_7_0.fuzzerstate.pickle"
# %%
with open(FUZZERSTATE_PATH, "rb") as f:
    fuzzerstate = pickle.load(f)
# %%
# Also change page addr?
OFFSETS = range(-(2**11),2**11-1,1)
# OFFSETS = [-1587]
# OFFSETS = [-1588,-1589]
N_BYTES = 1
n_bytes_to_instr = {
    # 1: "lb",
    # 2: "lh",
    # 4: "lw",
    8: "ld"
}
PAGE_ADDR = SPIKE_STARTADDR + 0x98800
leak_success = {offset:{n_bytes:False for n_bytes in n_bytes_to_instr.keys() } for offset in OFFSETS}
for offset in OFFSETS:
    for n_bytes, instr_str in n_bytes_to_instr.items():
    # find speculative instr and change offset
        for i,spec_instr in enumerate(fuzzerstate.spec_instr_objs_seq):
            if spec_instr.paddr == 0x28e00:
                spec_instr.instr.imm = offset
                spec_instr.instr.instr_str = instr
                spec_instr.print()
            # elif spec_instr.paddr == 0x28e04:
            #     instr = R12DInstruction_t0(fuzzerstate, "and",ABI_INAMES.index("sp"),ABI_INAMES.index("sp"), ABI_INAMES.index("t4"))
            #     instr.paddr = spec_instr.paddr
            #     fuzzerstate.spec_instr_objs_seq[i] = SpeculativeInstructionEncapsulator(fuzzerstate,instr)
            #     fuzzerstate.spec_instr_objs_seq[i].print()
            elif spec_instr.paddr == 0x28e04:
                instr = IntLoadInstruction_t0(fuzzerstate, instr_str,ABI_INAMES.index("s1"),ABI_INAMES.index("sp"),0,-1)
                instr.paddr = spec_instr.paddr
                fuzzerstate.spec_instr_objs_seq[i] = SpeculativeInstructionEncapsulator(fuzzerstate,instr)
                fuzzerstate.spec_instr_objs_seq[i].print()

        # zero out all other addresses
        fuzzerstate.memview.data_t0 = {key:0 for key in fuzzerstate.memview.data_t0.keys()}
        for i in range(n_bytes):
            fuzzerstate.memview.data_t0[PAGE_ADDR+offset+i] = 0xff
        for i in range(n_bytes):
            fuzzerstate.memview.data[PAGE_ADDR+offset+i] = (0xdeadbeef&(0xff<<i*8))>>i*8

        # remove all non-explicit taints
        for bb_instrs in fuzzerstate.instr_objs_seq:
            for next_instr in bb_instrs:
                if isinstance(next_instr, (ImmRdInstruction_t0, RegImmInstruction_t0, BranchInstruction_t0)):
                    if next_instr.imm_t0:
                        next_instr.imm = 0
                        next_instr.imm_t0 = 0

        for next_instr in fuzzerstate.ctxsv_bb:
            if isinstance(next_instr, (ImmRdInstruction_t0, RegImmInstruction_t0, BranchInstruction_t0)):
                if next_instr.imm_t0:
                    next_instr.imm = 0
                    next_instr.imm_t0 = 0

        # Write 0xdeadbeef to the leaking memory address
        for random_block_id, random_block_content4by4bytes in enumerate(fuzzerstate.random_block_contents4by4bytes):
            for word_id, word_content in enumerate(random_block_content4by4bytes):
                curr_bytecode = word_content.to_bytes(4, 'little')
                for curr_byte_id, curr_byte in enumerate(curr_bytecode):
                    curr_addr = fuzzerstate.random_data_block_ranges[random_block_id][0] + 4*word_id + curr_byte_id # NO_COMPRESSED
                    if SPIKE_STARTADDR + curr_addr == PAGE_ADDR+offset:
                        print(f"Overwriting {hex(fuzzerstate.random_block_contents4by4bytes[random_block_id][word_id])}")
                        fuzzerstate.random_block_contents4by4bytes[random_block_id][word_id] = 0xdeadbeef

        # gen new elf with modified speculative instructions
        fuzzerstate.rtl_elfpath = gen_elf_from_bbs(fuzzerstate, False, f'{n_bytes}bytes-from-{hex(PAGE_ADDR+offset)}-', fuzzerstate.instance_to_str(), fuzzerstate.design_base_addr)

        # check if it leaks
        is_success, exception = runtest_simulator(fuzzerstate, fuzzerstate.rtl_elfpath, fuzzerstate.expected_regvals, sum([len(i) for i in fuzzerstate.instr_objs_seq]))
        # print(f"Leaking from addr {hex(PAGE_ADDR+offset)}. Success: {not is_success}")
        if not is_success:
            print(f"Leaked {n_bytes} bytes from addr {hex(PAGE_ADDR+offset)} at offset {hex(offset)}!")
        else:
            print(f"Failed leaking {n_bytes} bytes from addr {hex(PAGE_ADDR+offset)} at offset {hex(offset)}!")

        leak_success[offset][n_bytes] = not is_success
    break


# %%
