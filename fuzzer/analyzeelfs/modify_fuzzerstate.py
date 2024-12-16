#%%
import sys
sys.path.append("../")
%env  ASSERT_WRITEBACK_TRACE=0
# %env NO_REMOVE_TMPFILES=1
# %env PRINT_ENVIRONMENT=1
%env CASCADE_DATADIR="pickletest-mod"
import multiprocessing as mp
from cascade.fuzzerstate import FuzzerState
import pickle
from cascade.fuzzsim import runtest_simulator
from cascade.spikeresolution import SPIKE_STARTADDR
FUZZERSTATE_PATH = "/mnt/cascade-data/pickletest/boom/729549_boom_275_73/rtlreduce_reducestart729549_boom_275_73_7_28_7_0.fuzzerstate.pickle"
# %%
with open(FUZZERSTATE_PATH, "rb") as f:
    fuzzerstate = pickle.load(f)
# %%
# Also change page addr?
OFFSETS = range(-(2**11)-1,2**11-1,1)
PAGE_ADDR = SPIKE_STARTADDR + 0x98800
leak_success = {offset:False for offset in OFFSETS}
for offset in OFFSETS:
    # find speculative instr and change offset
    for spec_instr in fuzzerstate.spec_instr_objs_seq:
        if spec_instr.paddr == 0x28e00:
            spec_instr.instr.imm = offset
            spec_instr.instr.instr_str = "lb"
            # spec_instr.print()
            break
    # zero out all other addresses
    fuzzerstate.memview.data_t0 = {key:0 for key in fuzzerstate.memview.data_t0.keys()}
    fuzzerstate.memview.data_t0[PAGE_ADDR+offset] = 0xff
    # check if it leaks
    is_success, exception = runtest_simulator(fuzzerstate, fuzzerstate.rtl_elfpath, fuzzerstate.expected_regvals, sum([len(i) for i in fuzzerstate.instr_objs_seq]))
    # print(f"Leaking from addr {hex(PAGE_ADDR+offset)}. Success: {not is_success}")
    if not is_success:
        print(f"Leaked from addr {hex(PAGE_ADDR+offset)} at offset {hex(offset)}!")
    leak_success[offset] = not is_success
# %%
