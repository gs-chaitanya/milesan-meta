import os, random, numpy as np
import shutil
import glob
import json

from params.runparams import PATH_TO_TMP, PATH_TO_COV, PRINT_INSTRUCTION_EXECUTION_FINAL, INSERT_REGDUMPS
from milesan.fuzzfromdescriptor import NUM_MAX_BBS_UPPERBOUND, gen_fuzzerstate_elf_expectedvals_interm, gen_fuzzerstate_elf_expectedvals, gen_new_test_instance, gen_fuzzerstate_elf_flipped_bits
from milesan.cfinstructionclasses import *
from milesan.fuzzsim import run_rtl_and_load_regstream
import subprocess, itertools
from common import designcfgs
from common.spike import SPIKE_STARTADDR
from milesan.randomize.pickbytecodetaints import CFINSTRCLASS_INJECT_PROBS
from milesan.registers import ABI_INAMES,MAX_32b
from milesan.spikeresolution import spike_resolution_return_interm
from drfuzz_mem.check_isa_sim_taint import check_isa_sim_taint, FuzzerStateException

MAX_CYCLES_PER_INSTR = 30
SETUP_CYCLES = 1000 # Without this, we had issues with BOOM with very short programs (typically <20 instructions) not being able to finish in time.
N_MAX_FAIL_REDUCE = 3
def reduce_reg_taint(design_name: str, seed: int):   
    try:
        check_isa_sim_taint(design_name, seed)
        print("No exception triggered. Exiting.")
        exit(0)
    except FuzzerStateException as e:
        print(e)
        fuzzerstate = e.fuzzerstate

    n_fail_reduce = 0
    n_total_tainted_bits = fuzzerstate.memview.restore_and_reduce_taint(True)
    while n_total_tainted_bits>1 and n_fail_reduce < N_MAX_FAIL_REDUCE:
        fuzzerstate.dump_memview_t0()
        fuzzerstate.intregpickstate.setup_registers()
        fuzzerstate.csrfile.reset()
        try:
            check_isa_sim_taint(design_name, seed, False, fuzzerstate)
            print("No exception triggered. Restoring previous input taints.")
            n_fail_reduce += 1
            n_total_tainted_bits = fuzzerstate.memview.restore_and_reduce_taint(False)

        except Exception as e:
            print(e)
            print("Exception triggered. Further reducing input taints.")
            n_total_tainted_bits = fuzzerstate.memview.restore_and_reduce_taint(True)
            n_fail_reduce = 0
    print("Finished reducing input taint.")

    return True



