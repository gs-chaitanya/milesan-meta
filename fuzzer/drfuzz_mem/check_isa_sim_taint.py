import os, random, numpy as np
import shutil
import glob
import json

from params.runparams import PATH_TO_TMP, PATH_TO_COV, PRINT_INSTRUCTION_EXECUTION_FINAL, PRINT_ENVIRONMENT, INSERT_REGDUMPS, PRINT_REGISTER_VALIDATION, PRINT_MEMORY_VALIDATION, PRINT_SKIPPED_CHECKS, PRINT_AND_COMPARE
from params.fuzzparams import USE_SPIKE_INTERM_ELF
from cascade.fuzzfromdescriptor import NUM_MAX_BBS_UPPERBOUND, gen_fuzzerstate_elf_expectedvals_interm, gen_fuzzerstate_elf_expectedvals, gen_new_test_instance
from cascade.cfinstructionclasses import *
from cascade.cfinstructionclasses_t0 import RegdumpInstruction_t0, filter_reg_t0_traceback
from cascade.fuzzsim import run_rtl_and_load_regstream
from common.spike import SPIKE_STARTADDR
from cascade.randomize.pickbytecodetaints import CFINSTRCLASS_INJECT_PROBS
from cascade.registers import ABI_INAMES,MAX_32b
from cascade.spikeresolution import spike_resolution_return_interm
from drfuzz_mem.spike_sim_taint import spike_sim_taint

class FuzzerStateException(Exception):
    def __init__(self, *args: object, fuzzerstate) -> None:
        super().__init__(*args)
        self.fuzzerstate = fuzzerstate

def check_isa_sim_taint(design_name: str,seed: int, generate_fuzzerstate: bool = True, fuzzerstate = None):   
    if generate_fuzzerstate:
        assert fuzzerstate is None, "fuzzerstate needs to be None when generate_fuzzerstate is enabled."
        fuzzerstate, rtl_elfpath, interm_elfpath, expected_regvals,_,_,_  = gen_fuzzerstate_elf_expectedvals(*gen_new_test_instance(design_name, seed, True), not INSERT_REGDUMPS) # can only do doublecheck if INSERT_REGDUMPS disabled since spike does not support them
        fuzzerstate.intregpickstate.setup_registers()
        fuzzerstate.memview.restore()
        fuzzerstate.csrfile.reset()
    else:
        assert fuzzerstate is not None, "fuzzerstate needs to be provided when generate_fuzzerstate is disabled."
        expected_regvals = fuzzerstate.expected_regvals
        rtl_elfpath = fuzzerstate.rtl_elfpath
        interm_elfpath = fuzzerstate.interm_elfpath
        
    # Retrieve register stream and final intregvals from spike.
    pc_reg_pairs = {req[0] + SPIKE_STARTADDR:{} for req in expected_regvals[2]}
    for req, regval in zip(expected_regvals[2],expected_regvals[3]):
        pc_reg_pairs[req[0] + SPIKE_STARTADDR][req[2]] = regval

    expected_intregvals = expected_regvals[0]

    env = fuzzerstate.setup_env(interm_elfpath if USE_SPIKE_INTERM_ELF else rtl_elfpath,seed)

    regstream_rtl, final_regvals_rtl, final_sramdump_rtl = run_rtl_and_load_regstream(env, fuzzerstate.design_name)
    regstream_rtl_val, regstream_rtl_val_t0 = regstream_rtl

    regdump_idx = 0
    try:
        for bb_instrs in fuzzerstate.instr_objs_seq: # skip first and last bb
            for next_instr in bb_instrs:
                if isinstance(next_instr, RegdumpInstruction_t0) and INSERT_REGDUMPS:
                    if not USE_SPIKE_INTERM_ELF:
                        next_instr.check_regs(regstream_rtl_val[regdump_idx]) # check value before executing instruction
                        if TAINT_EN:
                            next_instr.check_regs_t0(regstream_rtl_val_t0[regdump_idx]) # check value before executing instruction
                        regdump_idx += 1
                elif not is_placeholder(next_instr) and next_instr.addr in pc_reg_pairs:
                    next_instr.check_regs(pc_reg_pairs[next_instr.addr]) # check value before executing instruction. Skip if placeholder as their values change between spikeresol and final elf.
                elif PRINT_SKIPPED_CHECKS:
                    print(f"Skipping check for {next_instr.get_str(USE_SPIKE_INTERM_ELF)}")

                next_instr.execute(fuzzerstate.taint_en, is_spike_resolution=USE_SPIKE_INTERM_ELF)
                if PRINT_INSTRUCTION_EXECUTION_FINAL:
                    next_instr.print(USE_SPIKE_INTERM_ELF)

        if generate_fuzzerstate:
            for (addr_in_situ,trace_in_situ),(addr_final, trace_final) in zip(fuzzerstate.intregpickstate.writeback_trace_in_situ.items(),fuzzerstate.intregpickstate.writeback_trace_final.items()):
                assert addr_in_situ == addr_final
                assert trace_in_situ[0] == trace_final[0]
                assert trace_in_situ[1] == trace_final[1], f"Mismatch in taint trace between in-situ simulation and final elf: {hex(addr_final)}: {ABI_INAMES[trace_in_situ[0]]} <- {hex(trace_in_situ[1])}/{hex(trace_final[1])} (in-situ/final).{filter_reg_t0_traceback(trace_in_situ[0],addr_in_situ,fuzzerstate).get_str()}"
                # else:
                #     print(f"{hex(addr_spike)}: {ABI_INAMES[trace_spike[0]]} <- {hex(trace_spike[1])}")

        if PRINT_REGISTER_VALIDATION:
            print("*** REGISTER VALIDATION ***:")
            fuzzerstate.intregpickstate.print_and_compare(final_regvals_rtl)
        for id in range(fuzzerstate.num_pickable_regs-1):
            value = int(final_regvals_rtl[id]["value"],16)
            value_t0 = int(final_regvals_rtl[id]["value_t0"],16)
            mismatch = fuzzerstate.intregpickstate.regs[id+1].check(value)
            assert not mismatch, f"Value mismatch for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n\t Traceback: {filter_reg_traceback(id+1, None, fuzzerstate, None, False).get_str()}"
            mismatch = fuzzerstate.intregpickstate.regs[id+1].check(expected_intregvals[id])
            assert not mismatch, f"Value mismatch for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n\t Traceback: {filter_reg_traceback(id+1, None, fuzzerstate, None, False).get_str()}"
            mismatch = fuzzerstate.intregpickstate.regs[id+1].check_t0(value_t0)
            assert not mismatch, f"Taint mismatch for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n\t Traceback: {filter_reg_traceback(id+1, None, fuzzerstate, None, False).get_str()}"

        if PRINT_MEMORY_VALIDATION:
            print("*** MEMORY VALIDATION ***:")
            fuzzerstate.memview.print_and_compare(final_sramdump_rtl)
        if fuzzerstate.design_name == "kronos":
            fuzzerstate.memview.check(final_sramdump_rtl)
        # # print("Ok.")

    except Exception as e:
        if PRINT_AND_COMPARE:
            print("*** REGISTER VALIDATION FAILED ***")
            fuzzerstate.intregpickstate.print_and_compare(final_regvals_rtl)
            if fuzzerstate.design_name == "kronos": # kronos does not have a cache so we can validate the memory
                print("*** MEMORY CONTENT  ***")
                fuzzerstate.memview.print_and_compare(final_sramdump_rtl)
        print(f"Failed for seed {seed}")
        raise FuzzerStateException(f"{fuzzerstate.instance_to_str()}: {e}",fuzzerstate=fuzzerstate)

    return fuzzerstate



