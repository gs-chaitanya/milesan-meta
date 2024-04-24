import os, random, numpy as np
import shutil
import glob
import json

from params.runparams import PATH_TO_TMP, PATH_TO_COV, PRINT_INSTRUCTION_EXECUTION_FINAL, PRINT_ENVIRONMENT, INSERT_REGDUMPS, PRINT_REGISTER_VALIDATION, PRINT_MEMORY_VALIDATION, PRINT_SKIPPED_CHECKS
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

def check_isa_sim_taint(design_name: str,seed: int):   
    # Get fuzzerstate and expected regvals from program.
    fuzzerstate, rtl_elfpath, interm_elfpath, expected_regvals,_,_,_  = gen_fuzzerstate_elf_expectedvals(*gen_new_test_instance(design_name, seed, True), not INSERT_REGDUMPS) # can only do doublecheck if INSERT_REGDUMPS disabled since spike does not support them

    # Retrieve register stream and final intregvals from spike.
    pc_reg_pairs = {req[0] + SPIKE_STARTADDR:{} for req in expected_regvals[2]}
    for req, regval in zip(expected_regvals[2],expected_regvals[3]):
        pc_reg_pairs[req[0] + SPIKE_STARTADDR][req[2]] = regval

    expected_intregvals = expected_regvals[0]

    # Expected regvals of the program where bit was flipped are in in pc_reg_pairs1, which is the one that will be executed in the crossvalidation.
    # Initial program register dumps are in pc_reg_pairs_0, TODO: should this also be executed and checked?
    env = fuzzerstate.setup_env(interm_elfpath if USE_SPIKE_INTERM_ELF else rtl_elfpath,seed)

    regstream_rtl, final_regvals_rtl, final_sramdump_rtl = run_rtl_and_load_regstream(env, fuzzerstate.design_name)

    regstream_rtl_val, regstream_rtl_val_t0 = regstream_rtl

    fuzzerstate.intregpickstate.setup_registers()
    fuzzerstate.memview.restore()
    fuzzerstate.csrfile.reset()
    # print(f"Starting spike cross-validation. (FSM instructions are accounted for.)")
    regdump_idx = 0
    for bb_instrs in fuzzerstate.instr_objs_seq: # skip first and last bb
        for next_instr in bb_instrs:
            if isinstance(next_instr, RegdumpInstruction_t0) and INSERT_REGDUMPS:
                next_instr.check_regs(regstream_rtl_val[regdump_idx]) # check value before executing instruction
                next_instr.check_regs_t0(regstream_rtl_val_t0[regdump_idx]) # check value before executing instruction
                regdump_idx += 1
            elif not is_placeholder(next_instr):
                next_instr.check_regs(pc_reg_pairs[next_instr.addr]) # check value before executing instruction. Skip if placeholder as their values change between spikeresol and final elf.
            elif PRINT_SKIPPED_CHECKS:
                print(f"Skipping check for {next_instr.get_str(USE_SPIKE_INTERM_ELF)}")

            next_instr.execute(fuzzerstate.taint_en, is_spike_resolution=USE_SPIKE_INTERM_ELF)
            if PRINT_INSTRUCTION_EXECUTION_FINAL:
                next_instr.print(USE_SPIKE_INTERM_ELF)

    try:
        for (addr_in_situ,trace_in_situ),(addr_final, trace_final) in zip(fuzzerstate.intregpickstate.writeback_trace_in_situ.items(),fuzzerstate.intregpickstate.writeback_trace_final.items()):
            assert addr_in_situ == addr_final
            assert trace_in_situ[0] == trace_final[0]
            assert trace_in_situ[1] == trace_final[1], f"Mismatch in taint trace between in-situ simulation and final elf: {hex(addr_final)}: {ABI_INAMES[trace_in_situ[0]]} <- {hex(trace_in_situ[1])}/{hex(trace_final[1])} (in-situ/final).{filter_reg_t0_traceback(trace_in_situ[0],addr_in_situ,fuzzerstate).get_str(False)}"
            # else:
            #     print(f"{hex(addr_spike)}: {ABI_INAMES[trace_spike[0]]} <- {hex(trace_spike[1])}")

        if PRINT_REGISTER_VALIDATION:
            print("*** REGISTER VALIDATION ***:")
            fuzzerstate.intregpickstate.print_and_compare(final_regvals_rtl)
        for id in range(fuzzerstate.num_pickable_regs-1):
            value = int(final_regvals_rtl[id]["value"],16)
            value_t0 = int(final_regvals_rtl[id]["value_t0"],16)
            mismatch = fuzzerstate.intregpickstate.regs[id+1].check(value)
            assert not mismatch, f"Value mismatch for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n\t Traceback: {filter_reg_traceback(id+1, None, fuzzerstate, None, False).get_str(False)}"
            mismatch = fuzzerstate.intregpickstate.regs[id+1].check(expected_intregvals[id])
            assert not mismatch, f"Value mismatch for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n\t Traceback: {filter_reg_traceback(id+1, None, fuzzerstate, None, False).get_str(False)}"
            mismatch = fuzzerstate.intregpickstate.regs[id+1].check_t0(value_t0)
            assert not mismatch, f"Taint mismatch for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n\t Traceback: {filter_reg_traceback(id+1, None, fuzzerstate, None, False).get_str(False)}"

        if PRINT_MEMORY_VALIDATION:
            print("*** MEMORY VALIDATION ***:")
            fuzzerstate.memview.print_and_compare(final_sramdump_rtl)
        if fuzzerstate.design_name == "kronos":
            fuzzerstate.memview.check(final_sramdump_rtl)

        # print("Ok.")

    except Exception as e:
        # os.removedirs(trace_dir)
        # if os.path.isfile(env_path): os.remove(env_path)
        # if os.path.isfile(interm_elfpath): os.remove(interm_elfpath)
        print("*** REGISTER VALIDATION FAILED ***")
        fuzzerstate.intregpickstate.print_and_compare(final_regvals_rtl)
        if fuzzerstate.design_name == "kronos":
            print("*** MEMORY CONTENT  ***")
            fuzzerstate.memview.print_and_compare(final_sramdump_rtl)
        print(f"Failed for seed {seed}")
        raise e

    return True



