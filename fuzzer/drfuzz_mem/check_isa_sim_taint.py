import os, random, numpy as np
import shutil
import glob
import json

from params.runparams import CHECK_PC_SPIKE_AGAIN, PRINT_INSTRUCTION_EXECUTION_FINAL, INSERT_REGDUMPS, PRINT_REGISTER_VALIDATION, PRINT_MEMORY_VALIDATION, PRINT_SKIPPED_CHECKS, PRINT_AND_COMPARE
from params.fuzzparams import USE_SPIKE_INTERM_ELF, TAINT_EN
from cascade.fuzzfromdescriptor import gen_fuzzerstate_elf_expectedvals_interm, gen_fuzzerstate_elf_expectedvals, gen_new_test_instance
from cascade.cfinstructionclasses import *
from cascade.cfinstructionclasses_t0 import RegdumpInstruction_t0, RDInstruction_t0
from cascade.fuzzsim import run_rtl_and_load_regstream
from cascade.util import IntRegIndivState
from common.spike import SPIKE_STARTADDR
from cascade.randomize.pickbytecodetaints import CFINSTRCLASS_INJECT_PROBS
from cascade.registers import ABI_INAMES,MAX_32b
from cascade.spikeresolution import spike_resolution_return_interm
from drfuzz_mem.spike_sim_taint import spike_sim_taint

class FuzzerStateException(Exception):
    def __init__(self, *args: object, fuzzerstate) -> None:
        super().__init__(*args)
        self.fuzzerstate = fuzzerstate

def check_isa_sim_taint(design_name: str,seed: int, generate_fuzzerstate: bool = True, fuzzerstate = None, taint_en: bool = TAINT_EN):   
    if generate_fuzzerstate:
        assert fuzzerstate is None, "fuzzerstate needs to be None when generate_fuzzerstate is enabled."
        fuzzerstate, rtl_elfpath, interm_elfpath, expected_regvals,_,_,_  = gen_fuzzerstate_elf_expectedvals(*gen_new_test_instance(design_name, seed, True), CHECK_PC_SPIKE_AGAIN, taint_en) # can only do doublecheck if INSERT_REGDUMPS disabled since spike does not support them
        fuzzerstate.intregpickstate.setup_registers() # Restore registers to before anything was executed.
        fuzzerstate.memview.restore(0) # Restore contents before anything was executed.
        fuzzerstate.csrfile.reset() # Reset all CSRs to zero.
    else:
        assert fuzzerstate is not None, "fuzzerstate needs to be provided when generate_fuzzerstate is disabled."
        expected_regvals = fuzzerstate.expected_regvals
        rtl_elfpath = fuzzerstate.rtl_elfpath
        interm_elfpath = fuzzerstate.interm_elfpath

    # Retrieve register stream and final intregvals from spike.
    pc_reg_pairs = {req[0] + SPIKE_STARTADDR:{} for req in expected_regvals[2]}
    for req, regval in zip(expected_regvals[2],expected_regvals[3]):
        pc_reg_pairs[req[0] + SPIKE_STARTADDR][req[2]] = regval
        # print(f"{hex(req[0] + SPIKE_STARTADDR)}: {ABI_INAMES[req[2]]} = {hex(regval)}")
    expected_intregvals = expected_regvals[0]
    
    env = fuzzerstate.setup_env(interm_elfpath if USE_SPIKE_INTERM_ELF else rtl_elfpath,seed)

    fuzzerstate.dump_memview_t0()
    
    regstream_rtl, final_regvals_rtl, final_sramdump_rtl = run_rtl_and_load_regstream(env, fuzzerstate.design_name)
    regstream_rtl_val, regstream_rtl_val_t0 = regstream_rtl

    fuzzerstate.curr_pc = SPIKE_STARTADDR
    fuzzerstate.privilegestate.privstate = PrivilegeStateEnum.MACHINE
    regdump_idx = 0
    try:
        for bb_id, bb_instrs in enumerate(fuzzerstate.instr_objs_seq):
            for next_instr in bb_instrs:
                addr = next_instr.paddr if not USE_MMU else next_instr.vaddr
                # RTL SIM CHECK
                if isinstance(next_instr, RegdumpInstruction_t0) and INSERT_REGDUMPS:
                    if not USE_SPIKE_INTERM_ELF:
                        next_instr.check_regs(regstream_rtl_val[regdump_idx]) # check value before executing instruction
                        if fuzzerstate.taint_en:
                            next_instr.check_regs_t0(regstream_rtl_val_t0[regdump_idx]) # check value before executing instruction
                        regdump_idx += 1
                # SPIKE SIM CHECK
                elif not is_placeholder(next_instr) and addr in pc_reg_pairs: # TODO: why use is_placeholder? Values should also match here i think.
                    next_instr.check_regs(pc_reg_pairs[addr]) # check value before executing instruction. Skip if placeholder as their values change between spikeresol and final elf.
                elif PRINT_SKIPPED_CHECKS:
                    print(f"Skipping check for {next_instr.get_str(USE_SPIKE_INTERM_ELF)}")

                if PRINT_INSTRUCTION_EXECUTION_FINAL:
                    next_instr.print(USE_SPIKE_INTERM_ELF)
                next_instr.execute(fuzzerstate.taint_en, is_spike_resolution=USE_SPIKE_INTERM_ELF)
                
            # if this bb is followed by a context saver block, execute it
            if bb_id in fuzzerstate.bb_id_to_ctxsv_id:
                ctxsv_bb_id = fuzzerstate.bb_id_to_ctxsv_id[bb_id]
                for next_instr in fuzzerstate.ctxsv_bbs[ctxsv_bb_id]:
                    next_instr.execute(fuzzerstate.taint_en, is_spike_resolution=USE_SPIKE_INTERM_ELF)
                    if PRINT_INSTRUCTION_EXECUTION_FINAL:
                        print(f"{next_instr.get_str(USE_SPIKE_INTERM_ELF)} (ctx)")
        
        if PRINT_REGISTER_VALIDATION:
            print("*** REGISTER VALIDATION ***:")
            fuzzerstate.intregpickstate.print_and_compare(final_regvals_rtl)
        for id in range(fuzzerstate.num_pickable_regs-1):
            value = int(final_regvals_rtl[id]["value"],16)
            value_t0 = int(final_regvals_rtl[id]["value_t0"],16)

            # value validation between in-situ simulation and spike
            mismatch = fuzzerstate.intregpickstate.regs[id+1].check(expected_intregvals[id])
            if mismatch:
                raise ValueError(f"(SPIKE) Value mismatch between in-situ and spike for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n\t Traceback: {filter_reg_traceback(id+1, None, fuzzerstate, None, False).get_str()}")

            # value validation between in-situ simulation and RTL
            mismatch = fuzzerstate.intregpickstate.regs[id+1].check(value)
            if mismatch:
                last_instr = filter_reg_traceback(id+1, None, fuzzerstate, None, False)
                if isinstance(last_instr, EPCWriterInstruction) and last_instr.csr_instr.csr_id == CSR_IDS.SEPC:
                    pass # If the responsible instruction was an SEPC write, we ignore the mismatch as exception priority order is ambiguous.
                else:    
                    raise ValueError(f"(RTL) Value mismatch between in-situ and RTL for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n\t Traceback: {last_instr.get_str()}")

            if fuzzerstate.taint_en:
                mismatch = fuzzerstate.intregpickstate.regs[id+1].check_t0(value_t0)
                if mismatch:
                    raise ValueError(f"(RTL) mismatch between in-situ and RTL for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n\t Traceback: {filter_reg_traceback(id+1, None, fuzzerstate, None, False).get_str()}")

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
        if "There are less" in str(e):
            fuzzerstate.remove_tmp_files()
        else:
            fuzzerstate.log(str(e))
        raise FuzzerStateException(f"{fuzzerstate.instance_to_str()}: {e}",fuzzerstate=fuzzerstate)

    return fuzzerstate



