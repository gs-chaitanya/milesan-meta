import os, random, numpy as np
import shutil
import glob
import json

from params.runparams import CHECK_PC_SPIKE_AGAIN, PRINT_INSTRUCTION_EXECUTION_FINAL, INSERT_REGDUMPS, PRINT_REGISTER_VALIDATION, PRINT_MEMORY_VALIDATION, PRINT_SKIPPED_CHECKS, PRINT_AND_COMPARE, NO_REMOVE_TMPDIRS, NO_REMOVE_TMPFILES, DO_DOUBLECHECK_SIM, CHECK_MEM, COLLECT_PERF_STATS, COLLECT_EXCEPTION_STATS, COLLECT_TAINT_STATS
from params.fuzzparams import IGNORE_RTL_TIMEOUT, IGNORE_SPIKE_TIMEOUT, IGNORE_TAINT_MISMATCH, IGNORE_VALUE_MISMATCH, IGNORE_SPIKE_MISMATCH
from params.fuzzparams import USE_SPIKE_INTERM_ELF, TAINT_EN, ASSERT_EXEC_IN_TAINT_SINK_PRIV, DUMP_MCYCLES
from cascade.toleratebugs import  is_tolerate_cva6_mhpmcounter,  is_tolerate_cva6_mhpmevent31
from cascade.toleratebugs import is_tolerate_boom_minstret
from cascade.toleratebugs import is_tolerate_rocket_minstret
from cascade.fuzzfromdescriptor import gen_fuzzerstate_elf_expectedvals_interm, gen_fuzzerstate_elf_expectedvals, gen_new_test_instance
from cascade.cfinstructionclasses import *
from cascade.cfinstructionclasses_t0 import RegdumpInstruction_t0
from cascade.fuzzsim import run_rtl_and_load_regstream
from cascade.util import IntRegIndivState
from common.spike import SPIKE_STARTADDR
from cascade.randomize.pickbytecodetaints import CFINSTRCLASS_INJECT_PROBS
from cascade.registers import ABI_INAMES,MAX_32b
import enum
import subprocess
import time
def is_tolerate(design_name: str, instr: BaseInstruction):
    if isinstance(instr, (CSRInstruction, EPCWriterInstruction, GenericCSRWriterInstruction)):
        if "boom" in design_name:
            if instr.csr_id == CSR_IDS.MINSTRET:
                return is_tolerate_boom_minstret()
        elif "rocket" in design_name:
            if instr.csr_id == CSR_IDS.MINSTRET:
                return  is_tolerate_rocket_minstret()
        elif "cva6" in design_name:
            if instr.csr_id == CSR_IDS.MHPMCOUNTER3:
                return is_tolerate_cva6_mhpmcounter()
            if instr.csr_id == CSR_IDS.MHPMEVENT31:
                return is_tolerate_cva6_mhpmevent31()

    return True



class FailTypeEnum(enum.IntEnum):
    SPIKE_TIMEOUT = enum.auto()
    RTL_TIMEOUT = enum.auto()
    VALUE_MISMATCH = enum.auto()
    TAINT_MISMATCH = enum.auto()
    NO_FAILURE = enum.auto()

class FuzzerStateException(Exception):
    def __init__(self, *args: object, fuzzerstate, fail_type: FailTypeEnum, timestamp) -> None:
        super().__init__(*args)
        self.fuzzerstate = fuzzerstate
        self.fail_type = fail_type
        self.timestamp = timestamp
        if COLLECT_EXCEPTION_STATS:
            with open(os.path.join(fuzzerstate.tmp_dir, "exception.json"), "w") as f:
                json.dump({
                    "id": fuzzerstate.instance_to_str(),
                    "dut": fuzzerstate.design_name,
                    "t_total":timestamp,
                    "fail_type": self.fail_type.name,
                    "seed":fuzzerstate.randseed
                }, f)

class MismatchError(ValueError):
    def __init__(self, *args: object, fail_type: FailTypeEnum) -> None:
        super().__init__(*args)
        self.fail_type = fail_type

def check_isa_sim_taint(design_name: str,seed: int, generate_fuzzerstate: bool = True, fuzzerstate = None):   
    start_time = time.time()
    if generate_fuzzerstate:
        assert fuzzerstate is None, "fuzzerstate needs to be None when generate_fuzzerstate is enabled."
        fuzzerstate, rtl_elfpath, interm_elfpath, expected_regvals,time_seconds_spent_in_gen_bbs, time_seconds_spent_in_spike_resol, time_seconds_spent_in_gen_elf  = gen_fuzzerstate_elf_expectedvals(*gen_new_test_instance(design_name, seed, True), CHECK_PC_SPIKE_AGAIN) # can only do doublecheck if INSERT_REGDUMPS disabled since spike does not support them
        n_instr_in_priv, forbidden_privs = fuzzerstate.compute_context_stats()
        if USE_MMU and ASSERT_EXEC_IN_TAINT_SINK_PRIV:
            assert sum([n_instr_in_priv[priv] for priv in forbidden_privs]) != 0, f"Computed program does not execute in taint sink privilege(s) {[p.name for p in forbidden_privs]}."
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
    expected_intregvals = expected_regvals[0]
    
    fuzzerstate.setup_env(interm_elfpath if USE_SPIKE_INTERM_ELF else rtl_elfpath,seed)
    if COLLECT_TAINT_STATS:
        print(f'Dumping to {os.path.join(fuzzerstate.tmp_dir, "taint_stats.json")}')
        with open(os.path.join(fuzzerstate.tmp_dir, "taint_stats.json"), "w") as f:
            json.dump(fuzzerstate.compute_taint_stats(),f)
    fuzzerstate.write_imm_t0_to_mem() # Write the immediate taints from the program code to the imem.
    fuzzerstate.dump_memview_t0()
    try:
        start_time_rtl = time.time()
        regstream_rtl, final_regvals_rtl, final_sramdump_rtl = run_rtl_and_load_regstream(fuzzerstate)
        time_seconds_spent_in_rtl = time.time() - start_time_rtl
        if not len(final_regvals_rtl):
            raise FuzzerStateException(f"{fuzzerstate.instance_to_str()}: Modelsim timeout: Did not receive register requests.",fuzzerstate=fuzzerstate, fail_type=FailTypeEnum.RTL_TIMEOUT, timestamp=time.time()-start_time)

        regstream_rtl_val, regstream_rtl_val_t0 = regstream_rtl

        fuzzerstate.curr_pc = SPIKE_STARTADDR
        fuzzerstate.privilegestate.privstate = PrivilegeStateEnum.MACHINE
        regdump_idx = 0
        for bb_id, bb_instrs in enumerate(fuzzerstate.instr_objs_seq):
            for next_instr in bb_instrs:
                addr = next_instr.paddr if not USE_MMU else next_instr.vaddr
                if DO_DOUBLECHECK_SIM:
                    ## RTL SIM CHECK WHEN INSERT_REGDUMPS IS ENABLED ##
                    if isinstance(next_instr, RegdumpInstruction_t0):
                        assert INSERT_REGDUMPS, f"Encountered RegdumpInstruction with INSERT_REGDUMPS disabled."
                        try:
                            next_instr.check_regs(regstream_rtl_val[regdump_idx]) # check value before executing instruction
                        except AssertionError as e:
                            raise MismatchError(str(e), fail_type=FailTypeEnum.VALUE_MISMATCH)
                        if TAINT_EN:
                            try:
                                next_instr.check_regs_t0(regstream_rtl_val_t0[regdump_idx]) # check value before executing instruction
                            except AssertionError as e:
                                raise MismatchError(str(e), fail_type=FailTypeEnum.TAINT_MISMATCH)
                        regdump_idx += 1
                    
                    ## SPIKE SIM CHECK ##
                    elif addr in pc_reg_pairs:
                        try:
                            next_instr.check_regs(pc_reg_pairs[addr]) # check value before executing instruction. Skip if placeholder as their values change between spikeresol and final elf.
                        except AssertionError as e:
                            raise MismatchError(str(e), fail_type=FailTypeEnum.VALUE_MISMATCH)
                    
                    ## SKIP CHECK ##
                    elif PRINT_SKIPPED_CHECKS:
                        print(f"Skipping check for {next_instr.get_str(USE_SPIKE_INTERM_ELF)}")

                    if PRINT_INSTRUCTION_EXECUTION_FINAL:
                        next_instr.print(USE_SPIKE_INTERM_ELF)

                next_instr.execute(is_spike_resolution=USE_SPIKE_INTERM_ELF)
                
            # if this bb is followed by a context saver block, execute it
            if bb_id == fuzzerstate.last_bb_id_before_ctx_saver:
                for next_instr in fuzzerstate.ctxsv_bb:
                    if DO_DOUBLECHECK_SIM:
                        if isinstance(next_instr, RegdumpInstruction_t0):
                            assert INSERT_REGDUMPS, f"Encountered RegdumpInstruction with INSERT_REGDUMPS disabled."
                            try:
                                next_instr.check_regs(regstream_rtl_val[regdump_idx]) # check value before executing instruction
                            except AssertionError as e:
                                raise MismatchError(str(e), fail_type=FailTypeEnum.VALUE_MISMATCH)
                            if TAINT_EN:
                                try:
                                    next_instr.check_regs_t0(regstream_rtl_val_t0[regdump_idx]) # check value before executing instruction
                                except AssertionError as e:
                                    raise MismatchError(str(e), fail_type=FailTypeEnum.TAINT_MISMATCH)
                            regdump_idx += 1

                        ## SPIKE SIM CHECK ##
                        elif addr in pc_reg_pairs:
                            try:
                                next_instr.check_regs(pc_reg_pairs[addr]) # check value before executing instruction. Skip if placeholder as their values change between spikeresol and final elf.
                            except AssertionError as e:
                                raise MismatchError(str(e), fail_type=FailTypeEnum.VALUE_MISMATCH)
                        
                        # SKIP CHECK ##
                        elif PRINT_SKIPPED_CHECKS:
                            print(f"Skipping check for {next_instr.get_str(USE_SPIKE_INTERM_ELF)}")

                        if PRINT_INSTRUCTION_EXECUTION_FINAL:
                            next_instr.print(USE_SPIKE_INTERM_ELF)
                        
                    next_instr.execute(is_spike_resolution=USE_SPIKE_INTERM_ELF)
        
        if PRINT_REGISTER_VALIDATION:
            print("*** REGISTER VALIDATION ***:")
            fuzzerstate.intregpickstate.print_and_compare(final_regvals_rtl)
        for id in range(fuzzerstate.num_pickable_regs-1):
            value = int(final_regvals_rtl[id]["value"],16)
            value_t0 = int(final_regvals_rtl[id]["value_t0"],16)

            # value validation between in-situ simulation and spike
            mismatch = fuzzerstate.intregpickstate.regs[id+1].check(expected_intregvals[id])
            if mismatch and not IGNORE_SPIKE_MISMATCH:
                raise ValueError(f"(SPIKE) Value mismatch between in-situ and spike for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n\t Traceback: {filter_reg_traceback(id+1, None, fuzzerstate, None, False).get_str()}. \n\t This should not happen!")

            # value validation between in-situ (and spike) simulation and RTL
            mismatch = fuzzerstate.intregpickstate.regs[id+1].check(value)
            if mismatch:
                last_instr = filter_reg_traceback(id+1, None, fuzzerstate, None, False)
                if isinstance(last_instr, EPCWriterInstruction) and last_instr.csr_instr.csr_id == CSR_IDS.SEPC:
                    pass # If the responsible instruction was an SEPC write, we ignore the mismatch as exception priority order is ambiguous when a msialigned memory instruction casues the exception, which also triggers a page fault.
                elif isinstance(last_instr, CSRInstruction) and last_instr.csr_id in (CSR_IDS.SCAUSE, CSR_IDS.MCAUSE):
                    pass # TODO check that *cause values are either misaligned/pagefault
                elif isinstance(last_instr, GenericCSRWriterInstruction) and last_instr.csr_instr.csr_id in (CSR_IDS.SCAUSE, CSR_IDS.MCAUSE):
                    pass
                elif not IGNORE_VALUE_MISMATCH and is_tolerate(design_name, last_instr):
                    raise MismatchError(f"(RTL) Value mismatch between in-situ and RTL for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n\t Traceback: {last_instr.get_str()}", fail_type=FailTypeEnum.VALUE_MISMATCH)

            if TAINT_EN:
                mismatch = fuzzerstate.intregpickstate.regs[id+1].check_t0(value_t0)
                if mismatch and not IGNORE_TAINT_MISMATCH:
                    raise MismatchError(f"(RTL) Taint mismatch between in-situ and RTL for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n\t Traceback: {filter_reg_traceback(id+1, None, fuzzerstate, None, False).get_str()}.\n\t Taint allowed in {[p.name for p in fuzzerstate.taint_in_priv]}.", fail_type=FailTypeEnum.TAINT_MISMATCH)


        if DUMP_MCYCLES:
            assert len(final_regvals_rtl) == MAX_NUM_PICKABLE_REGS, f"Did not dump MCYCLES CSR." # We dump the MCYCLES CSR after all integer registers
            mcycle = int(final_regvals_rtl[MAX_NUM_PICKABLE_REGS-1]["value"],16)
            mcycle_t0 = int(final_regvals_rtl[MAX_NUM_PICKABLE_REGS-1]["value_t0"],16)
            
            if TAINT_EN and mcycle_t0:
                raise MismatchError(f"(RTL) MCYCLE CSR got tainted: {hex(mcycle)}, {hex(mcycle_t0)}.\n\t Taint allowed in {[p.name for p in fuzzerstate.taint_in_priv]}.", fail_type=FailTypeEnum.TAINT_MISMATCH)

        if CHECK_MEM:
            if PRINT_MEMORY_VALIDATION:
                print("*** MEMORY VALIDATION ***:")
                fuzzerstate.memview.print_and_compare(final_sramdump_rtl)
            if fuzzerstate.design_name == "kronos":
                fuzzerstate.memview.check(final_sramdump_rtl)

    except Exception as e:
        if PRINT_AND_COMPARE:
            print("*** REGISTER VALIDATION FAILED ***")
            fuzzerstate.intregpickstate.print_and_compare(final_regvals_rtl)
            if fuzzerstate.design_name == "kronos": # kronos does not have a cache so we can validate the memory
                print("*** MEMORY CONTENT  ***")
                fuzzerstate.memview.print_and_compare(final_sramdump_rtl)
        print(f"Failed for seed {seed}")
        if "There are less" in str(e) or "Computed program does not execute" in str(e):
            fuzzerstate.remove_tmp_dir()
        else:
            if not NO_REMOVE_TMPFILES:
                fuzzerstate.remove_tmp_files()
            fuzzerstate.log(str(e))
        if isinstance(e, subprocess.CalledProcessError):
            if "spike" in str(e):
                if IGNORE_SPIKE_TIMEOUT:
                    pass
                else:
                    raise FuzzerStateException(f"{fuzzerstate.instance_to_str()}: {e}",fuzzerstate=fuzzerstate, fail_type=FailTypeEnum.SPIKE_TIMEOUT, timestamp=time.time()-start_time)
            if "make" in str(e):
                if IGNORE_RTL_TIMEOUT:
                    pass
                else:
                    raise FuzzerStateException(f"{fuzzerstate.instance_to_str()}: {e}",fuzzerstate=fuzzerstate, fail_type=FailTypeEnum.RTL_TIMEOUT, timestamp=time.time()-start_time)

        elif isinstance(e, MismatchError):
            if COLLECT_PERF_STATS:
                # print(f'dumping to {os.path.join(fuzzerstate.tmp_dir, "perfstats.json")}')
                with open(os.path.join(fuzzerstate.tmp_dir, "perfstats.json"), "w") as f:
                    json.dump({
                        "id": fuzzerstate.instance_to_str(),
                        "dut": fuzzerstate.design_name,
                        "t_gen_bbs": time_seconds_spent_in_gen_bbs,
                        "t_spike_resol": time_seconds_spent_in_spike_resol,
                        "t_gen_elf": time_seconds_spent_in_gen_elf,
                        "t_rtl" : time_seconds_spent_in_rtl,
                        "n_bbs": len(fuzzerstate.instr_objs_seq),
                        "n_instrs": sum([len(i) for i in fuzzerstate.instr_objs_seq]) + len(fuzzerstate.final_bb),
                        "t_total":time.time() - start_time,
                        "fail_type": e.fail_type.name,
                        "seed":fuzzerstate.randseed
                    }, f)
            raise FuzzerStateException(f"{fuzzerstate.instance_to_str()}: {e}",fuzzerstate=fuzzerstate, fail_type=e.fail_type, timestamp=time.time()-start_time)
        else:
            raise e
    return fuzzerstate



