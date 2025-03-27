# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script is responsible for running the RTL simulations from the fuzzer.

from params.fuzzparams import MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_FLOATING_REGS,USE_VANILLA, MAX_CYCLES_PER_INSTR, SETUP_CYCLES, STOP_AT_PC_TAINT
from params.runparams import DO_ASSERT, PATH_TO_TMP, NO_REMOVE_TMPFILES, NO_REMOVE_TMPDIRS, TRACE_FST, TRACE_EN, CHECK_MEM, PATH_TO_MNT, MODELSIM_REQ_DIR, PATH_FROM_MODELSIM_TO_MNT, INSERT_REGDUMPS, USE_MODELSIM, COV_EN
from milesan.util import IntRegIndivState, SimulatorEnum
from common.sim.modelsim import get_next_worker_id
from common.sim.commonsim import setup_sim_env
from common import designcfgs
from milesan.spikeresolution import SPIKE_STARTADDR
from time import gmtime, strftime

import itertools
import os
import subprocess
import sys
import json
from distutils import dir_util
import time
import shutil

PRINT_THREAD_STATUS = False
# @param get_rfuzz_coverage_mask if True, then return a pair (is_stop_successful: bool, rfuzz_coverage_mask: int)
# Return a pair (is_stop_successful: bool, reg_vals: int list of length <= MAX_NUM_PICKABLE_REGS-1 or None if is_stop_successful is False)
def runsim_verilator(design_name, simlen, elfpath, num_int_regs: int = MAX_NUM_PICKABLE_REGS-1, num_float_regs: int = MAX_NUM_PICKABLE_FLOATING_REGS, coveragepath = None, get_rfuzz_coverage_mask = False):
    if DO_ASSERT:
        assert coveragepath is None or not get_rfuzz_coverage_mask

    design_cfg       = designcfgs.get_design_cfg(design_name)
    milesandir       = designcfgs.get_design_milesan_path(design_name)
    builddir         = os.path.join(milesandir,'build')

    my_env = setup_sim_env(elfpath, '/dev/null', '/dev/null', simlen, milesandir, coveragepath, False)

    simdir               = f"run_{'coverage' if coveragepath else 'rfuzz' if get_rfuzz_coverage_mask else 'vanilla'}_{'notrace'}_0.1"
    verilatordir         = 'default-verilator'
    verilator_executable = 'V%s' % design_cfg['toplevel']
    sim_executable_path  = os.path.abspath(os.path.join(builddir, simdir, verilatordir, verilator_executable))

    # Run Verilator
    exec_out = subprocess.run([sim_executable_path], check=True, text=True, capture_output=True, env=my_env)
    outlines = list(filter(lambda l: 'Writing ELF word to' not in l, exec_out.stdout.split('\n')))

    # Check stop success
    is_stop_successful = 'Found a stop request.' in exec_out.stdout
    if not is_stop_successful:
        return False, None

    # Retrieve the register values
    ret_intregs = []
    ret_floatregs = []
    curr_index = 0
    for reg_id in range(1, num_int_regs+1):
        for row_id in itertools.count(curr_index):
            if len(outlines[row_id]) >= 19 and outlines[row_id][:19] == f"Dump of reg x{reg_id:02}: 0x":
                ret_intregs.append(int(outlines[row_id][19:35], 16))
                curr_index = row_id + 1
                break
    if designcfgs.design_has_float_support(design_name):
        for fp_reg_id in range(num_float_regs):
            for row_id in itertools.count(curr_index):
                if row_id >= len(outlines):
                    # This happens if the FPU is disabled in the final block and the final permission level does not permit enabling it.
                    ret_floatregs.append(None)
                    curr_index = row_id + 1
                    break
                if len(outlines[row_id]) >= 19 and outlines[row_id][:19] == f"Dump of reg f{fp_reg_id:02}: 0x":
                    ret_floatregs.append(int(outlines[row_id][19:35], 16))
                    curr_index = row_id + 1
                    break
    if get_rfuzz_coverage_mask:
        for row_id in range(curr_index, len(outlines)):
            # print('outlines[row_id]', outlines[row_id])
            if len(outlines[row_id]) >= 21 and outlines[row_id][:21] == f"RFUZZ coverage mask: ":
                rfuzz_coverage_mask = int(outlines[row_id][22:], 16)
                return True, rfuzz_coverage_mask
        raise Exception("Could not find the RFUZZ coverage mask.")
    return True, (ret_intregs, ret_floatregs)


# Return a pair (is_stop_successful: bool, reg_vals: int list of length <= MAX_NUM_PICKABLE_REGS-1 or None if is_stop_successful is False)
def runsim_modelsim(design_name, simlen, elfpath, num_int_regs: int = MAX_NUM_PICKABLE_REGS-1, num_float_regs: int = MAX_NUM_PICKABLE_FLOATING_REGS, coveragepath = None):
    milesandir       = designcfgs.get_design_milesan_path(design_name)

    my_env = setup_sim_env(elfpath, '/dev/null', '/dev/null', simlen, milesandir, coveragepath, False)
    # Run the simulation on the same worker id as the core used for this worker. This may not be absolutely optimal.
    curr_coreid = get_next_worker_id()
    my_env["FUZZCOREID"] = str(curr_coreid)
    my_env["MODELSIM_NOQUIT"] = '0'

    # Check whether the library exists.
    tracestr = 'notrace'
    workdir  = designcfgs.get_design_worklib_path(design_name, False, curr_coreid)[-1]
    if not os.path.exists(workdir):
        print("Error: Need {} to run this experiment. Design is {}.\n"
              "Please run 'make build_{}_{}_modelsim' to build the the modelsim library.\n"
              "Also be in the milesan dir so the path is right.\n".format(workdir, design_name, 'vanilla', tracestr, milesandir))
        sys.exit(1)
    cmdline=['make', '-C', milesandir, f"rerun_vanilla_{tracestr}_modelsim"]

    # We expect the simulation to take at most 4*simlen + 20 seconds.
    exec_out = subprocess.run(cmdline, cwd=workdir, check=True, text=True, capture_output=True, env=my_env, timeout=min(4*simlen + 20, 1800))

    outlines = exec_out.stdout.split('\n')
    outlines = list(map(lambda l: l[2:], filter(lambda l: 'Writing ELF word to SRAM addr' not in l, outlines))) # Remove the initial `# ` from Modelsim

    # Check stop success
    is_stop_successful = 'Found a stop request.' in exec_out.stdout
    if not is_stop_successful:
        # print('Stop not successful in runsim_modelsim', exec_out.stdout)
        return False, None

    if num_int_regs == 0 and num_float_regs == 0:
        return True, None

    # Retrieve the register values
    ret_intregs = []
    ret_floatregs = []
    curr_index = 0
    for reg_id in range(1, num_int_regs+1):
        for row_id in itertools.count(curr_index):
            if len(outlines[row_id]) >= 19 and outlines[row_id][:19] == f"Dump of reg x{reg_id:02}: 0x" or outlines[row_id][:19] == f"Dump of reg x{reg_id: 2}: 0x":
                ret_intregs.append(int(outlines[row_id][19:35], 16))
                curr_index = row_id + 1
                break

    if designcfgs.design_has_float_support(design_name):
        for fp_reg_id in range(num_float_regs):
            # print('Curr index', curr_index)
            # print('fp_reg_id', fp_reg_id)
            for row_id in itertools.count(curr_index):
                # print('Candidate:', outlines[row_id])
                if row_id >= len(outlines):
                    # This happens if the FPU is disabled in the final block and the final permission level does not permit enabling it.
                    ret_floatregs.append(None)
                    curr_index = row_id + 1
                    break
                if len(outlines[row_id]) >= 19 and outlines[row_id][:19] == f"Dump of reg f{fp_reg_id:02}: 0x" or outlines[row_id][:19] == f"Dump of reg f{fp_reg_id: 2}: 0x":
                    # print('Floating outline found:', outlines[row_id])
                    ret_floatregs.append(int(outlines[row_id][19:35], 16))
                    curr_index = row_id + 1
                    break
    return True, (ret_intregs, ret_floatregs)

# Runs the test and checks for matching.
# @param expected_regvals a pair of iterables of expected int regvals, and float regvals.
# @param override_num_instrs if not None, then use this value instead of the number of instructions in fuzzerstate.instr_objs_seq. Used when pruning to shorten a bit the timeout.
# @return (is_success: bool, msg: str)
def runtest_simulator(fuzzerstate, elfpath: str, expected_regvals: tuple, override_num_instrs: int = None):
    from drfuzz_mem.check_isa_sim_taint import check_isa_sim_taint, FuzzerStateException
    try:
        check_isa_sim_taint(fuzzerstate.design_name, fuzzerstate.randseed, False, fuzzerstate)
    except FuzzerStateException as e:
        print(e)
        return False, e
    return True, "No taint or value mismatch detected."

    expected_intregvals, expected_floatregvals = expected_regvals
    del expected_regvals

    if DO_ASSERT:
        assert len(expected_intregvals) >= fuzzerstate.num_pickable_regs-1
        if fuzzerstate.design_has_fpu:
            assert len(expected_floatregvals) == fuzzerstate.num_pickable_floating_regs

    num_instrs = override_num_instrs if override_num_instrs is not None else len(list(itertools.chain.from_iterable(fuzzerstate.instr_objs_seq)))
    if simulator == SimulatorEnum.VERILATOR:
        is_stop_successful, received_regvals = runsim_verilator(fuzzerstate.design_name, num_instrs*MAX_CYCLES_PER_INSTR + SETUP_CYCLES, elfpath, fuzzerstate.num_pickable_regs-1, fuzzerstate.num_pickable_floating_regs)
    elif simulator == SimulatorEnum.MODELSIM:
        is_stop_successful, received_regvals = runsim_modelsim(fuzzerstate.design_name, num_instrs*MAX_CYCLES_PER_INSTR + SETUP_CYCLES, elfpath, fuzzerstate.num_pickable_regs-1, fuzzerstate.num_pickable_floating_regs)
    else:
        raise NotImplementedError(f"Unknown simulator {simulator}")

    # Check successful stop
    if not is_stop_successful:
        return False, f"Timeout for params: memsize: `{fuzzerstate.memsize}`, design_name: `{fuzzerstate.design_name}`, nmax_bbs: `{fuzzerstate.nmax_bbs}`, randseed: `{fuzzerstate.randseed}` -- ({fuzzerstate.memsize}, design_name, {fuzzerstate.randseed}, {fuzzerstate.nmax_bbs})"

    # Check that we retrieved the regs correctly
    if received_regvals is None:
        raise Exception(f"Missing all regs for params: memsize: `{fuzzerstate.memsize}`, design_name: `{fuzzerstate.design_name}`, nmax_bbs: `{fuzzerstate.nmax_bbs}`, randseed: `{fuzzerstate.randseed}`")

    received_intregvals, received_floatregvals = received_regvals
    del received_regvals

    if DO_ASSERT:
        assert len(received_intregvals) >= fuzzerstate.num_pickable_regs-1
        if fuzzerstate.design_has_fpu:
            assert len(received_floatregvals) == fuzzerstate.num_pickable_floating_regs, f"Wanted {fuzzerstate.num_pickable_floating_regs} floating regs. Got {len(received_floatregvals)}."

    # Compare the expected vs. received registers
    reg_mismatch = False
    ret_str_list_regmismatch = []
    for reg_id in range(fuzzerstate.num_pickable_regs-1):
        if expected_intregvals[reg_id] != received_intregvals[reg_id] and fuzzerstate.intregpickstate.get_regstate(reg_id+1) in (IntRegIndivState.FREE, IntRegIndivState.CONSUMED):
            reg_mismatch = True
            ret_str_list_regmismatch.append(f"Register mismatch (x{reg_id+1}) for params: memsize: `{fuzzerstate.memsize}`, design_name: `{fuzzerstate.design_name}`, nmax_bbs: `{fuzzerstate.nmax_bbs}`, randseed: `{fuzzerstate.randseed}`. State: {fuzzerstate.intregpickstate.get_regstate(reg_id+1)}. Expected `{hex(expected_intregvals[reg_id])}`, got `{hex(received_intregvals[reg_id])}`.")

    if fuzzerstate.design_has_fpu:
        for fp_reg_id in range(fuzzerstate.num_pickable_floating_regs):
            # received_floatregvals[fp_reg_id] can be None if the FPU is disabled in the final block and the final permission level does not permit enabling it.
            if expected_floatregvals[fp_reg_id] != received_floatregvals[fp_reg_id] and received_floatregvals[fp_reg_id] is not None:
                reg_mismatch = True
                ret_str_list_regmismatch.append(f"Register mismatch (f{fp_reg_id}) for params: memsize: `{fuzzerstate.memsize}`, design_name: `{fuzzerstate.design_name}`, nmax_bbs: `{fuzzerstate.nmax_bbs}`, randseed: `{fuzzerstate.randseed}`. Expected `{hex(expected_floatregvals[fp_reg_id])}`, got `{hex(received_floatregvals[fp_reg_id])}`.")
    return not reg_mismatch, '\n  '.join(ret_str_list_regmismatch)


# Runs the test in the goal of collecting coverage.
# Returns nothing
def runtest_modelsim(fuzzerstate, elfpath: str, coveragepath: str):
    num_instrs = len(list(itertools.chain.from_iterable(fuzzerstate.instr_objs_seq)))
    is_stop_successful, _ = runsim_modelsim(fuzzerstate.design_name, num_instrs*MAX_CYCLES_PER_INSTR + SETUP_CYCLES, elfpath, 1, 0, coveragepath)
    # Check successful stop
    if not is_stop_successful:
        raise Exception(f"Timeout during modelsim testing of design `{fuzzerstate.design_name}` for tuple ({fuzzerstate.memsize}, design_name, {fuzzerstate.randseed}, {fuzzerstate.nmax_bbs}).")

# Runs the test and checks for a single dumped register.
# @return the value of the dumped register
def runtest_verilator_forprofiling(fuzzerstate, elfpath: str, expected_fuzzerstate_len_fordebug: int):
    if DO_ASSERT:
        assert len(fuzzerstate.instr_objs_seq) == expected_fuzzerstate_len_fordebug, f"Unexpected length of fuzzerstate: {len(fuzzerstate.instr_objs_seq)}"
    is_stop_successful, received_regvals = runsim_verilator(fuzzerstate.design_name, len(fuzzerstate.instr_objs_seq[0])*MAX_CYCLES_PER_INSTR + SETUP_CYCLES, elfpath, 1, 0)
    if not NO_REMOVE_TMPFILES:
        fuzzerstate.remove_tmp_dir()
    # Check successful stop
    if not is_stop_successful:
        raise Exception(f"Timeout during profiling of design `{fuzzerstate.design_name}`.")
    # Check that we retrieved the regs correctly
    if received_regvals is None:
        raise Exception(f"Missing all regs for params: memsize: `{fuzzerstate.memsize}`, design_name: `{fuzzerstate.design_name}`, nmax_bbs: `{fuzzerstate.nmax_bbs}`, randseed: `{fuzzerstate.randseed}`")
    received_intregvals, received_floatregvals = received_regvals
    del received_regvals
    if DO_ASSERT:
        assert len(received_intregvals) == 1
        assert len(received_floatregvals) == 0
    return received_intregvals[0]

# Runs the test in the goal of collecting RFUZZ coverage.
# Returns the Verilator coverage mask
def runtest_verilator_forrfuzz(fuzzerstate, elfpath: str):
    num_instrs = len(list(itertools.chain.from_iterable(fuzzerstate.instr_objs_seq)))
    is_stop_successful, rfuzz_coverage_mask = runsim_verilator(fuzzerstate.design_name, num_instrs*MAX_CYCLES_PER_INSTR + SETUP_CYCLES, elfpath, 1, 0, get_rfuzz_coverage_mask=True)
    # Check successful stop
    if not is_stop_successful:
        raise Exception(f"Timeout during rfuzz coverage testing of design `{fuzzerstate.design_name}` for tuple ({fuzzerstate.memsize}, design_name, {fuzzerstate.randseed}, {fuzzerstate.nmax_bbs}).")
    return rfuzz_coverage_mask

# Runs the test in the goal of collecting modelsim coverage.
# Returns nothing
def runtest_modelsim_forcoverage(fuzzerstate, elfpath: str, coveragepath: str):
    num_instrs = len(list(itertools.chain.from_iterable(fuzzerstate.instr_objs_seq)))
    is_stop_successful, _ = runsim_modelsim(fuzzerstate.design_name, num_instrs*MAX_CYCLES_PER_INSTR + SETUP_CYCLES, elfpath, 1, 0, coveragepath)
    # Check successful stop
    if not is_stop_successful:
        raise Exception(f"Timeout during modelsim testing of design `{fuzzerstate.design_name}` for tuple ({fuzzerstate.memsize}, design_name, {fuzzerstate.randseed}, {fuzzerstate.nmax_bbs}).")


def run_rtl_and_load_regstream(fuzzerstate):
    design_name = fuzzerstate.design_name
    if fuzzerstate.simulator == SimulatorEnum.MODELSIM:
        return wait_and_load_regstream(fuzzerstate)
    
    assert not COV_EN, f"Coverage only in modelsim right now."
    cmd = ["make",f"rerun_{'drfuzz_mem' if not USE_VANILLA else 'vanilla'}_{'notrace' if not TRACE_EN else 'trace' if not TRACE_FST else 'trace_fst'}"]
    milesandir = designcfgs.get_design_milesan_path(design_name)
    env = os.environ
    env.update(fuzzerstate.env)
    subprocess.run(cmd,cwd=milesandir,env=env,capture_output=True,check=True)

    assert "REGDUMP_PATH" in env
    with open(env["REGDUMP_PATH"], "rb") as f:
        regdumps_rtl = json.load(f)
    
    if not USE_VANILLA:
        assert "REGSTREAM_PATH" in env
        with open(env["REGSTREAM_PATH"], "rb") as f:
            regstream_rtl = json.load(f)
    
    regdump_rtl_val_t0 = {int(r["id"][1:]): int(clean_xX(r["value_t0"]),16) for r in regdumps_rtl}
    regdump_rtl_val = {int(r["id"][1:]): int(r["value"],16) for r in regdumps_rtl}

    regstream_rtl_val_t0 = {int(r["id"],16): int(r["value_t0"],16) for r in regstream_rtl}
    regstream_rtl_val = {int(r["id"],16): int(r["value"],16) for r in regstream_rtl}

    sramdump_rtl = {}
    if CHECK_MEM and not USE_VANILLA:
        assert "SRAMDUMP_PATH" in env
        with open(env["SRAMDUMP_PATH"], "r") as f:
            for line in f.read().split("\n"):
                if "{" not in line:
                    continue
                d = json.loads(line)
                addr = int(d["addr"],16) + SPIKE_STARTADDR
                sramdump_rtl[addr] = {}
                sramdump_rtl[addr]["val"] = int(d["value"],16)
                sramdump_rtl[addr]["val_t0"] = int(d["value_t0"],16)
    return (regstream_rtl_val, regstream_rtl_val_t0), (regdump_rtl_val, regdump_rtl_val_t0), sramdump_rtl, None


def clean_xX(r: str):
    return r[:2] + r[2:].replace("x","0").replace("X","0")
    
# Use this when fuzzing with modelsim as we can't start it from the container. Need second script to run natively in parallel and a shared mount.
def wait_and_load_regstream(fuzzerstate, use_vanilla: bool = False):
    req_dict = {key: value.replace(PATH_TO_MNT, PATH_FROM_MODELSIM_TO_MNT) if isinstance(value,str) else value for key,value in fuzzerstate.env.items()}
    req_dict["USE_VANILLA"] = use_vanilla
    req_dict["TRACE_EN"] = TRACE_EN
    req_dict["COV_EN"] = COV_EN
    req_dict["TRACE_FST"] = TRACE_FST

    rtl_name = fuzzerstate.env['SIMSRAMELF'].split('/')[-1].split(".")[0]
    timestring=strftime("%a_%d_%b_%Y_%H:%M:%S", gmtime())
    req_path = f"{MODELSIM_REQ_DIR}/{rtl_name}.{timestring}.modelsim_req.json"
    

    assert "REGDUMP_PATH" in fuzzerstate.env
    regdump_path = fuzzerstate.env["REGDUMP_PATH"]

    assert "PCDUMP_PATH" in fuzzerstate.env
    pcdump_path = fuzzerstate.env["PCDUMP_PATH"]


    # If there's an old register dump from a previous run, delete it. 
    # Otherwise we get aliasing with other simuations, especially Verilator.
    if os.path.exists(regdump_path):
        os.remove(regdump_path)

    if INSERT_REGDUMPS:
        assert "REGSTREAM_PATH" in fuzzerstate.env
        regstream_path = fuzzerstate.env["REGSTREAM_PATH"]
        if os.path.exists(regstream_path):
            os.remove(regstream_path)

    with open(req_path, "w") as f:
        json.dump(req_dict, f)

    os.chmod(MODELSIM_REQ_DIR, 0o777)
    os.chmod(req_path, 0o777)
    os.chmod(fuzzerstate.tmp_dir, 0o777)

    if PRINT_THREAD_STATUS:
        print(f"Dumped request to {req_path}")
    start = time.time()
    while(1):
        time.sleep(2)
        if PRINT_THREAD_STATUS:
            print(f"Waiting for modelsim results at {regdump_path}...")
        if(os.path.exists(regdump_path)):
           break
        if STOP_AT_PC_TAINT:
            if(os.path.exists(pcdump_path)):
               break
    
    if PRINT_THREAD_STATUS:
        print(f"Modelsim results are ready. Loading...")

    while(1):
        try:
            if STOP_AT_PC_TAINT:
                with open(pcdump_path, "r") as f:
                    pcdump = int(f.read(),16)
                    if pcdump:
                        return (None, None), (None, None), None, pcdump
                    
            with open(regdump_path, "rb") as f:
                regdumps_rtl = json.load(f)
                if PRINT_THREAD_STATUS:
                    print(f"Modelsim results loaded succesfully from {regdump_path}.")
                break
        except Exception as e:
            if isinstance(e, ValueError) or isinstance(e, json.decoder.JSONDecodeError):
                time.sleep(1)
            else:
                raise e

    if len(regdumps_rtl) == 1 and "timeout" in regdumps_rtl[0]:
        assert False, f"Modelsim instance timed out after {time.time-start}s. ({regdumps_rtl[0]['timeout']}s modelsim runtime)."
    
    regdump_rtl_val_t0 = {int(r["id"][1:]): int(clean_xX(r["value_t0"]),16) for r in regdumps_rtl}
    regdump_rtl_val = {int(r["id"][1:]): int(r["value"],16) for r in regdumps_rtl}

    regstream_rtl_val_t0 = {}
    regstream_rtl_val = {}
    if INSERT_REGDUMPS:
        assert not USE_VANILLA
        assert os.path.exists(regstream_path), f"{regstream_path} does not exist"
        with open(regstream_path, "rb") as f:
            regstream_rtl = json.load(f)
        regstream_rtl_val_t0 = {int(r["id"],16): int(clean_xX(r["value_t0"]),16) for r in regstream_rtl}
        regstream_rtl_val = {int(r["id"],16): int(r["value"],16) for r in regstream_rtl}

    sramdump_rtl = {} # For compatibility with kronos. Not used for other cores.
    return (regstream_rtl_val, regstream_rtl_val_t0), (regdump_rtl_val, regdump_rtl_val_t0), sramdump_rtl, pcdump if STOP_AT_PC_TAINT else None