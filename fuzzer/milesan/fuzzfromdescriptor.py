# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script executes the fuzzer to find faulting programs.

from common.timeout import timeout
from common.designcfgs import get_design_boot_addr
from params.runparams import DO_ASSERT, NO_REMOVE_TMPFILES
from params.fuzzparams import LOG2_MEMSIZE_LOWERBOUND, LOG2_MEMSIZE_UPPERBOUND, NUM_MIN_BBS_LOWERBOUND, NUM_MAX_BBS_UPPERBOUND, NUM_BBS
from params.fuzzparams import PROBA_AUTHORIZE_PRIVILEGES, TAINT_EN
from milesan.basicblock import gen_basicblocks
from milesan.fuzzsim import SimulatorEnum, runtest_simulator
from milesan.genelf import gen_elf_from_bbs
from milesan.spikeresolution import spike_resolution
import numpy as np
import os
import random
import time
import subprocess



# Creates a new program descriptor.
def gen_new_test_instance(design_name: str, randseed: int, can_authorize_privileges: bool):
    random.seed(randseed)
    np.random.seed(randseed)
    n_bbs = random.randrange(NUM_MIN_BBS_LOWERBOUND, NUM_MAX_BBS_UPPERBOUND) if NUM_BBS == 0 else NUM_BBS
    return random.randrange(1 << LOG2_MEMSIZE_LOWERBOUND, 1 << LOG2_MEMSIZE_UPPERBOUND), design_name, randseed, n_bbs, can_authorize_privileges and random.random() < PROBA_AUTHORIZE_PRIVILEGES

# The main function for a single fuzzer run. It creates a new fuzzer state, populates it with basic blocks, and then runs the spike resolution. It does not run the RTL simulation.
# @return (fuzzerstate, rtl_elfpath, expected_regvals: list) where expected_regval is a list of num_pickable_regs-1 expected reg values (we ignore x0)
def gen_fuzzerstate_elf_expectedvals(memsize: int, design_name: str, randseed: int, nmax_bbs: int, authorize_privileges: bool, check_pc_spike_again: bool):
    from milesan.fuzzerstate import FuzzerState
    if DO_ASSERT:
        assert nmax_bbs is None or nmax_bbs > 0

    start = time.time()
    random.seed(randseed)
    fuzzerstate = FuzzerState(get_design_boot_addr(design_name), design_name, memsize, randseed, nmax_bbs, authorize_privileges)
    gen_basicblocks(fuzzerstate)
    time_seconds_spent_in_gen_bbs = time.time() - start

    # spike resolution
    start = time.time()
    expected_regvals, interm_elfpath = spike_resolution(fuzzerstate, check_pc_spike_again, return_interm = True)
    fuzzerstate.expected_regvals = expected_regvals
    fuzzerstate.interm_elfpath = interm_elfpath
    time_seconds_spent_in_spike_resol = time.time() - start

    start = time.time()
    # This is typically quite short
    rtl_elfpath = gen_elf_from_bbs(fuzzerstate, False, 'rtl', fuzzerstate.instance_to_str(), fuzzerstate.design_base_addr)
    fuzzerstate.rtl_elfpath = rtl_elfpath
    time_seconds_spent_in_gen_elf = time.time() - start
    return fuzzerstate, rtl_elfpath, interm_elfpath, expected_regvals, time_seconds_spent_in_gen_bbs, time_seconds_spent_in_spike_resol, time_seconds_spent_in_gen_elf


def gen_fuzzerstate_elf_flipped_bits(fuzzerstate):
    # spike resolution
    expected_regvals, intem_elfpath = spike_resolution(fuzzerstate, True, return_interm=True)
    rtl_elfpath = gen_elf_from_bbs(fuzzerstate, False, 'rtl', fuzzerstate.instance_to_str(), fuzzerstate.design_base_addr)
    return rtl_elfpath, expected_regvals


def gen_fuzzerstate_elf_expectedvals_interm(memsize: int, design_name: str, randseed: int, nmax_bbs: int, authorize_privileges: bool, check_pc_spike_again: bool, en_taint: bool = TAINT_EN):
    from milesan.fuzzerstate import FuzzerState
    if DO_ASSERT:
        assert nmax_bbs is None or nmax_bbs > 0

    start = time.time()
    random.seed(randseed)
    fuzzerstate = FuzzerState(get_design_boot_addr(design_name), design_name, memsize, randseed, nmax_bbs, authorize_privileges, en_taint)
    gen_basicblocks(fuzzerstate)
    time_seconds_spent_in_gen_bbs = time.time() - start

    # spike resolution
    start = time.time()
    expected_regvals, interm_elfpath = spike_resolution(fuzzerstate, check_pc_spike_again, return_interm=True)
    time_seconds_spent_in_gen_elf = time.time() - start
    
    return fuzzerstate, interm_elfpath, expected_regvals

###
# Exposed function
###

def run_rtl(memsize: int, design_name: str, randseed: int, nmax_bbs: int, authorize_privileges: bool, check_pc_spike_again: bool, simulator=SimulatorEnum.VERILATOR):
    fuzzerstate, rtl_elfpath, finalregvals_spikeresol, time_seconds_spent_in_gen_bbs, time_seconds_spent_in_spike_resol, time_seconds_spent_in_gen_elf = gen_fuzzerstate_elf_expectedvals(memsize, design_name, randseed, nmax_bbs, authorize_privileges, check_pc_spike_again)

    start = time.time()
    is_success, rtl_msg = runtest_simulator(fuzzerstate, rtl_elfpath, finalregvals_spikeresol, simulator=simulator)
    time_seconds_spent_in_rtl_sim = time.time() - start

    # For debugging, potentially expose the ELF files
    if NO_REMOVE_TMPFILES:
        print('rtl elfpath', rtl_elfpath)
    if not NO_REMOVE_TMPFILES:
        os.remove(rtl_elfpath)
        del rtl_elfpath

    if not is_success:
        raise Exception(rtl_msg)
    return time_seconds_spent_in_gen_bbs, time_seconds_spent_in_spike_resol, time_seconds_spent_in_gen_elf, time_seconds_spent_in_rtl_sim

###
# Some tests
###

# This function runs a single test run from a test descriptor (memsize, design_name, randseed, nmax_bbs) and returns the gathered times (used for the performance evaluation plot).
# Loggers are not yet very tested facilities.
@timeout(seconds=60*60*2)
def fuzz_single_from_descriptor(memsize: int, design_name: str, randseed: int, nmax_bbs: int, authorize_privileges: bool, loggers: list = None, check_pc_spike_again: bool = False, start_time: float = None):
    try:
        gathered_times = run_rtl(memsize, design_name, randseed, nmax_bbs, authorize_privileges, check_pc_spike_again)
        if loggers is not None:
            loggers[random.randrange(len(loggers))].log(True, {'memsize': memsize, 'design_name': design_name, 'randseed': randseed, 'nmax_bbs': nmax_bbs}, False, '') # No message for successful runs
        else:
            return gathered_times
    except Exception as e:
        if loggers is not None:
            emsg = str(e)
            if 'Spike timeout' in emsg:
                loggers[random.randrange(len(loggers))].log(False, {'memsize': memsize, 'design_name': design_name, 'randseed': randseed, 'nmax_bbs': nmax_bbs}, True, '') # No message for Spike timeouts
            else:
                loggers[random.randrange(len(loggers))].log(False, {'memsize': memsize, 'design_name': design_name, 'randseed': randseed, 'nmax_bbs': nmax_bbs}, False, emsg)
        else:
            print(f"Failed test_run_rtl_single for params memsize: `{memsize}`, design_name: `{design_name}`, check_pc_spike_again: `{check_pc_spike_again}`, randseed: `{randseed}`, nmax_bbs: `{nmax_bbs}` -- ({memsize}, design_name, {randseed}, {nmax_bbs})\n{e}")
        return 0, 0, 0, 0

