
from cascade.fuzzerstate import FuzzerState
from params.runparams import DO_ASSERT, NO_REMOVE_TMPFILES, PATH_TO_TMP
from cascade.basicblock import gen_basicblocks
from common.designcfgs import get_design_boot_addr
from cascade.spikeresolution import spike_resolution
from cascade.genelf import gen_elf_from_bbs
from common.profiledesign import profile_get_medeleg_mask
from cascade.util import IntRegIndivState

import random
import os
import re

def recompute_final_elf(memsize, design_name, randseed, nmax_bbs, expected_regvals_path, init_regvals_path, elfpath,authorize_privileges, check_pc_spike_again: bool = False):
    if DO_ASSERT:
        assert nmax_bbs is None or nmax_bbs > 0

    random.seed(randseed)
    fuzzerstate = FuzzerState(get_design_boot_addr(design_name), design_name, memsize, randseed, nmax_bbs, authorize_privileges)
    gen_basicblocks(fuzzerstate, load_initial_regvals=True,init_regvals_path=init_regvals_path)

    expected_regvals, interm_elfpath = spike_resolution(fuzzerstate, check_pc_spike_again)
    
    # This is typically quite short
    iregs, fregs = expected_regvals

    with open(expected_regvals_path, 'w') as f:
        f.write("{\n")
        for reg_id in range(fuzzerstate.num_pickable_regs-1):
             # The transient registers are not expected to match.
            if not fuzzerstate.intregpickstate.get_regstate(reg_id+1) in (IntRegIndivState.FREE, IntRegIndivState.CONSUMED): continue
            f.write(f"\"i{reg_id+1}\":\"0x{iregs[reg_id]:x}\"") # starts with 1
            # print(f"\"i{reg_id+1}\":\"0x{iregs[reg_id]:x}\"")
            if reg_id != fuzzerstate.num_pickable_regs - 2:
                f.write(",\n")
        if fuzzerstate.num_pickable_floating_regs > 0: f.write(",\n")
        for reg_id in range(fuzzerstate.num_pickable_floating_regs):
            f.write(f"\"f{reg_id}\":\"0x{fregs[reg_id]:x}\"") # starts with 0
            # print(f"\"f{reg_id}\":\"0x{fregs[reg_id]:x}\"")
            if reg_id != fuzzerstate.num_pickable_floating_regs-1:
                f.write(",\n")
        f.write("\n}")
    gen_elf_from_bbs(fuzzerstate, False, 'rtl', fuzzerstate.instance_to_str(), fuzzerstate.design_base_addr,rtl_elfpath=elfpath)
    return fuzzerstate, elfpath, interm_elfpath, expected_regvals

def recompute_from_existing_elf(elfpath: str = "", expected_regvals_path: str = "",  init_regvals_path: str = ""):
    id = elfpath.split("/")[-1].split(".")[0]
    # print(f"Recomputing for id {id} at {elfpath}")
    id_splits = id.split("_")
    memsize = int(re.findall("[0-9]+",id_splits[0])[0])
    design_name = id_splits[1]
    randseed = int(id_splits[2])
    nmax_bbs = int(id_splits[3])


    # tolerate_bug_for_eval_reduction(design_name)
    # calibrate_spikespeed()
    profile_get_medeleg_mask(design_name)
    return recompute_final_elf(memsize,design_name,randseed,nmax_bbs,expected_regvals_path,init_regvals_path,elfpath,True,False)

