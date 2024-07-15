import sys
sys.path.append("../")

from drfuzz_mem.check_isa_sim_worker import check_isa_sims
from drfuzz_mem.check_isa_sim_taint import FailTypeEnum
from workers.reduce_worker import reduce_programs
from common.spike import calibrate_spikespeed
from params.runparams import NO_REMOVE_TMPDIRS, NO_REMOVE_TMPFILES
from common.profiledesign import profile_get_medeleg_mask, profile_get_asid_mask

import os
import json

def load_fuzzconfigs(path: str):
    with open(path, "r") as f:
        cfgs = json.load(f)
    return cfgs

if __name__ == '__main__':
    if "CASCADE_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")
    
    if len(sys.argv) < 1:
        raise Exception("Usage: python3 fuzzall.py <path_to_config_json>")


    if len(sys.argv) > 1:
        cfgs_path = sys.argv[1]
    
    cfgs = load_fuzzconfigs(cfgs_path)


    assert not NO_REMOVE_TMPDIRS
    assert not NO_REMOVE_TMPFILES

    calibrate_spikespeed()
    for cfg in cfgs:
        # set_cfg(cfg)
        for design_name in cfg["duts"]:

    
else:
    raise Exception("This module must be at the toplevel.")

