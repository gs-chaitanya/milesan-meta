import json

from milesan.fuzzfromdescriptor import gen_new_test_instance
from milesan.genelf import gen_elf_from_bbs
from milesan.spikeresolution import spike_resolution_return_interm
from common.spike import calibrate_spikespeed
from common.designcfgs import get_design_boot_addr
from common.profiledesign import profile_get_medeleg_mask
from milesan.fuzzerstate import FuzzerState
from milesan.basicblock import gen_basicblocks


def inject_instrucion_in_elf(q_path):
    with open(q_path, "rb") as f:
        q = json.load(f)
    assert len(q) == 1, "Queue should only have a single entry."
    assert len(q[0]["instructions"]) == 1, "Queue should only have single instruction."
    inject_addr = q[0]["instructions"][0]["addr"]
    inject_bytecode = q[0]["instructions"][0]["bytecode"]
    dut =  q[0]["dut"].lower()
    seed = q[0]["seed"]



    memsize, design_name, randseed, nmax_bbs, authorize_privileges = gen_new_test_instance(dut, seed, True)
    calibrate_spikespeed()
    profile_get_medeleg_mask(design_name)

    fuzzerstate = FuzzerState(get_design_boot_addr(design_name), design_name, memsize, seed, nmax_bbs, authorize_privileges)
    gen_basicblocks(fuzzerstate)

    for bb_id ,(bb_start_addr, bb_instrs) in enumerate(zip(fuzzerstate.bb_start_addr_seq[:-1], fuzzerstate.instr_objs_seq[:-1])): # skip first and last bb
        if bb_id == 0: continue
        for instr_id_in_bb, instr_obj in enumerate(bb_instrs):
            addr = bb_start_addr + 4*instr_id_in_bb
            if addr == inject_addr:
                instr_obj.set_bytecode(inject_bytecode)

    # spike_resolution_elfpath = gen_elf_from_bbs(fuzzerstate, True, 'spikeresol', fuzzerstate.instance_to_str(), SPIKE_STARTADDR)
    (ireg,freg), elfpath = spike_resolution_return_interm(fuzzerstate)
    print(f"Recomputed ELF at: {elfpath}")
    return elfpath