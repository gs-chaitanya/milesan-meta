# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This module defines the final block.

from params.runparams import DO_ASSERT, DEBUG_PRINT
from params.fuzzparams import USE_MMU, DUMP_MCYCLES
from rv.csrids import CSR_IDS
from common.designcfgs import is_design_32bit, get_design_stop_sig_addr, get_design_reg_dump_addr, design_has_float_support, get_design_fpreg_dump_addr
from params.fuzzparams import RDEP_MASK_REGISTER_ID, MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_FLOATING_REGS, FPU_ENDIS_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, RPROD_MASK_REGISTER_ID
from milesan.privilegestate import PrivilegeStateEnum
from rv.asmutil import li_into_reg
from milesan.cfinstructionclasses import ImmRdInstruction, RegImmInstruction, IntStoreInstruction, FloatStoreInstruction, JALInstruction, SpecialInstruction, CSRRegInstruction, R12DInstruction, CSRImmInstruction

def get_finalblock_max_size():
    return (10 + 2*MAX_NUM_PICKABLE_REGS + 2*MAX_NUM_PICKABLE_FLOATING_REGS - 1) * 4 + 10*4 

# We must instantiate it in the end because we must know whether we have the privileges to turn on the FPU.
# Returns the instruction objects of the tail basic block
def finalblock(fuzzerstate, design_name: str):
    try:
        stopsig_addr = get_design_stop_sig_addr(design_name)
    except:
        raise ValueError(f"Design `{design_name}` does not have the `stopsigaddr` attribute.")
    try:
        regdump_addr = get_design_reg_dump_addr(design_name)
    except:
        raise ValueError(f"Design `{design_name}` does not have the `regdumpaddr` attribute.")

    if DO_ASSERT:
        assert regdump_addr < 0x80000000, f"For the destination address `{hex(regdump_addr)}`, we will need to manage sign extension, which is not yet implemented here."
        assert stopsig_addr < 0x80000000, f"For the destination address `{hex(stopsig_addr)}`, we will need to manage sign extension, which is not yet implemented here."

    if DEBUG_PRINT: print(f"in final block, layout: {fuzzerstate.effective_curr_layout}, priv: ", fuzzerstate.privilegestate.privstate)
        # assert fuzzerstate.effective_curr_layout == fuzzerstate.instr_objs_seq[-1][-1].va_layout_after_op, f"Effective layout does not match layout after op after final instruction before final block: {fuzzerstate.effective_curr_layout} != {fuzzerstate.instr_objs_seq[-1][-1].va_layout_after_op}, {fuzzerstate.instr_objs_seq[-1][-1].get_str()}"

    ret = []
    design_has_fpu = design_has_float_support(design_name)
    design_has_fpud = design_has_float_support(design_name)

    ##
    # Handle virtual layouts
    ##

    # Set the U bit to the corresponding value
    sum_bit, mprv_bit = fuzzerstate.status_sum_mprv
    if (fuzzerstate.effective_curr_layout != -1 or (fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE and mprv_bit and (fuzzerstate.privilegestate.curr_mstatus_mpp != PrivilegeStateEnum.MACHINE))):
        
        pte_content = fuzzerstate.pagetablestate.all_pt_entries
        # Set the U bit to the corresponding value
        if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.USER or (fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE and mprv_bit and fuzzerstate.privilegestate.curr_mstatus_mpp == PrivilegeStateEnum.USER):
            for layout_id, va_layout in enumerate(pte_content):
                if fuzzerstate.pagetablestate.entangled_layouts[layout_id] != None: continue
                last_elem = len(va_layout[-1])-1
                va_layout[-1][last_elem-1] |= 0b10000
                va_layout[-1][last_elem] |= 0b10000
        # if the sum bit is on, we can still access supervisor mappings
        if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR or (fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE and mprv_bit and fuzzerstate.privilegestate.curr_mstatus_mpp == PrivilegeStateEnum.SUPERVISOR):
            for layout_id, va_layout in enumerate(pte_content):
                if fuzzerstate.pagetablestate.entangled_layouts[layout_id] != None: continue
                last_elem = len(va_layout[-1])-1
                va_layout[-1][last_elem-1] &= 0xffffffffffffffef
                va_layout[-1][last_elem] &= 0xffffffffffffffef

    if fuzzerstate.effective_curr_layout == -1 and not (fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE and mprv_bit and (fuzzerstate.privilegestate.curr_mstatus_mpp != PrivilegeStateEnum.MACHINE) and fuzzerstate.real_curr_layout != -1):
        lui_imm_regdump, addi_imm_regdump = li_into_reg(regdump_addr)
        
        # We re-purpose MPP_BOTH_ENDIS_REGISTER_ID, because we will not need it anymore.
        # Compute the register dump address
        ret += [
            ImmRdInstruction(fuzzerstate, "lui", MPP_BOTH_ENDIS_REGISTER_ID, lui_imm_regdump, is_rd_nonpickable_ok=True),
            RegImmInstruction(fuzzerstate, "addi", MPP_BOTH_ENDIS_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, addi_imm_regdump, is_rd_nonpickable_ok=True)
        ]
    else:
        if DEBUG_PRINT: print(f"physical regdump addr is: {hex(regdump_addr)}")
        if USE_MMU:
            regdump_addr, _ = fuzzerstate.pagetablestate.finalblock_sig_vaddr[fuzzerstate.real_curr_layout] #FIXME somewhow, this can be a tuple
        if DEBUG_PRINT: print(f"virtual regdump addr is: {hex(regdump_addr)}, sum/mprv: {fuzzerstate.status_sum_mprv} layout: {fuzzerstate.effective_curr_layout} ", fuzzerstate.privilegestate.privstate)
        
        # We re-purpose MPP_BOTH_ENDIS_REGISTER_ID, because we will not need it anymore.
        # Compute the register dump address
        #load the first 32 bits 
        lui_imm_regdump, addi_imm_regdump = li_into_reg(regdump_addr & 0xFFFFFFFF, False)
        ret += [
            ImmRdInstruction(fuzzerstate, "lui", MPP_BOTH_ENDIS_REGISTER_ID, lui_imm_regdump, is_rd_nonpickable_ok=True),
            RegImmInstruction(fuzzerstate, "addi", MPP_BOTH_ENDIS_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, addi_imm_regdump, is_rd_nonpickable_ok=True),
        ]
        if fuzzerstate.is_design_64bit: 
            #load the next 32 bits
            lui_imm_regdump_top, addi_imm_regdump_top = li_into_reg((regdump_addr>>32) & 0xFFFFFFFF, False)
            ret += [
                #clear the top 32 bits
                R12DInstruction(fuzzerstate, "and", MPP_BOTH_ENDIS_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, RDEP_MASK_REGISTER_ID, is_rd_nonpickable_ok=True),
                ImmRdInstruction(fuzzerstate, "lui", RPROD_MASK_REGISTER_ID, lui_imm_regdump_top, is_rd_nonpickable_ok=True),
                RegImmInstruction(fuzzerstate, "addi", RPROD_MASK_REGISTER_ID, RPROD_MASK_REGISTER_ID, addi_imm_regdump_top, is_rd_nonpickable_ok=True),
                RegImmInstruction(fuzzerstate, "slli", RPROD_MASK_REGISTER_ID, RPROD_MASK_REGISTER_ID, 32, is_rd_nonpickable_ok=True),
                #coalesce the result
                R12DInstruction(fuzzerstate, "or", MPP_BOTH_ENDIS_REGISTER_ID, RPROD_MASK_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, is_rd_nonpickable_ok=True)
            ]



    ###
    # Dump registers
    ###

    # lui_imm_regdump, addi_imm_regdump = li_into_reg(regdump_addr)

    # # We re-purpose RDEP_MASK_REGISTER_ID, because we will not need it anymore.
    # # Compute the register dump address
    # ret += [
    #     ImmRdInstruction(fuzzerstate,"lui", RDEP_MASK_REGISTER_ID, lui_imm_regdump, is_rd_nonpickable_ok=True),
    #     RegImmInstruction(fuzzerstate,"addi", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, addi_imm_regdump, is_rd_nonpickable_ok=True)
    # ]

    # Store the register values to the register dump address
    ret.append(SpecialInstruction(fuzzerstate,"fence")) # Hopefully this prevents speculative execution of the stores
    for reg_id in range(1, MAX_NUM_PICKABLE_REGS):
        ret.append(IntStoreInstruction(fuzzerstate,"sd" if fuzzerstate.is_design_64bit else "sw",  MPP_BOTH_ENDIS_REGISTER_ID, reg_id, 0, -1))
        ret.append(SpecialInstruction(fuzzerstate,"fence"))


    # Get the mcycle value
    if DUMP_MCYCLES:
        assert fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE
        ret += [
            CSRImmInstruction(fuzzerstate,"csrrci", 1, 0, CSR_IDS.MCYCLE),
            IntStoreInstruction(fuzzerstate,"sd" if fuzzerstate.is_design_64bit else "sw",  MPP_BOTH_ENDIS_REGISTER_ID, 1, 0, -1),
            SpecialInstruction(fuzzerstate,"fence")
        ]

    # Store the floating values as well, if FPU is supported and if there is no risk of it being deactivated
    if design_has_fpu and not fuzzerstate.is_fpu_activated:
        # Check that the fpregdump addr is correctly positioned
        if DO_ASSERT:
            assert get_design_fpreg_dump_addr(design_name) == regdump_addr + 8, f"We make the assumption that the FP regdump addr is the int regdump address + 8. However, currently, they are respectively {hex(get_design_fpreg_dump_addr(design_name))} and regdump_addr={hex(regdump_addr)}"
        if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE:
            # Enable the FPU
            ret.append(CSRRegInstruction(fuzzerstate,"csrrs", 0, FPU_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS))
            fuzzerstate.is_fpu_activated = True
        if fuzzerstate.is_fpu_activated:
            for reg_id in range(MAX_NUM_PICKABLE_FLOATING_REGS):
                ret.append(FloatStoreInstruction(fuzzerstate,"fsd" if design_has_fpud else "fsw", MPP_BOTH_ENDIS_REGISTER_ID, reg_id, 8, -1))
                ret.append(SpecialInstruction(fuzzerstate,"fence"))



    ###
    # Stop request
    ###
    if fuzzerstate.effective_curr_layout == -1 and  not (fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE and mprv_bit and (fuzzerstate.privilegestate.curr_mstatus_mpp != PrivilegeStateEnum.MACHINE and fuzzerstate.real_curr_layout != -1)):
        
        lui_imm_stopreq, addi_imm_stopreq = li_into_reg(stopsig_addr)

        # We re-purpose MPP_BOTH_ENDIS_REGISTER_ID, because we will not need it anymore.
        # Compute the stop request address
        ret += [
            ImmRdInstruction(fuzzerstate,"lui", MPP_BOTH_ENDIS_REGISTER_ID, lui_imm_stopreq, is_rd_nonpickable_ok=True),
            RegImmInstruction(fuzzerstate,"addi", MPP_BOTH_ENDIS_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, addi_imm_stopreq, is_rd_nonpickable_ok=True)
        ]
    else:
        if DEBUG_PRINT: print(f"physical stopsig addr is: {hex(stopsig_addr)}")
        if USE_MMU:
            _, stopsig_addr = fuzzerstate.pagetablestate.finalblock_sig_vaddr[fuzzerstate.real_curr_layout]
        if DEBUG_PRINT: print(f"virtual stopsig addr is: {hex(stopsig_addr)}")
        
        # We re-purpose MPP_BOTH_ENDIS_REGISTER_ID, because we will not need it anymore.
        # Compute the register dump address
        #load the first 32 bits 
        lui_imm_stopsig, addi_imm_stopsig = li_into_reg(stopsig_addr & 0xFFFFFFFF, False)
        ret += [
            ImmRdInstruction(fuzzerstate,"lui", MPP_BOTH_ENDIS_REGISTER_ID, lui_imm_stopsig, is_rd_nonpickable_ok=True),
            RegImmInstruction(fuzzerstate,"addi", MPP_BOTH_ENDIS_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, addi_imm_stopsig, is_rd_nonpickable_ok=True),
        ]
        if fuzzerstate.is_design_64bit:
            #load the next 32 bits
            lui_imm_stopsig_top, addi_imm_stopsig_top = li_into_reg((stopsig_addr>>32) & 0xFFFFFFFF, False)
            ret += [
                #clear the top 32 bits
                R12DInstruction(fuzzerstate,"and", MPP_BOTH_ENDIS_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, RDEP_MASK_REGISTER_ID, is_rd_nonpickable_ok=True),
                ImmRdInstruction(fuzzerstate,"lui", RPROD_MASK_REGISTER_ID, lui_imm_stopsig_top, is_rd_nonpickable_ok=True),
                RegImmInstruction(fuzzerstate,"addi", RPROD_MASK_REGISTER_ID, RPROD_MASK_REGISTER_ID, addi_imm_stopsig_top, is_rd_nonpickable_ok=True),
                RegImmInstruction(fuzzerstate,"slli", RPROD_MASK_REGISTER_ID, RPROD_MASK_REGISTER_ID, 32, is_rd_nonpickable_ok=True),
                #coalesce the result
                R12DInstruction(fuzzerstate,"or", MPP_BOTH_ENDIS_REGISTER_ID, RPROD_MASK_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID,is_rd_nonpickable_ok=True)
            ]

    # Store the register values to the register dump address
    ret.append(IntStoreInstruction(fuzzerstate,"sd" if fuzzerstate.is_design_64bit else "sw", MPP_BOTH_ENDIS_REGISTER_ID, 0, 0 & 0xFFFF, -1))
    ret.append(SpecialInstruction(fuzzerstate,"fence"))

    # Infinite loop in the end of the simulation
    ret.append(JALInstruction(fuzzerstate,"jal", 0, 0))

    if DO_ASSERT:
        assert len(ret) * 4 <= get_finalblock_max_size(), f"The final block is larger than expected: {len(ret) * 4} > {get_finalblock_max_size()}"

    return ret


# Spike does not support writing to some signaling addresses, but at the same time, we do not need it for spike resolution anyway. So let's replace it with an infinite loop.
def finalblock_spike_resolution(fuzzerstate):
    # Infinite loop in the end of the simulation
    jal_instr = JALInstruction(fuzzerstate,"jal", 0, 0)
    jal_instr.paddr = fuzzerstate.final_bb_base_addr
    return [jal_instr]
