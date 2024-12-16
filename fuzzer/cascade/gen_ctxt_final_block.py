from common.spike import SPIKE_STARTADDR
from milesan.cfinstructionclasses import MstatusWriterInstruction, PrivilegeDescentInstruction, ExceptionInstruction, CSRRegInstruction, SimpleExceptionEncapsulator, JALRInstruction
from milesan.privilegestate import PrivilegeStateEnum
from params.fuzzparams import USE_MMU

# TODO, for performance improvement, we can concat all these functions

# @brief gets the layout and priviledge state of an arbtraryinstruction instruction by backpropagation
def get_last_bb_layout_and_priv(fuzzerstate = None, bb_id = -1, instr_id = -1, is_cfi_replace = False):
    if instr_id == -1: 
        instr_id = len(fuzzerstate.instr_objs_seq[bb_id]) - 1

    # We want to start looking at the instruction before the one we overwrite, if we overwrite an instruction
    if is_cfi_replace:
        instr_id = instr_id - 1
        # If it was the first instr in a block, we go to the previous block
        if instr_id == -1:
            bb_id -= 1
            instr_id = len(fuzzerstate.instr_objs_seq[bb_id]) - 1

    # Just for sanity
    if not USE_MMU or bb_id == 0:
        return -1, PrivilegeStateEnum.MACHINE
    
    # If we end up here, it means we started looking for a specific instruction
    # So we iterate until the last instruction which had layout information
    for curr_instr_id in range(instr_id, -1, -1):  # Iterate over columns in reverse
        bb_instr = fuzzerstate.instr_objs_seq[bb_id][curr_instr_id]
        if isinstance(bb_instr, PrivilegeDescentInstruction) or isinstance(bb_instr, ExceptionInstruction):
            return bb_instr.va_layout_after_op, bb_instr.priv_level_after_op
        if isinstance(bb_instr, CSRRegInstruction):
            is_satp_smode, layout = bb_instr.is_satp_smode
            if is_satp_smode: 
                return layout, PrivilegeStateEnum.SUPERVISOR
        if isinstance(bb_instr, JALRInstruction):
            if bb_instr.to_new_layout:
                return bb_instr.va_layout, bb_instr.priv_level

    for curr_bb_id in range(bb_id - 1, -1, -1):  # Iterate over rows in reverse
        for curr_instr_id in range(len(fuzzerstate.instr_objs_seq[curr_bb_id]) - 1, -1, -1):  # Iterate over columns in reverse
            bb_instr = fuzzerstate.instr_objs_seq[curr_bb_id][curr_instr_id]
            if isinstance(bb_instr, PrivilegeDescentInstruction) or isinstance(bb_instr, ExceptionInstruction):
                return bb_instr.va_layout_after_op, bb_instr.priv_level_after_op
            if isinstance(bb_instr, CSRRegInstruction):
                is_satp_smode, layout = bb_instr.is_satp_smode
                if is_satp_smode:
                    return layout, PrivilegeStateEnum.SUPERVISOR
            if isinstance(bb_instr, JALRInstruction):
                if bb_instr.to_new_layout:
                    return bb_instr.va_layout, bb_instr.priv_level

    return -1, PrivilegeStateEnum.MACHINE

def get_priv_and_layout_after_instruction(bb_instr):
    if isinstance(bb_instr, PrivilegeDescentInstruction) or isinstance(bb_instr, ExceptionInstruction):
        return bb_instr.va_layout_after_op, bb_instr.priv_level_after_op
    if isinstance(bb_instr, CSRRegInstruction):
        is_satp_smode, layout = bb_instr.is_satp_smode
        if is_satp_smode: 
            return layout, PrivilegeStateEnum.SUPERVISOR
    if isinstance(bb_instr, JALRInstruction):
        if bb_instr.to_new_layout:
            return bb_instr.va_layout, bb_instr.priv_level

    return bb_instr.va_layout, bb_instr.priv_level



# @brief gets the last sum and mprv bits, a bit redundant, but its getting really complicated
def get_last_sum_mprv(fuzzerstate = None, bb_id = -1, instr_id = -1):
    for curr_instr_id in range(instr_id, -1, -1):  # Iterate over columns in reverse
        if isinstance(fuzzerstate.instr_objs_seq[bb_id][curr_instr_id], MstatusWriterInstruction):
            return fuzzerstate.instr_objs_seq[bb_id][curr_instr_id].old_sum_mprv
        if isinstance(fuzzerstate.instr_objs_seq[bb_id][curr_instr_id], PrivilegeDescentInstruction):
            if fuzzerstate.instr_objs_seq[bb_id][curr_instr_id].priv_level_after_op != PrivilegeStateEnum.MACHINE: 
                sum_bit, _ = fuzzerstate.status_sum_mprv
                return sum_bit, False
    for curr_bb_id in range(bb_id - 1, -1, -1):  # Iterate over rows in reverse
        for curr_instr_id in range(len(fuzzerstate.instr_objs_seq[curr_bb_id]) - 1, -1, -1):  # Iterate over columns in reverse
            if isinstance(fuzzerstate.instr_objs_seq[curr_bb_id][curr_instr_id], MstatusWriterInstruction):
                return fuzzerstate.instr_objs_seq[curr_bb_id][curr_instr_id].old_sum_mprv
            if isinstance(fuzzerstate.instr_objs_seq[curr_bb_id][curr_instr_id], PrivilegeDescentInstruction):
                if fuzzerstate.instr_objs_seq[curr_bb_id][curr_instr_id].priv_level_after_op != PrivilegeStateEnum.MACHINE: 
                    sum_bit, _ = fuzzerstate.status_sum_mprv
                    return sum_bit, False
    return 0, 0

# @brief gets the last mpp bits, a bit redundant, but its getting really complicated
def get_last_mpp(fuzzerstate = None, bb_id = -1, instr_id = -1):
    for curr_instr_id in range(instr_id, -1, -1):  # Iterate over columns in reverse
        if isinstance(fuzzerstate.instr_objs_seq[bb_id][curr_instr_id], CSRRegInstruction) and fuzzerstate.instr_objs_seq[bb_id][curr_instr_id].mpp_val != None :
            return fuzzerstate.instr_objs_seq[bb_id][curr_instr_id].mpp_val
        if isinstance(fuzzerstate.instr_objs_seq[bb_id][curr_instr_id], ExceptionInstruction):
            return fuzzerstate.instr_objs_seq[bb_id][curr_instr_id].priv_level
        if isinstance(fuzzerstate.instr_objs_seq[bb_id][curr_instr_id], PrivilegeDescentInstruction) and fuzzerstate.instr_objs_seq[bb_id][curr_instr_id].is_mret:
            return PrivilegeStateEnum.USER
        
    for curr_bb_id in range(bb_id - 1, -1, -1):  # Iterate over rows in reverse
        for curr_instr_id in range(len(fuzzerstate.instr_objs_seq[curr_bb_id]) - 1, -1, -1):  # Iterate over columns in reverse
            if isinstance(fuzzerstate.instr_objs_seq[curr_bb_id][curr_instr_id], CSRRegInstruction) and fuzzerstate.instr_objs_seq[curr_bb_id][curr_instr_id].mpp_val != None :
                return fuzzerstate.instr_objs_seq[curr_bb_id][curr_instr_id].mpp_val
            if isinstance(fuzzerstate.instr_objs_seq[curr_bb_id][curr_instr_id], ExceptionInstruction):
                return fuzzerstate.instr_objs_seq[curr_bb_id][curr_instr_id].priv_level
            if isinstance(fuzzerstate.instr_objs_seq[curr_bb_id][curr_instr_id], PrivilegeDescentInstruction) and fuzzerstate.instr_objs_seq[curr_bb_id][curr_instr_id].is_mret:
                return PrivilegeStateEnum.USER
            
    return PrivilegeStateEnum.SUPERVISOR

##
# If we change layout in machine mode, to a layout with the same base page, we do not use any trackable instructions, so the 
# real layout might be wrong. This is not a problem, as the only reason we need this layout, is the final block, so as long as
# the base page is correct, we are fine
##

# @brief gets the last real layout from a csr op, a bit redundant, but its getting really complicated
def get_last_real_layout(fuzzerstate = None, bb_id = -1, instr_id = -1):
    for curr_instr_id in range(instr_id, -1, -1):  # Iterate over columns in reverse
        if isinstance(fuzzerstate.instr_objs_seq[bb_id][curr_instr_id], CSRRegInstruction):
            _, layout = fuzzerstate.instr_objs_seq[bb_id][curr_instr_id].is_satp_smode
            if layout is not None:
                return layout
        if isinstance(fuzzerstate.instr_objs_seq[bb_id][curr_instr_id], SimpleExceptionEncapsulator) and isinstance(fuzzerstate.instr_objs_seq[bb_id][curr_instr_id].instr, CSRRegInstruction):
            _, layout = fuzzerstate.instr_objs_seq[bb_id][curr_instr_id].instr.is_satp_smode
            if layout is not None:
                return layout
        if isinstance(fuzzerstate.instr_objs_seq[bb_id][curr_instr_id], JALRInstruction):
            if fuzzerstate.instr_objs_seq[bb_id][curr_instr_id].to_new_layout:
                return fuzzerstate.instr_objs_seq[bb_id][curr_instr_id].va_layout
    for curr_bb_id in range(bb_id - 1, -1, -1):  # Iterate over rows in reverse
        for curr_instr_id in range(len(fuzzerstate.instr_objs_seq[curr_bb_id]) - 1, -1, -1):  # Iterate over columns in reverse
            if isinstance(fuzzerstate.instr_objs_seq[curr_bb_id][curr_instr_id], CSRRegInstruction):
                _, layout = fuzzerstate.instr_objs_seq[curr_bb_id][curr_instr_id].is_satp_smode
                if layout is not None:
                    return layout
            if isinstance(fuzzerstate.instr_objs_seq[curr_bb_id][curr_instr_id], SimpleExceptionEncapsulator) and isinstance(fuzzerstate.instr_objs_seq[curr_bb_id][curr_instr_id].instr, CSRRegInstruction):
                _, layout = fuzzerstate.instr_objs_seq[curr_bb_id][curr_instr_id].instr.is_satp_smode
                if layout is not None:
                    return layout
            if isinstance(fuzzerstate.instr_objs_seq[curr_bb_id][curr_instr_id], JALRInstruction):
                if fuzzerstate.instr_objs_seq[curr_bb_id][curr_instr_id].to_new_layout:
                    return fuzzerstate.instr_objs_seq[curr_bb_id][curr_instr_id].va_layout
                
    return -1