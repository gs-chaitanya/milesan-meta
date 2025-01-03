from milesan.privilegestate import PrivilegeStateEnum
from milesan.cfinstructionclasses_t0 import R12DInstruction_t0, CSRRegInstruction_t0, ImmRdInstruction_t0, RegImmInstruction_t0, TvecWriterInstruction_t0, SpecialInstruction_t0, JALRInstruction_t0
from params.fuzzparams import RPROD_MASK_REGISTER_ID, MAX_NUM_INSTR_IN_LAYOUT, MIN_NUM_INSTR_IN_LAYOUT, PROBA_NEW_SATP_NOT_USED, PROBA_NEW_SATP_XEPC_POP, PROBA_NEW_SATP_STVEC_POP, RDEP_MASK_REGISTER_ID
from params.runparams import DEBUG_PRINT, GET_DATA
from common.spike import SPIKE_STARTADDR
from milesan.mmu_utils import li_doubleword, MODES_PARAM_RV32, MODES_PARAMS_RV64, PAGE_ALIGNMENT_MASK, PAGE_ALIGNMENT_SHIFT
from rv.csrids import CSR_IDS
from rv.asmutil import li_into_reg
import random
from milesan.randomize.pickcleartaintops import clear_taints_with_random_instructions
from milesan.util import BASIC_BLOCK_MIN_SPACE, MmuState, IntRegIndivState, ExceptionCauseVal
#DEBUG_PRINT = True

# @brief checks if we can currently do an MMU operation
def is_mmu_op_not_possible(fuzzerstate, curr_alloc_cursor):
    # Check the basic conditions
    if fuzzerstate.design_has_no_mmu: 
        return True
    elif fuzzerstate.memview.get_available_contig_space(curr_alloc_cursor)-(10*4) < BASIC_BLOCK_MIN_SPACE: 
        return True
    elif fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.USER: 
        return True
    elif fuzzerstate.num_instr_to_stay_in_layout > 0:
            return True
    elif fuzzerstate.satp_set_not_used and random.random() > PROBA_NEW_SATP_NOT_USED: # With a low probability, we chnage satp even if it is unused, also, it might be used by mprv
        return True
    elif (fuzzerstate.privilegestate.is_sepc_populated or fuzzerstate.privilegestate.is_mepc_populated) and (random.random() > PROBA_NEW_SATP_XEPC_POP and fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE): # With a tiny proba, we allow it and invalidate both
        return True
    elif fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.CONSUMED):
        return True
    elif fuzzerstate.privilegestate.is_stvec_populated and (random.random() > PROBA_NEW_SATP_STVEC_POP and fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR): # If produced, needs to be in the same layout when consumed, mtvec will always be bare anyways
        return True
    elif fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR:
        ##
        # In S mode:
        # - going to bare is an exception, independant from the deleguation bit
        # - We allow a new SATP only if we can go to another layout by deleguation, otherwise it is an exception
        # - TODO with a low probability, allow a new satp even if we will trap
        # 
        # The final behaviour we are going for, is, go to another layout if we can deleg. Going to bare
        # is always an exception. With a low proba, write to SATP with a layout we can deleg (TODO should be an exception too)
        ##

        # If we can jump to a new layout, all is good
        if fuzzerstate.effective_curr_layout != -1 and len(fuzzerstate.pagetablestate.common_base_page[fuzzerstate.effective_curr_layout]) > 1:
            return False
        # Instruction page-fault bit, if we cannot deleguate instruction page-fault, we do not allow a new SATP, TODO add to exceptions
        if not (fuzzerstate.privilegestate.medeleg_val >> PAGE_ALIGNMENT_SHIFT) & 0b1:
            return True
        # If we cannot switch to another layout, there is not point in changing
        if len(fuzzerstate.prog_mmu_params) <= 1:
            return True

    return False

##
# Utility functions
##

# @brief generate the weights for the potential new layouts
def gen_weights_mmu(fuzzerstate):
    weights = [1] * (len(fuzzerstate.prog_mmu_params) + 1)  # +1 because we're including -1 (bare)
    weights[fuzzerstate.effective_curr_layout + 1] = 0 # +1 to account for bare

    if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR:
        # If we cannot deleg, set weights to 0
        if not (fuzzerstate.privilegestate.medeleg_val >> PAGE_ALIGNMENT_SHIFT) & 0b1:
            weights = [0] * (len(fuzzerstate.prog_mmu_params) + 1)
        # Always set the layouts we can jump to
        if fuzzerstate.effective_curr_layout != -1:
            for layout in fuzzerstate.pagetablestate.common_base_page[fuzzerstate.effective_curr_layout]:
                weights[layout + 1] = 1
        # bare is always 0 in S mode, as it is an exception
        weights[0] = 0
    # if fuzzerstate.privilegestate.curr_mstatus_mpp !=  PrivilegeStateEnum.MACHINE:
    #     weights[-1] = 0
            
    return weights

# @brief generares the satp value
def gen_satp_val(fuzzerstate, layout, base_page_addr):
    from common.profiledesign import get_asid_mask 
    
    satp_ppn            = (base_page_addr & (~0xFFF)) >> PAGE_ALIGNMENT_SHIFT
    mode                = fuzzerstate.prog_mmu_params[layout][0]
    if fuzzerstate.is_design_64bit:
        mode_id             = MODES_PARAMS_RV64[mode][0]
    else:
        mode_id             = MODES_PARAM_RV32[mode][0]
    supported_asid      = get_asid_mask(fuzzerstate.design_name)

    if supported_asid == 0:
        new_asid = 0
    else:
        new_asid = random.randint(0, supported_asid) # randomize or just one per layout ?

    if fuzzerstate.is_design_64bit:
        fuzzerstate.curr_satp_no_asid = (mode_id << 60) | (satp_ppn)
        return ((mode_id << 60) | (new_asid << 44) | (satp_ppn)), new_asid # ASID is used to avoid sfence, should be fuzzed as well, we will use the max ASID
    else:
        fuzzerstate.curr_satp_no_asid = (mode_id << 31) | (satp_ppn)
        return ((mode_id << 31) | (new_asid << 22) | (satp_ppn)), new_asid

def reset_some_states(fuzzerstate):
    # If either is populated, invalidated by the new layout
    if fuzzerstate.privilegestate.is_sepc_populated or fuzzerstate.privilegestate.is_mepc_populated:
        fuzzerstate.privilegestate.is_sepc_populated = False
        fuzzerstate.privilegestate.is_mepc_populated = False
    # Same, invalidated by new layout
    if fuzzerstate.privilegestate.is_stvec_populated:
        fuzzerstate.privilegestate.is_stvec_populated = False

def update_fuzzerstate(fuzzerstate, real_layout: int = None, effective_layout: int = None, asid: int = None, target_layout: int = None, \
                       is_sepc_pop: bool = None, curr_mstatus_spp: PrivilegeStateEnum = None, num_instr_to_stay_in_layout: int = None):
    if real_layout != None:
        fuzzerstate.real_curr_layout = real_layout
    if effective_layout != None:
        fuzzerstate.effective_curr_layout = effective_layout
    if asid != None:
        fuzzerstate.curr_asid = asid
    if target_layout != None:
        fuzzerstate.target_layout = target_layout
    if is_sepc_pop != None:
        fuzzerstate.is_sepc_populated = is_sepc_pop
    if curr_mstatus_spp != None:
        fuzzerstate.privilegestate.curr_mstatus_spp = curr_mstatus_spp
    if num_instr_to_stay_in_layout != None:
        fuzzerstate.num_instr_to_stay_in_layout = num_instr_to_stay_in_layout

def will_satp_write_tarp(fuzzerstate):
    # We only trap in S mode
    if fuzzerstate.privilegestate.privstate != PrivilegeStateEnum.SUPERVISOR:
        return False
    # If we are in bare, we tarp
    if fuzzerstate.effective_curr_layout == -1:
        return True
    # If the virtual addresses are identical, we will not trap
    if fuzzerstate.pagetablestate.vmem_base_list[fuzzerstate.target_layout][fuzzerstate.privilegestate.privstate] == \
        fuzzerstate.pagetablestate.vmem_base_list[fuzzerstate.effective_curr_layout][fuzzerstate.privilegestate.privstate]:
        return False
    
    return True

# @brief if the base page of the target layout is within our set of pages, it might fails, see report
def target_is_sane(fuzzerstate, target_layout):
    for base_page_target in fuzzerstate.pagetablestate.ptr_pt_base_list_per_layout[target_layout]:
        base_page_target_alligned = base_page_target & PAGE_ALIGNMENT_MASK
        for base_page in fuzzerstate.pagetablestate.ptr_pt_base_list_per_layout[fuzzerstate.effective_curr_layout]:
            base_page_alligned = base_page & PAGE_ALIGNMENT_MASK
            if base_page_target_alligned == base_page_alligned:
                return False
    return True

##
# TODO:
# - Add dynamic changes to paging structures (exceptions and page fault handling)
# - We excpect to not be able to translate the address after writing to satp, with rv32, it can happen that the excetion happens at the next address
# which we do not handle yet
##

##
# FSM for rv32 and rv64
##

# @brief, the rv32 mmu fsm
def update_mmu_fsm_rv32(fuzzerstate, curr_addr):
    if DEBUG_PRINT: print(f"Updating mmu fsm @ {hex(curr_addr+SPIKE_STARTADDR)}")
    # IDLE => MMU_PRODUCER1, generate RPROD, after this step, make sure we do not produce anything anymore for 64 bits values
    if fuzzerstate.curr_mmu_state == MmuState.IDLE:
        if fuzzerstate.privilegestate.is_sepc_populated or fuzzerstate.privilegestate.is_mepc_populated:
            fuzzerstate.privilegestate.is_sepc_populated = False
            fuzzerstate.privilegestate.is_mepc_populated = False
        if fuzzerstate.privilegestate.is_stvec_populated:
            fuzzerstate.privilegestate.is_stvec_populated = False

        assert fuzzerstate.target_layout == None
        if DEBUG_PRINT: print("rv32 mmu init")

        # First, select the next layout
        weights         = gen_weights_mmu(fuzzerstate)
        target_layout   = random.choices(range(-1, len(fuzzerstate.prog_mmu_params)), weights)[0]

        # There is one corner case, if the target layout has the same base page as a layout which has the same 
        # virtual memory base address as us, we will not tarp, so we should jump to the new layout after setting satp
        # To solve this issue, we modify the target to be the layout with the same virtual memeory as us
        if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR and fuzzerstate.effective_curr_layout != -1:
            # Get the layouts with the same base page as the target
            target_same_base_set = fuzzerstate.pagetablestate.common_base_page[target_layout]
            for layout_id in target_same_base_set:
                if fuzzerstate.pagetablestate.vmem_base_list[layout_id][fuzzerstate.privilegestate.privstate] == \
                    fuzzerstate.pagetablestate.vmem_base_list[fuzzerstate.effective_curr_layout][fuzzerstate.privilegestate.privstate]:
                    target_layout = layout_id

        # If target share the base page with the effective layout
        if target_layout != -1 and fuzzerstate.effective_curr_layout != -1 and target_layout in fuzzerstate.pagetablestate.common_base_page[fuzzerstate.effective_curr_layout]:
            # Update mmu state
            if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR:
                if GET_DATA:
                    fuzzerstate.jump_to_new_layout += 1
                fuzzerstate.target_layout = target_layout
                fuzzerstate.curr_mmu_state = MmuState.MMU_PROD_J
            if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE:
                if GET_DATA:
                    fuzzerstate.machine_only_rprod += 1
                fuzzerstate.real_curr_layout        = target_layout
                if DEBUG_PRINT: print(f"MACHINE, DOING NOTHING, new layout {target_layout}") 
                # This is a tricky operation, as it is impossible to track when popping block, might need another tracking mechanism to generate the correct pc sequence
                # For rv32, we only have to set tracking data
                return None

        # If we selected layout -1, we must be machine mode, so just write in SATP, has no side effects
        if target_layout == -1 and fuzzerstate.privilegestate.privstate != PrivilegeStateEnum.SUPERVISOR:
            # Update tracking
            fuzzerstate.effective_curr_layout   = -1
            fuzzerstate.real_curr_layout        = -1
            fuzzerstate.curr_asid               = 0
            fuzzerstate.target_layout           = None
            # Make CSRW instruction
            tmp = fuzzerstate.intregpickstate.pick_int_outputreg()
            is_satp_smode = ((fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR), fuzzerstate.real_curr_layout)
            # TODO with mode 0, we should be able to trash the other bits
            if GET_DATA:
                if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR:
                    fuzzerstate.satp_write_supervisor += 1
                else:
                    fuzzerstate.satp_write_machine += 1
            fuzzerstate.intregpickstate.free_pageregs()
            return [CSRRegInstruction_t0(fuzzerstate,"csrrw", tmp, 0, CSR_IDS.SATP, is_satp_smode=is_satp_smode)]
        else:
            fuzzerstate.target_layout = target_layout
            if fuzzerstate.curr_mmu_state == MmuState.IDLE:
                if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR \
                    and not (fuzzerstate.effective_curr_layout != -1 and (fuzzerstate.effective_curr_layout != -1 and (fuzzerstate.pagetablestate.vmem_base_list[fuzzerstate.target_layout][fuzzerstate.privilegestate.privstate] == \
                        fuzzerstate.pagetablestate.vmem_base_list[fuzzerstate.effective_curr_layout][fuzzerstate.privilegestate.privstate]))):
                    if GET_DATA:
                        fuzzerstate.satp_write_supervisor += 1
                    fuzzerstate.curr_mmu_state = MmuState.MMU_PROD_1
                else:
                    if GET_DATA:
                        fuzzerstate.satp_write_machine += 1
                    fuzzerstate.curr_mmu_state = MmuState.MMU_PROD_2
            # If the design is 32 bits, no need for rprod, got to next state now  

    # MMU_PRODUCER JUMP => MMU_IDLE, generate the stvec if needed (we are supervisor currently), if this step is taken, we cannot leave supervisor mode
    if fuzzerstate.curr_mmu_state == MmuState.MMU_PROD_J and fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR:
        if DEBUG_PRINT: 
            print("MMU fsm in state PRODJ->IDLE")
        # Update mmu state
        fuzzerstate.curr_mmu_state = MmuState.IDLE
        ret = gen_jump_new_layout(fuzzerstate, curr_addr)
        # Update tracking values
        fuzzerstate.real_curr_layout                = fuzzerstate.target_layout
        fuzzerstate.effective_curr_layout           = fuzzerstate.target_layout
        fuzzerstate.target_layout                   = None
        fuzzerstate.num_instr_to_stay_in_layout     = random.randint(MIN_NUM_INSTR_IN_LAYOUT, MAX_NUM_INSTR_IN_LAYOUT)
        return ret
    
    # MMU_PRODUCER1 => MMU_PRODUCER_2, generate the stvec if needed (we are supervisor currently), if this step is taken, we cannot leave supervisor mode
    if fuzzerstate.curr_mmu_state == MmuState.MMU_PROD_1:
        if DEBUG_PRINT: 
            print("MMU fsm in state PROD1->PROD2")
        # Update mmu state
        fuzzerstate.curr_mmu_state = MmuState.MMU_PROD_2
        return gen_stvec_satp(fuzzerstate, curr_addr)
    
    # MMU_PRODUCER_2 => IDLE, SATP produced, writes to satp, we either change layouts if currently in supervisor mode, or wait to use the layout, normal execution
    if fuzzerstate.curr_mmu_state == MmuState.MMU_PROD_2:
        if DEBUG_PRINT: 
            print("MMU fsm -> IDLE")
        # Update state
        fuzzerstate.curr_mmu_state = MmuState.IDLE
        ret = gen_satp_write(fuzzerstate, curr_addr)
        # Update bookeeping
        if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR:
            fuzzerstate.privilegestate.is_sepc_populated    = False #The trap will pollute it
            fuzzerstate.privilegestate.curr_mstatus_spp     = fuzzerstate.privilegestate.privstate
            fuzzerstate.effective_curr_layout               = fuzzerstate.target_layout
            fuzzerstate.num_instr_to_stay_in_layout         = random.randint(MIN_NUM_INSTR_IN_LAYOUT, MAX_NUM_INSTR_IN_LAYOUT)
        elif fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE:
            if DEBUG_PRINT: print(f"==> Set SATP in machine mode to {fuzzerstate.target_layout}")
            fuzzerstate.satp_set_not_used = True # In machine mode, we use bare independantly from the layout, so we only set the real layout

        fuzzerstate.real_curr_layout    = fuzzerstate.target_layout
        fuzzerstate.target_layout       = None
    return ret

##
# Top level FSM
# Leaving the IDLE state in RV32 does not have to produce a new RPROD, so handling differs
##

# @brief top evel function to handle MMU fsm states
def update_mmu_fsm_rv64(fuzzerstate, curr_addr):
    if DEBUG_PRINT: 
        print(f"Updating mmu fsm @ {hex(curr_addr + SPIKE_STARTADDR)}")

    # IDLE => NEXT_STATE (JUMP, IDLE, PROD1), generates RPROD or writes 0 to SATP
    if fuzzerstate.curr_mmu_state == MmuState.IDLE:
        return handle_idle_state_rv64(fuzzerstate, curr_addr)

    # MMU_PRODUCER JUMP => MMU_IDLE
    if fuzzerstate.curr_mmu_state == MmuState.MMU_PROD_J:
        return handle_producer_jump_state(fuzzerstate, curr_addr)

    # MMU_PRODUCER1 => MMU_PRODUCER_2
    if fuzzerstate.curr_mmu_state == MmuState.MMU_PROD_1:
        return handle_producer1_state(fuzzerstate, curr_addr)

    # MMU_PRODUCER_2 => IDLE
    if fuzzerstate.curr_mmu_state == MmuState.MMU_PROD_2:
        return handle_producer2_state(fuzzerstate, curr_addr)
##
# FSM state handlers
##

# @brief handles leaving the IDLE state
def handle_idle_state_rv64(fuzzerstate, curr_addr):
    assert fuzzerstate.target_layout is None
    # Reset MEPC/SEPC/STVEC state if needed
    reset_some_states(fuzzerstate)

    # First, select the next layout
    weights         = gen_weights_mmu(fuzzerstate)
    target_layout   = random.choices(range(-1, len(fuzzerstate.prog_mmu_params)), weights)[0]

    if DEBUG_PRINT:
        print(f"current layout: {fuzzerstate.effective_curr_layout}, target: {target_layout}, taint_source: {target_layout in fuzzerstate.taint_source_layouts}")

    # There is one corner case, if the target layout has the same base page as a layout which has the same 
    # virtual memory base address as us, we will not tarp, so we should jump to the new layout after setting satp
    # To solve this issue, we modify the target to be the layout with the same virtual memeory as us
    if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR and fuzzerstate.effective_curr_layout != -1:
        # Get the layouts with the same base page as the target
        target_same_base_set = fuzzerstate.pagetablestate.common_base_page[target_layout]
        for layout_id in target_same_base_set:
            if layout_id != fuzzerstate.effective_curr_layout and fuzzerstate.pagetablestate.vmem_base_list[layout_id][fuzzerstate.privilegestate.privstate] == \
                fuzzerstate.pagetablestate.vmem_base_list[fuzzerstate.effective_curr_layout][fuzzerstate.privilegestate.privstate]:
                target_layout = layout_id
                if DEBUG_PRINT: print(f"target changed to {target_layout} becuase of same base page")

    # If target share the base page with the effective layout, we either set RPROD then JUMP if in S mode, or set RPROD in M mode
    if target_layout != -1 and fuzzerstate.effective_curr_layout != -1 and (target_layout in fuzzerstate.pagetablestate.common_base_page[fuzzerstate.effective_curr_layout]):
        if GET_DATA:
            fuzzerstate.jump_to_new_layout += 1
        # Update mmu state
        if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR:
            fuzzerstate.curr_mmu_state = MmuState.MMU_PROD_J
        if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE:
            if DEBUG_PRINT: 
                print("MACHINE, ONLY SETTING RPROD")
            # here, we only need to make the new rprod, we saty idle
            update_fuzzerstate(fuzzerstate, target_layout=target_layout, real_layout=target_layout, num_instr_to_stay_in_layout=random.randint(MIN_NUM_INSTR_IN_LAYOUT, MAX_NUM_INSTR_IN_LAYOUT))
            ret = gen_rprod_taget_layout(fuzzerstate)
            fuzzerstate.target_layout = None
            return ret
        
    # If we cannot jump to the new layout, we have to check this corner case, and maybe invalidate the operation, see report
    if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR and fuzzerstate.curr_mmu_state == MmuState.IDLE and (not target_is_sane(fuzzerstate, target_layout)):
        if DEBUG_PRINT: print("cannot use this layout, aborting...")
        return None
        
    # If we selected layout -1, we must be machine mode, so just write in SATP, has no side effects
    if target_layout == -1:
        # Update tracking
        update_fuzzerstate(fuzzerstate, real_layout=-1, effective_layout=-1, asid=0)
        fuzzerstate.target_layout = None
        # Make CSRW instruction
        tmp = fuzzerstate.intregpickstate.pick_int_outputreg()
        is_satp_smode = ((fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR), fuzzerstate.real_curr_layout)
        # TODO with mode 0, we should be able to trash the other bits
        if GET_DATA:
            if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR:
                fuzzerstate.satp_write_supervisor += 1
            else:
                fuzzerstate.satp_write_machine += 1
        assert fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE
        fuzzerstate.intregpickstate.free_pageregs()
        return [CSRRegInstruction_t0(fuzzerstate,"csrrw", tmp, 0, CSR_IDS.SATP, is_satp_smode=is_satp_smode)]
    
    # Otherwise, if we are in S mode, and the virtual addresses changes, select the path to make STVEC, else just RPROD
    fuzzerstate.target_layout = target_layout
    if fuzzerstate.curr_mmu_state == MmuState.IDLE:
        if will_satp_write_tarp(fuzzerstate): #if the virtual addresses are the same, we will not trap if the pages are global
            if GET_DATA:
                fuzzerstate.satp_write_supervisor += 1
            if DEBUG_PRINT:
                print("MMU fsm in state IDLE -> PROD1")
            fuzzerstate.curr_mmu_state = MmuState.MMU_PROD_1
        else:
            if DEBUG_PRINT:
                print("MMU fsm in state IDLE -> PROD2")
            if GET_DATA:
                fuzzerstate.satp_write_machine += 1
            fuzzerstate.curr_mmu_state = MmuState.MMU_PROD_2

    # If we reached this point, we are leaving IDLE state, generate RPROD
    return gen_rprod_taget_layout(fuzzerstate) 

# @brief, handle the JUMP state, create the JUMP instruction and return to IDLE
def handle_producer_jump_state(fuzzerstate, curr_addr):
    assert fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR
    if DEBUG_PRINT: 
        print("MMU fsm in state PRODJ -> IDLE\n")
    # Update mmu state
    fuzzerstate.curr_mmu_state = MmuState.IDLE
    ret = gen_jump_new_layout(fuzzerstate, curr_addr)
    # Update tracking values
    update_fuzzerstate(fuzzerstate, real_layout=fuzzerstate.target_layout, effective_layout=fuzzerstate.target_layout, num_instr_to_stay_in_layout=random.randint(MIN_NUM_INSTR_IN_LAYOUT, MAX_NUM_INSTR_IN_LAYOUT))
    fuzzerstate.target_layout = None
    return ret

# @brief, handle the PROD1 state, generate the STVEC
def handle_producer1_state(fuzzerstate, curr_addr):
    assert fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR
    if DEBUG_PRINT: 
        print("MMU fsm in state PROD1->PROD2")
    # Update mmu state
    fuzzerstate.curr_mmu_state = MmuState.MMU_PROD_2
    return gen_stvec_satp(fuzzerstate, curr_addr)

# @brief, handle the PROD2 state, write to SATP and return to IDLE
def handle_producer2_state(fuzzerstate, curr_addr):
    if DEBUG_PRINT: 
        print("MMU fsm -> IDLE\n")
    # Update state
    fuzzerstate.curr_mmu_state = MmuState.IDLE
    ret = gen_satp_write(fuzzerstate, curr_addr)
    # Update bookeeping
    if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR:
        update_fuzzerstate(fuzzerstate, is_sepc_pop=False, curr_mstatus_spp=fuzzerstate.privilegestate.privstate, effective_layout=fuzzerstate.target_layout, num_instr_to_stay_in_layout=random.randint(MIN_NUM_INSTR_IN_LAYOUT, MAX_NUM_INSTR_IN_LAYOUT))
    elif fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE:
        if DEBUG_PRINT: print(f"==> Set SATP in machine mode to {fuzzerstate.target_layout}")
        fuzzerstate.satp_set_not_used = True # In machine mode, we use bare independantly from the layout, so we only set the real layout

    update_fuzzerstate(fuzzerstate, real_layout=fuzzerstate.target_layout)
    fuzzerstate.target_layout       = None
    return ret

##
# Functions to handle MMU FSM state
##

# @brief produces the RPROD register
def gen_rprod_taget_layout(fuzzerstate):
    # Set the RPROD mask for the new future layout, and save the coordinates to update the value when we know the next priv mode (only useful if we are currently in M mode)
    instr_objs = []
    tmp = fuzzerstate.intregpickstate.pick_int_outputreg_nonzero()
    if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE:
        fuzzerstate.satp_op_coordinates = ((len(fuzzerstate.instr_objs_seq)-1, len(fuzzerstate.instr_objs_seq[-1]) + len(instr_objs)), fuzzerstate.target_layout)
    rdep_imm = fuzzerstate.pagetablestate.vmem_base_list[fuzzerstate.target_layout][fuzzerstate.privilegestate.privstate] | 0x7fffffff
    instr_objs += li_doubleword(rdep_imm, RPROD_MASK_REGISTER_ID, tmp, fuzzerstate, is_rd_nonpickable_ok=True) #FUTURE use a CONSUMED reg to load the bottom 32 bits
    if GET_DATA:
        fuzzerstate.num_hardcoded_instr_mmufsm += len(instr_objs)
    return instr_objs

# TODO use a CONSUME reg for this operation
# TODO use a new bb instead of contiguous, so if we do not trap, we timeout
# @brief if in S mode, produces stvec, must disable exception after that, as we need to keep stvec
def gen_stvec_satp(fuzzerstate, curr_addr):
    instr_objs = []
    fuzzerstate.privilegestate.is_stvec_populated = False
    fuzzerstate.stvec_satp_op_coordinates = (len(fuzzerstate.instr_objs_seq)-1, len(fuzzerstate.instr_objs_seq[-1]) + len(instr_objs))
    stvec_val_reg   = fuzzerstate.intregpickstate.pick_int_inputreg_nonzero()
    lui_imm, addi_imm = 0, 0
    instr_objs.append(ImmRdInstruction_t0(fuzzerstate,"lui", stvec_val_reg, lui_imm))
    instr_objs.append(RegImmInstruction_t0(fuzzerstate,"addi", stvec_val_reg, stvec_val_reg, addi_imm))
    if fuzzerstate.is_design_64bit and fuzzerstate.target_layout != -1:
        instr_objs.append(R12DInstruction_t0(fuzzerstate,"and", stvec_val_reg, stvec_val_reg, RPROD_MASK_REGISTER_ID))
    if fuzzerstate.is_design_64bit and fuzzerstate.target_layout == -1:
        instr_objs.append(R12DInstruction_t0(fuzzerstate,"and", stvec_val_reg, stvec_val_reg, RDEP_MASK_REGISTER_ID))
    instr_objs.append(TvecWriterInstruction_t0(fuzzerstate,False, stvec_val_reg, stvec_val_reg, -1))
    fuzzerstate.intregpickstate.set_regstate(stvec_val_reg, IntRegIndivState.RELOCUSED, force=True)
    fuzzerstate.n_missing_r_cmds += 1
    if GET_DATA:
        fuzzerstate.num_hardcoded_instr_mmufsm += len(instr_objs)

    return instr_objs

# @brief, generates the CSR write operation to SATP and updates the tracking variables
def gen_satp_write(fuzzerstate, curr_addr):
    base_page_addr                  = fuzzerstate.pagetablestate.ptr_pt_base_list_per_layout[fuzzerstate.target_layout][0]
    instr_objs                      = []
    old_asid                        = fuzzerstate.curr_asid
    is_from_bare                    = (fuzzerstate.target_layout == -1) or (fuzzerstate.effective_curr_layout == -1)

    if fuzzerstate.target_layout not in fuzzerstate.taint_source_layouts:
        instr_objs += clear_taints_with_random_instructions(fuzzerstate,untaint_all=True)
        assert fuzzerstate.effective_curr_layout in fuzzerstate.taint_source_layouts or len(instr_objs) == 0
        curr_addr += 4*len(instr_objs)

    # Set the destination of stvec if needed
    if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR and fuzzerstate.stvec_satp_op_coordinates != (None, None):
        if DEBUG_PRINT: print(f"{hex(curr_addr+SPIKE_STARTADDR)}: In supervisor mode, going to layout {fuzzerstate.target_layout}")
        bb_id, instr_id = fuzzerstate.stvec_satp_op_coordinates
        if fuzzerstate.is_design_64bit: 
            if fuzzerstate.target_layout != -1:
                target = fuzzerstate.pagetablestate.vmem_base_list[fuzzerstate.target_layout][fuzzerstate.privilegestate.privstate] + curr_addr + 8*4 # Add the next instructions
            else:
                # TODO state should never be reached
                target = SPIKE_STARTADDR + curr_addr + 8*4 # Add the next instructions
            target = (target | 0x80000000) & 0xffffffff
        else:
            if fuzzerstate.target_layout != -1:
                target = fuzzerstate.pagetablestate.vmem_base_list[fuzzerstate.target_layout][fuzzerstate.privilegestate.privstate] + curr_addr + 3*4
            else:
                # TODO state should never be reached
                target = SPIKE_STARTADDR + curr_addr + 3*4

        lui_imm, addi_imm = li_into_reg(target, False)
        fuzzerstate.instr_objs_seq[bb_id][instr_id].imm     = lui_imm
        fuzzerstate.instr_objs_seq[bb_id][instr_id+1].imm   = addi_imm
        fuzzerstate.stvec_satp_op_coordinates = (None, None)


    # Generate the register which will hold the SATP value
    if fuzzerstate.target_layout != -1:
        satp_val, new_asid = gen_satp_val(fuzzerstate, fuzzerstate.target_layout, base_page_addr)
    else:
        satp_val, new_asid = 0, 0

    if DEBUG_PRINT: 
        print(f"{hex(curr_addr+SPIKE_STARTADDR)}: going to layout {fuzzerstate.target_layout}, base: {hex(base_page_addr)}, satp: {hex(satp_val)}")

    if fuzzerstate.is_design_64bit:
        satp_val_reg, tmp = fuzzerstate.intregpickstate.pick_int_inputregs_nonzero(2)
        instr_objs += li_doubleword(satp_val, satp_val_reg, tmp, fuzzerstate)
    else:
        satp_val_reg = fuzzerstate.intregpickstate.pick_int_inputreg_nonzero()
        lui_imm, addi_imm = li_into_reg(satp_val, False)
        instr_objs.append(ImmRdInstruction_t0(fuzzerstate,"lui", satp_val_reg, lui_imm))
        instr_objs.append(RegImmInstruction_t0(fuzzerstate,"addi", satp_val_reg, satp_val_reg, addi_imm))

    # Write to SATP
    is_satp_smode = ((fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR), fuzzerstate.target_layout)
    instr_objs.append(CSRRegInstruction_t0(fuzzerstate, "csrrw", satp_val_reg, satp_val_reg, CSR_IDS.SATP, is_satp_smode=is_satp_smode))
    fuzzerstate.intregpickstate.set_regstate(satp_val_reg, IntRegIndivState.RELOCUSED, force=True)

    # On satp write, if the ASID is recycled, we need an sfence
    # FIXME this is still buggy, as we still rely on traps currently
    if (not is_from_bare) and old_asid == new_asid:
        if DEBUG_PRINT:
            print("using fence, either, same asid")
        instr_objs.append(SpecialInstruction_t0(fuzzerstate, "sfence.vma", 0, 0, 0))
        fuzzerstate.n_missing_r_cmds += 1
        # print(f"Missing r cmds: {fuzzerstate.n_missing_r_cmds}")
        if (fuzzerstate.privilegestate.medeleg_val >> ExceptionCauseVal.ID_INSTRUCTION_PAGE_FAULT)&1:
            fuzzerstate.csrfile.regs[CSR_IDS.SEPC].unreliable = True
        else:
            fuzzerstate.csrfile.regs[CSR_IDS.MEPC].unreliable = True

    # If the old layout was global, we also need an sfence, or the TLB will continue using the old mappings.
    elif fuzzerstate.pagetablestate.layout_is_global[fuzzerstate.target_layout]:
        if DEBUG_PRINT: 
            print(f"layout {fuzzerstate.target_layout} is global, sfence")
        instr_objs.append(SpecialInstruction_t0(fuzzerstate, "sfence.vma", 0, 0, 0)) #TODO we can flush only the old ASID, must have a reg for that
        if (fuzzerstate.privilegestate.medeleg_val >> ExceptionCauseVal.ID_INSTRUCTION_PAGE_FAULT)&1 and not is_from_bare:
            fuzzerstate.csrfile.regs[CSR_IDS.SEPC].unreliable = True
        else:
            fuzzerstate.csrfile.regs[CSR_IDS.MEPC].unreliable = True

    if GET_DATA:
        fuzzerstate.num_hardcoded_instr_mmufsm += len(instr_objs)

    fuzzerstate.intregpickstate.free_pageregs()
    fuzzerstate.curr_asid = new_asid
    return instr_objs

# @brief jumps to new new layout
def gen_jump_new_layout(fuzzerstate, curr_addr):
    if DEBUG_PRINT: print("------ JUMPING TO NEW LAYOUT ---------\n")
    instr_objs = []
    # Generate the target address
    tmp = fuzzerstate.intregpickstate.pick_int_inputreg_nonzero()
    if fuzzerstate.is_design_64bit:
        target = fuzzerstate.pagetablestate.vmem_base_list[fuzzerstate.target_layout][fuzzerstate.privilegestate.privstate] + curr_addr + 4*4
        lui_imm, addi_imm = li_into_reg((target|0x80000000) & 0xffffffff, False)
    else:
        target = fuzzerstate.pagetablestate.vmem_base_list[fuzzerstate.target_layout][fuzzerstate.privilegestate.privstate] + curr_addr + 3*4
        lui_imm, addi_imm = li_into_reg(target, False)
    
    instr_objs.append(ImmRdInstruction_t0(fuzzerstate,"lui", tmp, lui_imm)) # Cannot produce, rely on freshly generated RPROD
    instr_objs.append(RegImmInstruction_t0(fuzzerstate,"addi", tmp, tmp, addi_imm))
    if fuzzerstate.is_design_64bit: 
        instr_objs.append(R12DInstruction_t0(fuzzerstate,"and", tmp, tmp, RPROD_MASK_REGISTER_ID))
    # Finally, we jump to the new layout
    instr_objs.append(JALRInstruction_t0(fuzzerstate,"jalr", tmp, tmp, 0, -1, True))
    # fuzzerstate.intregpickstate.set_regstate(tmp, IntRegIndivState.RELOCUSED, force=True)

    if GET_DATA:
        fuzzerstate.num_hardcoded_instr_mmufsm += len(instr_objs)
    fuzzerstate.intregpickstate.free_pageregs()
    return instr_objs