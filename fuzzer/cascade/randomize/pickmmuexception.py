from milesan.util import IntRegIndivState, MmuState
from milesan.cfinstructionclasses import SimpleExceptionEncapsulator, IntLoadInstruction, CSRRegInstruction
from rv.csrids import CSR_IDS
from params.runparams import DEBUG_PRINT, GET_DATA

# @brief triggers a load page fault
def id_load_page_fault(is_mtvec: bool, fuzzerstate, old_privilege):
    ret = []
    if DEBUG_PRINT: print(f"load page fault exception, real layout: {fuzzerstate.real_curr_layout}")
    rs1 = fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
    rd = fuzzerstate.intregpickstate.pick_int_outputreg()
    producer_id = fuzzerstate.intregpickstate.get_producer_id(rs1)
    fuzzerstate.intregpickstate.set_regstate(rs1, IntRegIndivState.FREE)
    #fuzzerstate.n_missing_r_cmds += 1 #TODO do we need one here ?
    # addr zero might be mapped by big page, but it should not have a pte
    ret.append(SimpleExceptionEncapsulator(is_mtvec, None, IntLoadInstruction("lw", rd, rs1, 0, producer_id, fuzzerstate.is_design_64bit, fuzzerstate.privilegestate.privstate, fuzzerstate.effective_curr_layout), fuzzerstate.privilegestate.privstate, fuzzerstate.effective_curr_layout, old_privilege))
    return ret

# @brief triggers a id_instr_access_fault, generated in supervisor mode, no difference if using medeleg or not
def id_instr_access_fault(is_mtvec: bool, fuzzerstate, old_privilege):
    ret = []
    if DEBUG_PRINT: print("going to bare from sup exception")
    fuzzerstate.n_missing_r_cmds += 1
    fuzzerstate.effective_curr_layout = -1
    fuzzerstate.real_curr_layout = -1
    fuzzerstate.curr_mmu_state = MmuState.IDLE
    fuzzerstate.target_layout = None
    is_satp_smode = (True, -1)
    ret.append(SimpleExceptionEncapsulator(is_mtvec, None, CSRRegInstruction("csrrw", 0, 0, CSR_IDS.SATP, is_satp_smode=is_satp_smode), fuzzerstate.privilegestate.privstate, fuzzerstate.effective_curr_layout, old_privilege))
    if GET_DATA:
        fuzzerstate.satp_write_supervisor += 1
    return ret

def id_store_amo_page_fault(is_mtvec: bool, fuzzerstate):
    raise NotImplementedError("ID_STORE_AMO_PAGE_FAULT not yet supported")

def id_instruction_page_fault(is_mtvec: bool, fuzzerstate):
    raise NotImplementedError("ID_INSTRUCTION_PAGE_FAULT not yet supported")


'''
The issue with paging exception is that milesan has no lookahead in terms of addresses. When we want to trigger and exception, we have a granualrity of a page,
which will have a side effect on all instructions within that page. The best solution is not to trigger them by selecting and then updating paging, but rather
select the address that will fault in advance. Than, whenver we will go to that address it triggers an exception.

We could potentially select some page that will fault prior to execution. Then, when that address is first reached, the exception must be triggered. 
thus, stvec must already be loaded. STVEC can be loaded with a random value within the current address space. The randomization of this address allows us
to make a new random layout that is very different. We couls also force it to reuse the last level of pages to save some instructions. 

The side effect is that we must know in advance to which address we will jump, so we can load stvec accordingly, which reuires 7 instructions
'''