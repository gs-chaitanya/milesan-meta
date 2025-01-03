from milesan.cfinstructionclasses_t0 import *
from milesan.mmu_utils import li_doubleword
from milesan.randomize.createcfinstr import create_instr
from milesan.spikeresolution import get_current_layout
from milesan.randomize.pickinstrtype import gen_next_instrstr_from_isaclass
from milesan.util import ISAInstrClass


# @params: create_cf_ambigous_instrs: function that returns a list of instructions that redirect the control flow e.g. a taken branch, jalr et.c
def _create_spectre_gadget_instrobjs(fuzzerstate, instr_str):
    load_str = None
    while load_str is None or load_str not in IntLoadInstruction.authorized_instr_strs:
        load_str = gen_next_instrstr_from_isaclass(ISAInstrClass.MEM, fuzzerstate)

    store_str = None
    while store_str is None or store_str not in IntStoreInstruction.authorized_instr_strs:
        store_str = gen_next_instrstr_from_isaclass(ISAInstrClass.MEM, fuzzerstate)

    if load_str in ["lb","lbu"]:
        load_alignment_bits = 0
        load_min_space = 1
    elif load_str in ["lh","lhu"]:
        load_alignment_bits = 1
        load_min_space = 2
    elif load_str in ["lw","lwu"]:
        load_alignment_bits = 2
        load_min_space = 4
    elif load_str in ["ld"]:
        load_alignment_bits = 3
        load_min_space = 8

    if store_str in ["sb"]:
        store_alignment_bits = 0
    elif store_str in ["sh"]:
        store_alignment_bits = 1
    elif store_str in ["sw"]:
        store_alignment_bits = 2
    elif store_str in ["sd"]:
        store_alignment_bits = 3
    


    if len(fuzzerstate.instr_objs_seq[-1]):
        last_instr = fuzzerstate.instr_objs_seq[-1][-1] # We need the layout from the previous instruction
    else: # In case its the first instruciton of a block.
        last_instr = fuzzerstate.instr_objs_seq[-2][-1] # We need the layout from the previous instruction

    va_layout, priv_level = get_current_layout(last_instr, last_instr.va_layout, last_instr.priv_level)
    curr_addr = fuzzerstate.curr_bb_start_addr + 4*len(fuzzerstate.instr_objs_seq[-1])

    # Generate an address to a tainted memory region. TODO: play around with load_min_space? Also ensure we load from index that stores tainted data?
    load_addr  = fuzzerstate.memview.gen_random_addr_from_randomblock(load_alignment_bits,load_min_space,tainted_ok=True, not_tainted_ok=False)
    assert load_addr is not None

    store_addr  = fuzzerstate.memview.gen_random_addr_from_randomblock(store_alignment_bits,256,tainted_ok=False, not_tainted_ok=True)
    assert store_addr is not None
    instr_objs = []
    if va_layout == -1: # We don't need 64bit values in bare.
        assert not USE_MMU or priv_level == PrivilegeStateEnum.MACHINE, f"We need to be in machine mode to use bare translation when the MMU is enabled."
        rd = fuzzerstate.intregpickstate.pick_untainted_int_outputreg_nonzero(force = False) # Rd will be untainted after execution.
        (rs1,rs2) = fuzzerstate.intregpickstate.pick_tainted_int_inputregs(n=2,force = False) # Chose some tainted regs to leak via cache.
        # In machine mode, we just try to leak some tainted register speculatively by using it to index into an array that is accessible from any privelege.
        uimm0, uimm1 = li_into_reg(to_unsigned(load_addr, fuzzerstate.is_design_64bit), False)
        instr_objs += [ # Prepare the target address for the load.
                ImmRdInstruction_t0(fuzzerstate, "lui", rd, uimm0),
                RegImmInstruction_t0(fuzzerstate,"addi",rd,rd,uimm1),
                R12DInstruction_t0(fuzzerstate, "xor",rd,rd ,RELOCATOR_REGISTER_ID)
                ]
        instr_objs += [create_instr(instr_str, fuzzerstate, curr_addr + 4*len(instr_objs), False)] # Everything below is executed speculatively. TODO: ensure the prepared regs are not overwritten.
        instr_objs += [
                SpeculativeInstructionEncapsulator(fuzzerstate, RegImmInstruction_t0(fuzzerstate,"andi",rs2,rs2,0xFF)), # mask out single byte
                SpeculativeInstructionEncapsulator(fuzzerstate, R12DInstruction_t0(fuzzerstate, "add", rd, rd, rs2)), # add tainted offset to rd
                SpeculativeInstructionEncapsulator(fuzzerstate, IntStoreInstruction_t0(fuzzerstate,store_str,rd,rs1, 0x0, None)) # store taitned reg at tainted offset
            ]

    else: # if we use the MMU, we need to get the virtual address and use one extra instruction to set up the 64 bit vaddress.
        assert priv_level != PrivilegeStateEnum.MACHINE, f"We can't be in machine mode and use vaddr translation."
        
        # Preparing the load addr to load from a tainted memory region, if we are not in a privilege that has access to tainted data.
        if priv_level in fuzzerstate.taint_sink_privs:
            (rd1,rd2,tmp) = fuzzerstate.intregpickstate.pick_untainted_int_outputregs_nonzero(3,force = False)
            rs2 = fuzzerstate.intregpickstate.pick_tainted_int_inputreg(force = False, authorize_sideeffects= False, allow_zero = False) # we will load tainted data into rs2
            load_addr = phys2virt(load_addr, priv_level, va_layout, fuzzerstate,absolute_addr=True)
            instr_objs += li_doubleword(load_addr, rd1, tmp, fuzzerstate) # rd1 has the load address 
        else:
            (rd2,tmp) = fuzzerstate.intregpickstate.pick_untainted_int_outputregs_nonzero(2,force = False) # Rd and tmp will be untainted after execution.
            rs2 = fuzzerstate.intregpickstate.pick_tainted_int_outputreg(force = False, authorize_sideeffects= False, allow_zero = False)
        # Prepare the store address.
        store_addr = phys2virt(store_addr, priv_level, va_layout,fuzzerstate,absolute_addr=True)
        instr_objs += li_doubleword(load_addr, rd2, tmp, fuzzerstate) # rd2 holds the store address

        instr_objs += [create_instr(instr_str, fuzzerstate, curr_addr + 4*len(instr_objs), False)] # Everything below is executed speculatively. TODO: ensure the prepared regs are not overwritten.

        if priv_level in fuzzerstate.taint_sink_privs:
            instr_objs += [SpeculativeInstructionEncapsulator(fuzzerstate, IntLoadInstruction_t0(fuzzerstate, load_str, rs2, rd1, 0x0, None))]  # Speculatively load tainted data into rs2 if we are in a privelege mode that cannot access tainted data.
        
        instr_objs += [
                SpeculativeInstructionEncapsulator(fuzzerstate, RegImmInstruction_t0(fuzzerstate,"andi",rs2,rs2,0xFF)), # mask out single byte
                SpeculativeInstructionEncapsulator(fuzzerstate, R12DInstruction_t0(fuzzerstate, "add", rd2, rd2, rs2)), # add tainted offset to rd2
                SpeculativeInstructionEncapsulator(fuzzerstate, IntStoreInstruction_t0(fuzzerstate,store_str,rd2,rs2,0x0, None)) # store taitned reg at tainted offset
            ]

    assert len(instr_objs)
    return instr_objs


def create_speculative_instrs(instr_str: str, fuzzerstate):
    # Only allow non-privilege affecting instructions for now.
    assert instr_str in SpeculativeInstructionEncapsulator.authorized_instr_strs, f"{instr_str} not authorzed for speculation."
    assert fuzzerstate.curr_branch_taken or instr_str not in BranchInstruction.authorized_instr_strs # Can only insert speculative instructions if we redirect the control flow.
    return _create_spectre_gadget_instrobjs(fuzzerstate, instr_str)

