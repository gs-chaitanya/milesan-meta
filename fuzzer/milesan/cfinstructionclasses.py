# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

from params.fuzzparams import MAX_NUM_PICKABLE_REGS, RELOCATOR_REGISTER_ID, RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID_VIRT, FPU_ENDIS_REGISTER_ID, MPP_BOTH_ENDIS_REGISTER_ID, MPP_TOP_ENDIS_REGISTER_ID, SPP_ENDIS_REGISTER_ID, REGDUMP_REGISTER_ID, RDEP_MASK_REGISTER_ID_VIRT, RPROD_MASK_REGISTER_ID
from params.fuzzparams import USE_MMU, USE_COMPRESSED, USE_SPIKE_INTERM_ELF, NONPICKABLE_REGISTERS, FENCE_CF_INSTR
from params.runparams import DO_ASSERT, PRINT_CHECK_REGS, PRINT_REG_TRACEBACK, PRINT_FILTERED_REG_TRACEBACK, ASSERT_ADDR
from params.toleratebugsparams import *
from rv.csrids import CSR_IDS
from rv.util import INSTRUCTION_IDS, PARAM_SIZES_BITS_32, PARAM_SIZES_BITS_64, PARAM_IS_SIGNED
from milesan.util import CFInstructionClass
from milesan.util_compressed import COMPRESSED_INST_EQUIV
from milesan.mmu_utils import phys2virt
from rv.asmutil import li_into_reg, twos_complement, to_unsigned, INSTR_FUNCS, INSTR_FUNCS_T0
from rv.rvprivileged import rvprivileged_mret, rvprivileged_sret
from rv.zifencei import *
from rv.zicsr import *
from rv.rv32i import *
from rv.rv32f import *
from rv.rv32d import *
from rv.rv32m import *
from rv.rv64i import *
from rv.rv64f import *
from rv.rv64d import *
from rv.rv64m import *
#COMPRESSED
from rv.rv32ic import *
from rv.rv64ic import *
from milesan.randomize.pickbytecodetaints import CFINSTRCLASS_TAINT_PROBS, RD_INT_TAINT_PROBS_MASK, RS_INT_TAINT_PROBS_MASK, RD_FLOAT_TAINT_PROBS_MASK, RS_FLOAT_TAINT_PROBS_MASK, CFINSTRCLASS_TAINT_ONLY_ONE, OPCODE_FIELD_MASKS, OPCODE_FIELD_BITS, DONT_TAINT_REGS, CFINSTRCLASS_INJECT_PROBS
from common.spike import SPIKE_STARTADDR
from common.exceptions import *
from milesan.registers import ABI_INAMES, MAX_32b, MAX_64b, MAX_20b
from milesan.util import ExceptionCauseVal
from milesan.privilegestate import PrivilegeStateEnum
from milesan.mmu_utils import PAGE_ALIGNMENT_MASK
import random
import numpy as np


def compute_reg_traceback(reg_id, addr, fuzzerstate, correct_val):
    if addr is None: # if no address is given, use address of last instruction in last basic block.
        addr = fuzzerstate.instr_objs_seq[-1][-1].vaddr if USE_MMU else fuzzerstate.instr_objs_seq[-1][-1].paddr

    last_instr = None
    for bb_instrs in fuzzerstate.instr_objs_seq:
        for instr_obj in bb_instrs:
            if PRINT_REG_TRACEBACK:
                instr_obj.print()
            if hasattr(instr_obj, "rd") and instr_obj.rd == reg_id:
                last_instr = instr_obj
            elif isinstance(instr_obj, PlaceholderPreConsumerInstr) and instr_obj.rdep == reg_id:
                last_instr = instr_obj
            if (instr_obj.vaddr if USE_MMU else instr_obj.paddr) == addr: # reached this instruction
                assert last_instr is not None, f"Traceback computation for instruction at {hex(addr)} failed: No previous instruction modifying register {ABI_INAMES[reg_id]} with mismatch {hex(fuzzerstate.intregpickstate.regs[reg_id].get_val())} =! {hex(correct_val)} found."
                return last_instr # reached address of calling instruction


    assert False, f"Traceback computation for instruction at {hex(addr)} failed, this should not happen."


def filter_reg_traceback(reg_id, addr, fuzzerstate, correct_val, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF):
    last_instr = compute_reg_traceback(reg_id, addr, fuzzerstate, correct_val)
    assert last_instr is not None
    dep_regs = set()
    instr_stream = []
    for bb_instrs in reversed(fuzzerstate.instr_objs_seq):
        for instr_obj in reversed(bb_instrs):
            if instr_obj.paddr == last_instr.paddr: # start collecting depending registers
                instr_stream += [instr_obj]
                if hasattr(instr_obj,"rs1"):
                    dep_regs |= {instr_obj.rs1}
                if hasattr(instr_obj,"rs2"):
                    dep_regs |= {instr_obj.rs2}
                if hasattr(instr_obj,"rdep"):
                    dep_regs |= {instr_obj.rdep}
                if hasattr(instr_obj,"rprod"):    
                    dep_regs |= {instr_obj.rprod}

            elif hasattr(instr_obj,"rd") and instr_obj.rd in dep_regs:
                instr_stream += [instr_obj]
                dep_regs.remove(instr_obj.rd)
                if hasattr(instr_obj,"rs1"):
                    dep_regs |= {instr_obj.rs1}
                if hasattr(instr_obj,"rs2"):
                    dep_regs |= {instr_obj.rs2}
                if hasattr(instr_obj,"rdep"):
                    dep_regs |= {instr_obj.rdep}
                if hasattr(instr_obj,"rprod"):    
                    dep_regs |= {instr_obj.rprod}
            elif isinstance(instr_obj, PlaceholderPreConsumerInstr) and instr_obj.rdep in dep_regs:
                instr_stream += [instr_obj]
            if 0 in dep_regs:
                dep_regs.remove(0)

  
    
    if PRINT_FILTERED_REG_TRACEBACK:
        print("*** FILTERED TRACEBACK ***")
        for instr_obj in reversed(instr_stream):
            instr_obj.print(is_spike_resolution)

    return last_instr

# These classes are here for generating multi-instruction fuzzing programs.

###
# Abstract classes
###

class BaseInstruction:
    fuzzerstate = None
    paddr = None
    vaddr = None
    instr_str = None
    instr_type = CFInstructionClass.NONE
    instr_func = None
    instr_func_t0 = None
    priv_level = None
    iscontext = False
    iscompressed = False
    isdead = False # During reduction, me might want to remove instructions from arch. execution but keep them in memory as dead code for transient execution.
    if USE_MMU:
        va_layout = -1
    else:
        va_layout = None

    def __init__(self, fuzzerstate, instr_str,):
        assert fuzzerstate is not None
        self.fuzzerstate = fuzzerstate
        self.instr_str = instr_str
        if "c." in self.instr_str:
            self.iscompressed = True
        self.instr_func = INSTR_FUNCS[self.instr_str]

    def reset_addr(self):
        from milesan.spikeresolution import get_current_layout
        if not len(self.fuzzerstate.instr_objs_seq[0]): # This is the first instruction, special case.
            self.priv_level = PrivilegeStateEnum.MACHINE
            self.va_layout = -1
        else:
            if len(self.fuzzerstate.instr_objs_seq[-1]):
                last_instr = self.fuzzerstate.instr_objs_seq[-1][-1] # We need the layout from the previous instruction
            else: # In case it's the first instruction of a block.
                last_instr = self.fuzzerstate.instr_objs_seq[-2][-1] # We need the layout from the previous instruction
            self.va_layout, self.priv_level = get_current_layout(last_instr, last_instr.va_layout, last_instr.priv_level)
        if DO_ASSERT:
            assert self.priv_level is not None
            assert not (USE_MMU and self.va_layout is None)
            if self.va_layout == -1:
                assert not USE_MMU or self.priv_level == PrivilegeStateEnum.MACHINE, f"We need to be in machine mode to use bare translation when the MMU is enabled."
            if USE_MMU and self.priv_level == PrivilegeStateEnum.MACHINE:
                assert self.va_layout == -1,  f"Need to use bare translation when in MACHINE mode."
        # self.paddr = self.fuzzerstate.curr_bb_start_addr + 4*len(self.fuzzerstate.instr_objs_seq[-1]) + SPIKE_STARTADDR
        self.paddr = self.fuzzerstate.get_curr_paddr()
        if USE_MMU:
            self.vaddr = phys2virt(self.paddr, self.priv_level, self.va_layout,self.fuzzerstate,absolute_addr=False)
            self.fuzzerstate.add_page_domain(self.paddr, self.va_layout, self.priv_level)


        else:
            self.vaddr = None
            self.va_layout = -1
        if USE_MMU and DO_ASSERT:
            assert self.priv_level == PrivilegeStateEnum.MACHINE or self.priv_level in self.fuzzerstate.pagetablestate.ppn_leaf_to_priv_dict[(self.paddr&PAGE_ALIGNMENT_MASK)], f"{self.get_str()} cannot be stored in physical page reserved for {[p.name for p in self.fuzzerstate.pagetablestate.ppn_leaf_to_priv_dict[(self.paddr&PAGE_ALIGNMENT_MASK)]]} at page addr {hex(self.paddr&PAGE_ALIGNMENT_MASK)}."

    def print(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF):
        print(self.get_str(is_spike_resolution))

    def get_preamble(self):
        return f"({self.priv_level.name[0] if self.priv_level is not None else '?'}/{self.va_layout if self.va_layout is not None else '?'}): {hex(self.paddr) if self.paddr is not None else '?'}/{hex(self.vaddr) if self.vaddr is not None else '?'}"

    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = False):
        return f"{self.get_preamble()}: {self.instr_str}"

    def execute(self, is_spike_resolution: bool = True):
        raise Exception(f"Function execute() called on abstract class BaseInstruction {self.get_str(is_spike_resolution)}.")
 
    def check_regs(self,reg_cmp):
        for reg_id,reg_val in reg_cmp.items():
            if reg_id not in self.fuzzerstate.intregpickstate.regs:
                if PRINT_CHECK_REGS:
                    print(f"{self.get_preamble()}: Ignoring register value: {ABI_INAMES[reg_id]}")
                continue
            if PRINT_CHECK_REGS:
                print(f"{self.get_preamble()}: Checking register value: {ABI_INAMES[reg_id]}:{hex(reg_val)}")
            mismatch = self.fuzzerstate.intregpickstate.regs[reg_id].check(reg_val)
            assert not mismatch, f"{self.get_str()}: (Inst) Value mismatch for {ABI_INAMES[reg_id]}: {hex(mismatch[1])} != {hex(reg_val)}\n\t Traceback: {compute_reg_traceback(reg_id,self.paddr,self.fuzzerstate,reg_val).get_str()}"

    def assert_addr(self):
        if ASSERT_ADDR:
            if USE_MMU:
                assert self.vaddr == self.fuzzerstate.curr_pc, f"Instruction  vaddress does not match pc: {self.get_str()}, {hex(self.fuzzerstate.curr_pc)}"
            else:
                assert self.paddr == self.fuzzerstate.curr_pc, f"Instruction paddress does not match pc: {self.get_str()}, {hex(self.fuzzerstate.curr_pc)}"

class CFInstruction(BaseInstruction):
    # Could be any instruction
    authorized_instr_strs = range(len(INSTRUCTION_IDS))
    # Check that it's not a wrong instruction id.
    def assert_authorized_instr_strs(self):
        if DO_ASSERT:
            assert self.instr_str in self.__class__.authorized_instr_strs, f"{self.instr_str} is not authorized."

    def __init__(self, fuzzerstate, instr_str: str, iscompressed: bool = False):
        super().__init__(fuzzerstate,instr_str)
        self.assert_authorized_instr_strs()

    # @param is_spike_resolution: some rare instructions (typically offset management placeholders) are treated differently between spike resolution and the subsequent actual simulation.
    def gen_bytecode_int(self, is_spike_resolution: bool):
        raise ValueError('Cannot generate bytecode in the abstract instruction classes.')
    
    def log(self,curr_addr):
        if self.fuzzerstate is not None:
            print(f"{hex(curr_addr)}: {self.instr_str}: {self.fuzzerstate.intregpickstate.regs[self.rd].abi_name}:{hex(self.fuzzerstate.intregpickstate.regs[self.rd].get_val_bk())} <- {hex(self.fuzzerstate.intregpickstate.regs[self.rd].get_val())}")
        else:
            print(f"{hex(curr_addr)}: {self.instr_str}: (not tracked)")

# Any instruction with an immediate
class ImmInstruction(CFInstruction):
    # static
    authorized_instr_strs = ("lui", "auipc", "jal", "jalr", "beq", "bne", "blt", "bge", "bltu", "bgeu", "lb", "lh", "lw", "lbu", "lhu", "sb", "sh", "sw", "addi", "slti", "sltiu", "xori", "ori", "andi", "slli", "srli", "srai", "lwu", "ld", "sd", "addiw", "slliw", "srliw", "sraiw", "flw", "fsw", "fld", "fsd")
    authorized_instr_strs += ("c.lui","c.slli","c.srli","c.srai","c.andi")
    # Checks the immediate size.
    def assert_imm_size(self):
        # print(f"{PARAM_SIZES_BITS_64[INSTRUCTION_IDS[self.instr_str]][-1]}, {INSTRUCTION_IDS[self.instr_str]}, {self.instr_str}")
        if DO_ASSERT:
            assert hasattr(self, 'imm')
            if self.fuzzerstate.is_design_64bit:
                curr_param_size = PARAM_SIZES_BITS_64[INSTRUCTION_IDS[self.instr_str]][-1]
            else:
                curr_param_size = PARAM_SIZES_BITS_32[INSTRUCTION_IDS[self.instr_str]][-1]
            if PARAM_IS_SIGNED[INSTRUCTION_IDS[self.instr_str]][-1]:
                assert self.imm >= -(1<<(curr_param_size-1)), f"{hex(self.imm)} not within paramsize: (signed, {curr_param_size}): {self.instr_str}"
                assert self.imm <  1<<(curr_param_size-1),  f"{hex(self.imm)} not within paramsize: (signed, {curr_param_size}):  {self.instr_str}"
            else:
                assert self.imm >= 0, f"{hex(self.imm)} < 0: {self.instr_str}"
                assert self.imm <  1<<curr_param_size, f"{hex(self.imm)} not within paramsize: (unsigned, {curr_param_size}):  {self.instr_str}"

    def __init__(self, fuzzerstate, instr_str: str, imm: int, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, iscompressed)
        assert imm <= MAX_20b, "Immediate exceeds 20 bits."
        self.imm = imm
        self.assert_imm_size()


###
# Concrete classes: integers
###

# Instructions with rs1, rs2 and rd
R12DInstructions = ("add", "sub", "sll", "slt", "sltu", "xor", "srl", "sra", "or", "and", "addw", "subw", "sllw", "srlw", "sraw", "mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu", "mulw", "divw", "divuw", "remw", "remuw","c.and","c.or","c.xor","c.add","c.sub","c.mv","c.addw","c.subw")
class R12DInstruction(CFInstruction):
    authorized_instr_strs = R12DInstructions

    def __init__(self, fuzzerstate, instr_str: str, rd: int, rs1: int, rs2: int, iscompressed: bool = False, is_rd_nonpickable_ok: bool = False):
        super().__init__(fuzzerstate, instr_str, iscompressed)
        if DO_ASSERT:
            assert rs1 >= 0
            assert rs1 < MAX_NUM_PICKABLE_REGS or rs1 in NONPICKABLE_REGISTERS
            assert rs2 >= 0
            assert rs2 < MAX_NUM_PICKABLE_REGS or rs2 in NONPICKABLE_REGISTERS
            assert rd >= 0
            assert is_rd_nonpickable_ok and rd in NONPICKABLE_REGISTERS or rd < MAX_NUM_PICKABLE_REGS
        self.rs1 = rs1
        self.rs2 = rs2
        self.rd =  rd

    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = False):
        return f"{self.get_preamble()}: {self.instr_str} {ABI_INAMES[self.rd]}, {ABI_INAMES[self.rs1]}, {ABI_INAMES[self.rs2]}"

    def gen_bytecode_int(self, is_spike_resolution: bool):
        # rv32i
        if self.instr_str == "add":
            return rv32i_add(self.rd, self.rs1, self.rs2)
        elif self.instr_str == "sub":
            return rv32i_sub(self.rd, self.rs1, self.rs2)
        elif self.instr_str == "sll":
            return rv32i_sll(self.rd, self.rs1, self.rs2)
        elif self.instr_str == "slt":
            return rv32i_slt(self.rd, self.rs1, self.rs2)
        elif self.instr_str == "sltu":
            return rv32i_sltu(self.rd, self.rs1, self.rs2)
        elif self.instr_str == "xor":
            return rv32i_xor(self.rd, self.rs1, self.rs2)
        elif self.instr_str == "srl":
            return rv32i_srl(self.rd, self.rs1, self.rs2)
        elif self.instr_str == "sra":
            return rv32i_sra(self.rd, self.rs1, self.rs2)
        elif self.instr_str == "or":
            return rv32i_or(self.rd, self.rs1, self.rs2)
        elif self.instr_str == "and":
            return rv32i_and(self.rd, self.rs1, self.rs2)
        # rv64i
        elif self.instr_str == "addw":
            return rv64i_addw(self.rd, self.rs1, self.rs2)
        elif self.instr_str == "subw":
            return rv64i_subw(self.rd, self.rs1, self.rs2)
        elif self.instr_str == "sllw":
            return rv64i_sllw(self.rd, self.rs1, self.rs2)
        elif self.instr_str == "srlw":
            return rv64i_srlw(self.rd, self.rs1, self.rs2)
        elif self.instr_str == "sraw":
            return rv64i_sraw(self.rd, self.rs1, self.rs2)
        # rv32m
        elif self.instr_str == "mul":
            return rv32m_mul(self.rd, self.rs1, self.rs2)
        elif self.instr_str == "mulh":
            return rv32m_mulh(self.rd, self.rs1, self.rs2)
        elif self.instr_str == "mulhsu":
            return rv32m_mulhsu(self.rd, self.rs1, self.rs2)
        elif self.instr_str == "mulhu":
            return rv32m_mulhu(self.rd, self.rs1, self.rs2)
        elif self.instr_str == "div":
            return rv32m_div(self.rd, self.rs1, self.rs2)
        elif self.instr_str == "divu":
            return rv32m_divu(self.rd, self.rs1, self.rs2)
        elif self.instr_str == "rem":
            return rv32m_rem(self.rd, self.rs1, self.rs2)
        elif self.instr_str == "remu":
            return rv32m_remu(self.rd, self.rs1, self.rs2)
        # rv64m
        elif self.instr_str == "mulw":
            return rv64m_mulw(self.rd, self.rs1, self.rs2)
        elif self.instr_str == "divw":
            return rv64m_divw(self.rd, self.rs1, self.rs2)
        elif self.instr_str == "divuw":
            return rv64m_divuw(self.rd, self.rs1, self.rs2)
        elif self.instr_str == "remw":
            return rv64m_remw(self.rd, self.rs1, self.rs2)
        elif self.instr_str == "remuw":
            return rv64m_remuw(self.rd, self.rs1, self.rs2)
        # rv32ic
        elif self.instr_str == "c.mv":
            return rv32ic_mv(self.rd, self.rs2)
        elif self.instr_str == "c.add":
            return rv32ic_add(self.rd, self.rs2)
        elif self.instr_str == "c.and":
            return rv32ic_and(self.rd, self.rs2)
        elif self.instr_str == "c.or":
            return rv32ic_or(self.rd, self.rs2)
        elif self.instr_str == "c.xor":
            return rv32ic_xor(self.rd, self.rs2)
        elif self.instr_str == "c.sub":
            return rv32ic_sub(self.rd, self.rs2)
        # rv64ic
        elif self.instr_str == "c.addw":
            return rv64ic_addw(self.rd, self.rs2)
        elif self.instr_str == "c.subw":
            return rv64ic_subw(self.rd, self.rs2)

        # Default case
        else:
            raise ValueError(f"Unexpected instruction string: `{self.instr_str}`.")

    def set_bytecode(self, bytecode):
        self.rs1 = (bytecode>>OPCODE_FIELD_BITS["rs1"])&OPCODE_FIELD_MASKS["rs"]
        self.rs2 = (bytecode>>OPCODE_FIELD_BITS["rs2"])&OPCODE_FIELD_MASKS["rs"]
        self.rd =  (bytecode>>OPCODE_FIELD_BITS["rd"])&OPCODE_FIELD_MASKS["rd"]

    
# Instructions with imm and rd
ImmRdInstructions = ("lui", "auipc", "c.lui")
class ImmRdInstruction(ImmInstruction):
    authorized_instr_strs = ImmRdInstructions

    def __init__(self, fuzzerstate, instr_str: str, rd: int, imm: int, iscompressed: bool = False, is_rd_nonpickable_ok: bool = False):
        super().__init__(fuzzerstate, instr_str, imm, iscompressed)
        if DO_ASSERT:
            assert rd >= 0
            assert is_rd_nonpickable_ok and rd in NONPICKABLE_REGISTERS or rd < MAX_NUM_PICKABLE_REGS, f"{rd} not in NONPICKABLE_REGISTERS " if is_rd_nonpickable_ok else f"{rd} > MAX_NUM_PICKABLE_REGS ({MAX_NUM_PICKABLE_REGS})"
        self.rd =  rd

    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = False):
        return f"{self.get_preamble()}: {self.instr_str} {ABI_INAMES[self.rd]}, {hex(self.imm)}"

    def gen_bytecode_int(self, is_spike_resolution: bool):

        # rv32i
        if self.instr_str == "lui":
            return rv32i_lui(self.rd, self.imm)
        elif self.instr_str == "auipc":
            return rv32i_auipc(self.rd, self.imm)
        #rv32ic
        elif self.instr_str == "c.lui":
            return rv32ic_lui(self.rd, self.imm)
        # Default case
        else:
            raise ValueError(f"Unexpected instruction string: `{self.instr_str}`.")

    def set_bytecode(self, bytecode):
        self.imm = (bytecode>>OPCODE_FIELD_BITS["immu"])&OPCODE_FIELD_MASKS["immu"]
        self.rd =  (bytecode>>OPCODE_FIELD_BITS["rd"])&OPCODE_FIELD_MASKS["rd"]


# Instructions with rs1, imm and rd
RegImmInstructions = ("addi", "slti", "sltiu", "xori", "ori", "andi", "slli", "srli", "srai") # base
RegImmInstructions += ("addiw", "slliw", "srliw", "sraiw") # w-extension
RegImmInstructions += ("c.addi","c.li","c.addi16sp","c.addi4spn","c.slli","c.srli","c.srai","c.andi", "c.addiw") # compressed
RegImmShiftInstructions = ("slli", "srli", "srai", "slliw", "srliw", "sraiw", "c.slli","c.srli","c.srai")
class RegImmInstruction(ImmInstruction):
    authorized_instr_strs = RegImmInstructions

    def __init__(self, fuzzerstate, instr_str: str, rd: int, rs1: int, imm: int, iscompressed: bool = False, is_rd_nonpickable_ok: bool = False):
        super().__init__(fuzzerstate, instr_str, imm, iscompressed)
        if DO_ASSERT:
            assert rs1 >= 0
            assert rs1 < MAX_NUM_PICKABLE_REGS or rs1 in NONPICKABLE_REGISTERS
            assert rd >= 0
            assert is_rd_nonpickable_ok and rd in NONPICKABLE_REGISTERS or rd < MAX_NUM_PICKABLE_REGS
        self.rs1 = rs1
        self.rd =  rd

        if self.instr_str == "sraiw" and self.imm < 0:
            assert False
        
    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = False):
        return f"{self.get_preamble()}: {self.instr_str} {ABI_INAMES[self.rd]}, {ABI_INAMES[self.rs1]}, {hex(self.imm)}"

    def set_bytecode(self,bytecode):
        has_shamt = self.instr_str in RegImmShiftInstructions
        self.rs1 = (bytecode>>15)&0x1F
        self.imm = (bytecode>>20)&(0xFFF if not has_shamt else 0x1F)
        self.rd =  (bytecode>>7)&0x1F

    def gen_bytecode_int(self, is_spike_resolution: bool):
        # rv32i
        if self.instr_str == "addi":
            return rv32i_addi(self.rd, self.rs1, self.imm)
        elif self.instr_str == "slti":
            return rv32i_slti(self.rd, self.rs1, self.imm)
        elif self.instr_str == "sltiu":
            return rv32i_sltiu(self.rd, self.rs1, self.imm)
        elif self.instr_str == "xori":
            return rv32i_xori(self.rd, self.rs1, self.imm)
        elif self.instr_str == "ori":
            return rv32i_ori(self.rd, self.rs1, self.imm)
        elif self.instr_str == "andi":
            return rv32i_andi(self.rd, self.rs1, self.imm)
        elif self.instr_str == "slli":
            return rv32i_slli(self.rd, self.rs1, self.imm)
        elif self.instr_str == "srli":
            return rv32i_srli(self.rd, self.rs1, self.imm)
        elif self.instr_str == "srai":
            return rv32i_srai(self.rd, self.rs1, self.imm)
        # rv64i
        elif self.instr_str == "addiw":
            return rv64i_addiw(self.rd, self.rs1, self.imm)
        elif self.instr_str == "slliw":
            return rv64i_slliw(self.rd, self.rs1, self.imm)
        elif self.instr_str == "srliw":
            return rv64i_srliw(self.rd, self.rs1, self.imm)
        elif self.instr_str == "sraiw":
            return rv64i_sraiw(self.rd, self.rs1, self.imm)
        #rv32ic
        elif self.instr_str == "c.addi16sp":
            return rv32ic_addi16sp(self.rd, self.imm)
        elif self.instr_str == "c.addi4spn":
            return rv32ic_addi4spn(self.rd, self.imm)
        elif self.instr_str == "c.addi":
            return rv32ic_addi(self.rd, self.imm)
        elif self.instr_str == "c.li":
            return rv32ic_li(self.rd, self.imm)
        elif self.instr_str == "c.slli":
            return rv32ic_slli(self.rd, self.imm)
        elif self.instr_str == "c.andi":
            return rv32ic_andi(self.rs1, self.imm)
        elif self.instr_str == "c.srli":
            return rv32ic_srli(self.rs1, self.imm)
        elif self.instr_str == "c.srai":
            return rv32ic_srai(self.rs1, self.imm)
        #rv64ic
        elif self.instr_str == "c.addiw":
            return rv64ic_addiw(self.rd, self.imm)

        # Default case
        else:
            raise ValueError(f"Unexpected instruction string: `{self.instr_str}`.")

# Branch instructions: with rs1, rs2 and an immediate
BranchInstructions = ("beq", "bne", "blt", "bge", "bltu", "bgeu")
BranchInstructionsCompressed = ("c.beqz", "c.bnez") #this should not be part of the random choices
class BranchInstruction(ImmInstruction):
    authorized_instr_strs = BranchInstructions + BranchInstructionsCompressed

    # @param plan_taken is True iff the branch instruction is planned to be taken.
    def __init__(self, fuzzerstate, instr_str: str, rs1: int, rs2: int, imm: int, plan_taken: bool, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, imm, iscompressed)
        if DO_ASSERT:
            assert rs1 >= 0
            assert rs1 < MAX_NUM_PICKABLE_REGS
            assert rs2 >= 0
            assert rs2 < MAX_NUM_PICKABLE_REGS

        self.rs1 = rs1
        self.rs2 = rs2
        self.plan_taken = plan_taken

    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = False):
        return f"{self.get_preamble()}: {self.instr_str} {ABI_INAMES[self.rs1]}, {ABI_INAMES[self.rs2]}, {hex(self.imm)}"

    # Choose an opcode that, given the values of rs1 and rs2, will comply with the required takenness
    def select_suitable_opcode(self, rs1_content: int, rs2_content: int):
        int_plan_taken = int(self.plan_taken)
        can_take_opcodes = [
            # beq
            int_plan_taken ^ int(rs1_content != rs2_content),
            # bne
            int_plan_taken ^ int(rs1_content == rs2_content),
            # blt
            int_plan_taken ^ int(twos_complement(rs1_content, self.fuzzerstate.is_design_64bit) >= twos_complement(rs2_content, self.fuzzerstate.is_design_64bit)),
            # bge
            int_plan_taken ^ int(twos_complement(rs1_content, self.fuzzerstate.is_design_64bit) < twos_complement(rs2_content, self.fuzzerstate.is_design_64bit)),
            # bltu
            int_plan_taken ^ int(rs1_content >= rs2_content),
            # bgeu
            int_plan_taken ^ int(rs1_content < rs2_content),
        ]

        self.instr_str = random.choices(BranchInstructions, can_take_opcodes, k=1)[0]
        if USE_COMPRESSED and self.iscompressed:
            if self.plan_taken:
                if rs1_content == 0:
                    #print(f"chose {self.instr_str}, taken = {self.plan_taken} with rs1 = {rs1_content} rs2 = {rs2_content}, so we use c.beqz")
                    self.instr_str = "c.beqz"
                else:
                    #print(f"chose {self.instr_str}, taken = {self.plan_taken} with rs1 = {rs1_content} rs2 = {rs2_content}, so we use c.bnez")
                    self.instr_str = "c.bnez"
            else:
                if rs1_content == 0:
                    #print(f"chose {self.instr_str}, taken = {self.plan_taken} with rs1 = {rs1_content} rs2 = {rs2_content}, so we use c.bnez")
                    self.instr_str = "c.bnez"
                else:
                    #print(f"chose {self.instr_str}, taken = {self.plan_taken} with rs1 = {rs1_content} rs2 = {rs2_content}, so we use c.beqz")
                    self.instr_str = "c.beqz"


    def gen_bytecode_int(self, is_spike_resolution: bool):
        if is_spike_resolution:
            if self.plan_taken:
                if self.iscompressed:
                    return rv32ic_j(self.imm) # Just unconditionally jump to the next basic block, need compressed
                else:
                    return rv32i_jal(0, self.imm) # Just unconditionally jump to the next basic block
            else:
                if self.iscompressed:
                    return rv32ic_addi(0, 0) # c.nop
                else:
                    return rv32i_addi(0, 0, 0) # Nop
        else:
            # rv32i
            if self.instr_str == "beq":
                return rv32i_beq(self.rs1, self.rs2, self.imm)
            elif self.instr_str == "bne":
                return rv32i_bne(self.rs1, self.rs2, self.imm)
            elif self.instr_str == "blt":
                return rv32i_blt(self.rs1, self.rs2, self.imm)
            elif self.instr_str == "bge":
                return rv32i_bge(self.rs1, self.rs2, self.imm)
            elif self.instr_str == "bltu":
                return rv32i_bltu(self.rs1, self.rs2, self.imm)
            elif self.instr_str == "bgeu":
                return rv32i_bgeu(self.rs1, self.rs2, self.imm)
            #rv32ic
            elif self.instr_str == "c.beqz":
                return rv32ic_beqz(self.rs1, self.imm)
            elif self.instr_str == "c.bnez":
                return rv32ic_bnez(self.rs1, self.imm)
            # Default case
            else:
                raise ValueError(f"Unexpected instruction string: `{self.instr_str}`.")

# The jal instruction
JALInstructions = ("jal","c.jal","c.j")
class JALInstruction(ImmInstruction):
    authorized_instr_strs = JALInstructions

    def __init__(self, fuzzerstate, instr_str: str, rd: int, imm: int, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, imm, iscompressed)
        
        if DO_ASSERT:
            assert rd >= 0
            assert rd < MAX_NUM_PICKABLE_REGS
        self.rd  = rd

    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = False):
        return f"{self.get_preamble()}: {self.instr_str} {ABI_INAMES[self.rd]}, {hex(self.imm)}"

    def gen_bytecode_int(self, is_spike_resolution: bool):
        # rv32i
        if self.instr_str == "jal":
            return rv32i_jal(self.rd, self.imm)
        #rv32ic
        elif self.instr_str == "c.jal":
            return rv32ic_jal(self.imm)
        elif self.instr_str == "c.j":
            return rv32ic_j(self.imm)
        # Default case
        else:
            raise ValueError(f"Unexpected instruction string: `{self.instr_str}`.")




# The jalr instruction
JALRInstructions = ("jalr","c.jalr","c.jr")
class JALRInstruction(ImmInstruction):
    authorized_instr_strs = JALRInstructions

    def __init__(self, fuzzerstate, instr_str: str, rd: int, rs1: int, imm: int, producer_id: int, to_new_layout: bool = False, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, imm, iscompressed)
        
        if DO_ASSERT:
            assert rd >= 0
            assert rd < MAX_NUM_PICKABLE_REGS
            assert rs1 >= 0
            assert rs1 < MAX_NUM_PICKABLE_REGS
        self.rd  = rd
        self.rs1 = rs1
        self.producer_id = producer_id
        self.to_new_layout = to_new_layout
        self.va_layout_after_op = fuzzerstate.target_layout
            
    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = False):
        return f"{self.get_preamble()}: {self.instr_str} {ABI_INAMES[self.rd]}, {ABI_INAMES[self.rs1]}, {hex(self.imm)}"


    def reset_addr(self):
        super().reset_addr()
        if DO_ASSERT:
            assert not FENCE_CF_INSTR or len(self.fuzzerstate.instr_objs_seq[-1]) == 0 or "fence" in self.fuzzerstate.instr_objs_seq[-1][-1].instr_str, f"{self.get_str()} not fenced."


    def gen_bytecode_int(self, is_spike_resolution: bool):
        # rv32i
        if self.instr_str == "jalr":
            return rv32i_jalr(self.rd, self.rs1, self.imm)
        #rv32ic
        elif self.instr_str == "c.jr":
            return rv32ic_jr(self.rs1)
        elif self.instr_str == "c.jalr":
            return rv32ic_jalr(self.rs1)
        # Default case
        else:
            raise ValueError(f"Unexpected instruction string: `{self.instr_str}`.")


# Instructions that create no (explicit) information flow
SpecialInstructions = ("fence", "fence.i", "sfence.vma")
class SpecialInstruction(CFInstruction):
    authorized_instr_strs = SpecialInstructions

    def __init__(self, fuzzerstate, instr_str: str, rd: int = 0, rs1: int = 0, rs2: int = 0, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, iscompressed)
        self.rd = rd
        self.rs1 = rs1
        self.rs2 = rs2

    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = False):
        return f"{self.get_preamble()}: {self.instr_str} {ABI_INAMES[self.rd]}, {ABI_INAMES[self.rs1]}"

    def gen_bytecode_int(self, is_spike_resolution: bool):
        # rv32i
        if self.instr_str == "fence":
            return rv32i_fence(self.rd, self.rs1)
        # zifencei
        elif self.instr_str == "fence.i":
            return zifencei_fencei(self.rd, self.rs1)
        elif self.instr_str == "sfence.vma":
            return rv32i_sfencevma(self.rs1, self.rs2)
        # Default case
        else:
            raise ValueError(f"Unexpected instruction string: `{self.instr_str}`.")

EcallEbreakInstructions = ("ecall", "ebreak")
class EcallEbreakInstruction(CFInstruction):
    authorized_instr_strs = EcallEbreakInstructions

    def __init__(self, fuzzerstate, instr_str: str, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, iscompressed)

    def gen_bytecode_int(self, is_spike_resolution: bool):
        # rv32i
        if self.instr_str == "ecall":
            return rv32i_ecall()
        elif self.instr_str == "ebreak":
            return rv32i_ebreak()
        # Default case
        else:
            raise ValueError(f"Unexpected instruction string: `{self.instr_str}`.")


# Integer load instructions
IntLoadInstructions = ("lb", "lh", "lw", "lbu", "lhu", "lwu", "ld", "c.lwsp","c.lw","c.ldsp","c.ld")
class IntLoadInstruction(ImmInstruction):
    authorized_instr_strs = IntLoadInstructions

    def __init__(self, fuzzerstate, instr_str: str, rd: int, rs1: int, imm: int, producer_id: int, iscompressed: bool = False, is_rd_nonpickable_ok: bool = False):
        super().__init__(fuzzerstate, instr_str, imm, iscompressed)
    
        if DO_ASSERT:
            assert rd >= 0
            assert rs1 >= 0
            assert is_rd_nonpickable_ok and rd in NONPICKABLE_REGISTERS or rd < MAX_NUM_PICKABLE_REGS
        self.rd  = rd
        self.rs1 =  rs1
        self.producer_id = producer_id

    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = False):
        return f"{self.get_preamble()}: {self.instr_str} {ABI_INAMES[self.rd]}, {self.imm}({ABI_INAMES[self.rs1]}) "

    def gen_bytecode_int(self, is_spike_resolution: bool):
        # rv32i
        if self.instr_str == "lb":
            return rv32i_lb(self.rd, self.rs1, self.imm)
        elif self.instr_str == "lh":
            return rv32i_lh(self.rd, self.rs1, self.imm)
        elif self.instr_str == "lw":
            return rv32i_lw(self.rd, self.rs1, self.imm)
        elif self.instr_str == "lbu":
            return rv32i_lbu(self.rd, self.rs1, self.imm)
        elif self.instr_str == "lhu":
            return rv32i_lhu(self.rd, self.rs1, self.imm)
        # rv64i
        elif self.instr_str == "lwu":
            return rv64i_lwu(self.rd, self.rs1, self.imm)
        elif self.instr_str == "ld":
            return rv64i_ld(self.rd, self.rs1, self.imm)
        # rv32ic
        elif self.instr_str == "c.lwsp":
            return rv32ic_lwsp(self.rd, self.imm)
        elif self.instr_str == "c.lw":
            return rv32ic_lw(self.rd, self.rs1, self.imm)
        # rv64ic
        elif self.instr_str == "c.ldsp":
            return rv64ic_ldsp(self.rd, self.imm)
        elif self.instr_str == "c.ld":
            return rv64ic_ld(self.rd, self.rs1, self.imm)
        # Default case
        else:
            raise ValueError(f"Unexpected instruction string: `{self.instr_str}`.")

# Integer store instructions
IntStoreInstructions = ("sb", "sh", "sw", "sd","c.swsp","c.sw","c.sdsp","c.sd")
class IntStoreInstruction(ImmInstruction):
    authorized_instr_strs = IntStoreInstructions

    def __init__(self, fuzzerstate, instr_str: str, rs1: int, rs2: int, imm: int, producer_id: int, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, imm, iscompressed)
        
        if DO_ASSERT:
            assert rs1 >= 0
            assert rs1 < MAX_NUM_PICKABLE_REGS or rs1 in NONPICKABLE_REGISTERS
            assert rs2 >= 0
            assert rs2 < MAX_NUM_PICKABLE_REGS or rs2 in NONPICKABLE_REGISTERS
        self.rs1 =  rs1
        self.rs2  = rs2
        self.producer_id = producer_id
        
    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = False):
        return f"{self.get_preamble()}: {self.instr_str} {ABI_INAMES[self.rs2]}, {self.imm}({ABI_INAMES[self.rs1]})"

    def gen_bytecode_int(self, is_spike_resolution: bool):
        # rv32i
        if self.instr_str == "sb":
            return rv32i_sb(self.rs1, self.rs2, self.imm)
        elif self.instr_str == "sh":
            return rv32i_sh(self.rs1, self.rs2, self.imm)
        elif self.instr_str == "sw":
            return rv32i_sw(self.rs1, self.rs2, self.imm)
        # rv64i
        elif self.instr_str == "sd":
            return rv64i_sd(self.rs1, self.rs2, self.imm)
        #rv32ic
        elif self.instr_str == "c.sw":
            return rv32ic_sw(self.rs1, self.rs2, self.imm)
        elif self.instr_str == "c.swsp":
            return rv32ic_swsp(self.rs2, self.imm)
        #rv64ic
        elif self.instr_str == "c.sd":
            return rv64ic_sd(self.rs1, self.rs2, self.imm)
        elif self.instr_str == "c.sdsp":
            return rv64ic_sdsp(self.rs2, self.imm)
        # Default case
        else:
            raise ValueError(f"Unexpected instruction string: `{self.instr_str}`.")


class RegdumpInstruction(IntStoreInstruction):
    def gen_bytecode_int(self, is_spike_resolution: bool):
        if is_spike_resolution:
            return rv32i_addi(0x0,0x0,0x0) # Return nop for spike resolution
        else:
            return super().gen_bytecode_int(is_spike_resolution)

    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = False):
        if not is_spike_resolution:
            return f"{self.get_preamble()}: {self.instr_str} {ABI_INAMES[self.rs2]}, {self.imm}({ABI_INAMES[self.rs1]})"
        else:
            return f"{self.get_preamble()}: nop"


###
# Floating-point
###

# Float load instructions
FloatLoadInstructions = ("flw", "fld")
class FloatLoadInstruction(ImmInstruction):
    authorized_instr_strs = FloatLoadInstructions

    def __init__(self, fuzzerstate, instr_str: str, frd: int, rs1: int, imm: int, producer_id: int, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, imm, iscompressed)
        raise NotImplementedError
        if DO_ASSERT:
            assert frd >= 0
            assert frd < MAX_NUM_PICKABLE_REGS
            assert rs1 >= 0
            assert rs1 < MAX_NUM_PICKABLE_REGS
        self.frd  = frd
        self.rs1 =  rs1
        self.producer_id = producer_id

    def gen_bytecode_int(self, is_spike_resolution: bool):
        # rv32f
        if self.instr_str == "flw":
            return rv32f_flw(self.frd, self.rs1, self.imm)
        # rv32d
        elif self.instr_str == "fld":
            return rv32d_fld(self.frd, self.rs1, self.imm)
        # Default case
        else:
            raise ValueError(f"Unexpected instruction string: `{self.instr_str}`.")

# Float store instructions
FloatStoreInstructions = ("fsw", "fsd")
class FloatStoreInstruction(ImmInstruction):
    authorized_instr_strs = FloatStoreInstructions

    def __init__(self, fuzzerstate, instr_str: str, rs1: int, frs2: int, imm: int, producer_id: int, iscompressed: bool = False):        
        super().__init__(fuzzerstate, instr_str, imm, iscompressed)
        raise NotImplementedError

        if DO_ASSERT:
            assert rs1 >= 0
            assert rs1 < MAX_NUM_PICKABLE_REGS or rs1 in (RELOCATOR_REGISTER_ID, RDEP_MASK_REGISTER_ID)
            assert frs2 >= 0
            assert frs2 < MAX_NUM_PICKABLE_REGS
        self.rs1  =  rs1
        self.frs2 = frs2
        self.producer_id = producer_id

    def gen_bytecode_int(self, is_spike_resolution: bool):
        # rv32f
        if self.instr_str == "fsw":
            return rv32f_fsw(self.rs1, self.frs2, self.imm)
        # rv32d
        elif self.instr_str == "fsd":
            return rv32d_fsd(self.rs1, self.frs2, self.imm)
        # Default case
        else:
            raise ValueError(f"Unexpected instruction string: `{self.instr_str}`.")

# Float to int instructions
FloatToIntInstructions = ("fcvt.w.s", "fcvt.wu.s", "fcvt.l.s", "fcvt.lu.s", "fcvt.w.d", "fcvt.wu.d", "fcvt.l.d", "fcvt.lu.d")
class FloatToIntInstruction(CFInstruction):
    authorized_instr_strs = FloatToIntInstructions

    def __init__(self, fuzzerstate, instr_str: str, rd: int, frs1: int, rm: int, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, iscompressed)
        raise NotImplementedError

        if DO_ASSERT:
            assert rm >= 0
            assert rm < MAX_NUM_PICKABLE_REGS
            assert frs1 >= 0
            assert frs1 < MAX_NUM_PICKABLE_REGS
            assert rd >= 0
            assert rd < MAX_NUM_PICKABLE_REGS
        self.rm   = rm
        self.frs1 = frs1
        self.rd   = rd

    def set_bytecode(self, bytecode):
        self.frs1 = (bytecode>>15)&0x1F
        self.rm = (bytecode>>12)&0x7
        self.rd =  (bytecode>>7)&0x1F

    def gen_bytecode_int(self, is_spike_resolution: bool):
        # rv32f
        if self.instr_str == "fcvt.w.s":
            return rv32f_fcvtws(self.rd, self.frs1, self.rm)
        elif self.instr_str == "fcvt.wu.s":
            return rv32f_fcvtwus(self.rd, self.frs1, self.rm)
        # rv64f
        elif self.instr_str == "fcvt.l.s":
            return rv64f_fcvtls(self.rd, self.frs1, self.rm)
        elif self.instr_str == "fcvt.lu.s":
            return rv64f_fcvtlus(self.rd, self.frs1, self.rm)
        # rv32d
        elif self.instr_str == "fcvt.w.d":
            return rv32d_fcvtwd(self.rd, self.frs1, self.rm)
        # rv32d
        elif self.instr_str == "fcvt.wu.d":
            return rv32d_fcvtwud(self.rd, self.frs1, self.rm)
        # rv64d
        elif self.instr_str == "fcvt.l.d":
            return rv64d_fcvtld(self.rd, self.frs1, self.rm)
        elif self.instr_str == "fcvt.lu.d":
            return rv64d_fcvtlud(self.rd, self.frs1, self.rm)
        # Default case
        else:
            raise ValueError(f"Unexpected instruction string: `{self.instr_str}`.")

# Int to float instructions
IntToFloatInstructions = ("fcvt.s.w", "fcvt.s.wu", "fcvt.s.l", "fcvt.s.lu", "fcvt.d.w", "fcvt.d.wu", "fcvt.d.l", "fcvt.d.lu")
class IntToFloatInstruction(CFInstruction):
    authorized_instr_strs = IntToFloatInstructions

    def __init__(self, fuzzerstate, instr_str: str, frd: int, rs1: int, rm: int, iscompressed: bool = False):
        super().__init__(fuzzerstate,instr_str, iscompressed)
        raise NotImplementedError
        if DO_ASSERT:
            assert rm >= 0
            assert rm < 8
            assert rs1 >= 0
            assert rs1 < MAX_NUM_PICKABLE_REGS
            assert frd >= 0
            assert frd < MAX_NUM_PICKABLE_REGS
        self.rs1 = rs1
        self.frd = frd
        self.rm  = rm

    def set_bytecode(self, bytecode):
        self.rs1 = (bytecode>>15)&0x1F
        self.rm = (bytecode>>12)&0x7
        self.frd =  (bytecode>>7)&0x1F

    def gen_bytecode_int(self, is_spike_resolution: bool):
        # rv32f
        if self.instr_str == "fcvt.s.w":
            return rv32f_fcvtsw(self.frd, self.rs1, self.rm)
        elif self.instr_str == "fcvt.s.wu":
            return rv32f_fcvtswu(self.frd, self.rs1, self.rm)
        # rv64f
        elif self.instr_str == "fcvt.s.l":
            return rv64f_fcvtsl(self.frd, self.rs1, self.rm)
        elif self.instr_str == "fcvt.s.lu":
            return rv64f_fcvtslu(self.frd, self.rs1, self.rm)
        # rv32d
        elif self.instr_str == "fcvt.d.w":
            return rv32d_fcvtdw(self.frd, self.rs1, self.rm)
        elif self.instr_str == "fcvt.d.wu":
            return rv32d_fcvtdwu(self.frd, self.rs1, self.rm)
        # rv64d
        elif self.instr_str == "fcvt.d.l":
            return rv64d_fcvtdl(self.frd, self.rs1, self.rm)
        elif self.instr_str == "fcvt.d.lu":
            return rv64d_fcvtdlu(self.frd, self.rs1, self.rm)
        # Default case
        else:
            raise ValueError(f"Unexpected instruction string: `{self.instr_str}`.")

# Pure float instructions with frs1, frs2, frs3 and frd
Float4Instructions = ("fmadd.s", "fmsub.s", "fnmsub.s", "fnmadd.s", "fmadd.d", "fmsub.d", "fnmsub.d", "fnmadd.d")
class Float4Instruction(CFInstruction):
    authorized_instr_strs = Float4Instructions

    def __init__(self, fuzzerstate, instr_str: str, frd: int, frs1: int, frs2: int, frs3: int, rm: int, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, iscompressed)
        raise NotImplementedError
        if DO_ASSERT:
            assert rm >= 0
            assert rm < 8
            assert frs1 >= 0
            assert frs1 < MAX_NUM_PICKABLE_REGS
            assert frs2 >= 0
            assert frs2 < MAX_NUM_PICKABLE_REGS
            assert frs3 >= 0
            assert frs3 < MAX_NUM_PICKABLE_REGS
            assert frd >= 0
            assert frd < MAX_NUM_PICKABLE_REGS
        self.rm   = rm
        self.frs1 = frs1
        self.frs2 = frs2
        self.frs3 = frs3
        self.frd  = frd

    def set_bytecode(self, bytecode):
        self.frs1 = (bytecode>>15)&0x1F
        self.frs2 = (bytecode>>20)&0x1F
        self.frs3 = (bytecode>>27)&0x1F
        self.rm = (bytecode>>12)&0x7
        self.frd =  (bytecode>>7)&0x1F

    def gen_bytecode_int(self, is_spike_resolution: bool):
        # rv32f
        if self.instr_str == "fmadd.s":
            return rv32f_fmadds(self.frd, self.frs1, self.frs2, self.frs3, self.rm)
        elif self.instr_str == "fmsub.s":
            return rv32f_fmsubs(self.frd, self.frs1, self.frs2, self.frs3, self.rm)
        elif self.instr_str == "fnmsub.s":
            return rv32f_fnmsubs(self.frd, self.frs1, self.frs2, self.frs3, self.rm)
        elif self.instr_str == "fnmadd.s":
            return rv32f_fnmadds(self.frd, self.frs1, self.frs2, self.frs3, self.rm)
        # rv32d
        elif self.instr_str == "fmadd.d":
            return rv32d_fmaddd(self.frd, self.frs1, self.frs2, self.frs3, self.rm)
        elif self.instr_str == "fmsub.d":
            return rv32d_fmsubd(self.frd, self.frs1, self.frs2, self.frs3, self.rm)
        elif self.instr_str == "fnmsub.d":
            return rv32d_fnmsubd(self.frd, self.frs1, self.frs2, self.frs3, self.rm)
        elif self.instr_str == "fnmadd.d":
            return rv32d_fnmaddd(self.frd, self.frs1, self.frs2, self.frs3, self.rm)
        # Default case
        else:
            raise ValueError(f"Unexpected instruction string: `{self.instr_str}`.")


# Pure float instructions with frs1, frs2 and frd
Float3Instructions = ("fadd.s", "fsub.s", "fmul.s", "fdiv.s", "fadd.d", "fsub.d", "fmul.d", "fdiv.d")
class Float3Instruction(CFInstruction):
    authorized_instr_strs = Float3Instructions

    def __init__(self, fuzzerstate, instr_str: str, frd: int, frs1: int, frs2: int, rm: int, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, iscompressed)
        raise NotImplementedError
        if DO_ASSERT:
            assert rm >= 0
            assert rm < 8
            assert frs1 >= 0
            assert frs1 < MAX_NUM_PICKABLE_REGS
            assert frs2 >= 0
            assert frs2 < MAX_NUM_PICKABLE_REGS
            assert frd >= 0
            assert frd < MAX_NUM_PICKABLE_REGS
        self.rm   = rm
        self.frs1 = frs1
        self.frs2 = frs2
        self.frd  = frd

    def set_bytecode(self, bytecode):
        self.frs1 = (bytecode>>15)&0x1F
        self.frs2 = (bytecode>>20)&0x1F
        self.rm = (bytecode>>12)&0x7
        self.frd =  (bytecode>>7)&0x1F

    def gen_bytecode_int(self, is_spike_resolution: bool):
        # rv32f
        if self.instr_str == "fadd.s":
            return rv32f_fadds(self.frd, self.frs1, self.frs2, self.rm)
        elif self.instr_str == "fsub.s":
            return rv32f_fsubs(self.frd, self.frs1, self.frs2, self.rm)
        elif self.instr_str == "fmul.s":
            return rv32f_fmuls(self.frd, self.frs1, self.frs2, self.rm)
        elif self.instr_str == "fdiv.s":
            return rv32f_fdivs(self.frd, self.frs1, self.frs2, self.rm)
        # rv32d
        elif self.instr_str == "fadd.d":
            return rv32d_faddd(self.frd, self.frs1, self.frs2, self.rm)
        elif self.instr_str == "fsub.d":
            return rv32d_fsubd(self.frd, self.frs1, self.frs2, self.rm)
        elif self.instr_str == "fmul.d":
            return rv32d_fmuld(self.frd, self.frs1, self.frs2, self.rm)
        elif self.instr_str == "fdiv.d":
            return rv32d_fdivd(self.frd, self.frs1, self.frs2, self.rm)
        # Default case
        else:
            raise ValueError(f"Unexpected instruction string: `{self.instr_str}`.")


# Pure float instructions with frs1, frs2 and frd
Float3NoRmInstructions = ("fsgnj.s", "fsgnjn.s", "fsgnjx.s", "fmin.s", "fmax.s", "fsgnj.d", "fsgnjn.d", "fsgnjx.d", "fmin.d", "fmax.d")
class Float3NoRmInstruction(CFInstruction):
    authorized_instr_strs = Float3NoRmInstructions

    def __init__(self, fuzzerstate, instr_str: str, frd: int, frs1: int, frs2: int, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, iscompressed)
        raise NotImplementedError

        if DO_ASSERT:
            assert frs1 >= 0
            assert frs1 < MAX_NUM_PICKABLE_REGS
            assert frs2 >= 0
            assert frs2 < MAX_NUM_PICKABLE_REGS
            assert frd >= 0
            assert frd < MAX_NUM_PICKABLE_REGS
        self.frs1 = frs1
        self.frs2 = frs2
        self.frd  = frd

    def set_bytecode(self, bytecode):
        self.frs1 = (bytecode>>15)&0x1F
        self.frs2 = (bytecode>>20)&0x1F
        self.frd =  (bytecode>>7)&0x1F

    def gen_bytecode_int(self, is_spike_resolution: bool):
        # rv32f
        if  self.instr_str == "fsgnj.s":
            return rv32f_fsgnjs(self.frd, self.frs1, self.frs2)
        elif self.instr_str == "fsgnjn.s":
            return rv32f_fsgnjns(self.frd, self.frs1, self.frs2)
        elif self.instr_str == "fsgnjx.s":
            return rv32f_fsgnjxs(self.frd, self.frs1, self.frs2)
        elif self.instr_str == "fmin.s":
            return rv32f_fmins(self.frd, self.frs1, self.frs2)
        elif self.instr_str == "fmax.s":
            return rv32f_fmaxs(self.frd, self.frs1, self.frs2)
        # rv32d
        if  self.instr_str == "fsgnj.d":
            return rv32d_fsgnjd(self.frd, self.frs1, self.frs2)
        elif self.instr_str == "fsgnjn.d":
            return rv32d_fsgnjnd(self.frd, self.frs1, self.frs2)
        elif self.instr_str == "fsgnjx.d":
            return rv32d_fsgnjxd(self.frd, self.frs1, self.frs2)
        elif self.instr_str == "fmin.d":
            return rv32d_fmind(self.frd, self.frs1, self.frs2)
        elif self.instr_str == "fmax.d":
            return rv32d_fmaxd(self.frd, self.frs1, self.frs2)
        # Default case
        else:
            raise ValueError(f"Unexpected instruction string: `{self.instr_str}`.")

# Pure float instructions with frs1, and frd
Float2Instructions = ("fsqrt.s", "fsqrt.d", "fcvt.d.s", "fcvt.s.d")
class Float2Instruction(CFInstruction):
    authorized_instr_strs = Float2Instructions

    def __init__(self, fuzzerstate, instr_str: str, frd: int, frs1: int, rm: int, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, iscompressed)        
        raise NotImplementedError

        if DO_ASSERT:
            assert rm >= 0
            assert rm < 8
            assert frs1 >= 0
            assert frs1 < MAX_NUM_PICKABLE_REGS
            assert frd >= 0
            assert frd < MAX_NUM_PICKABLE_REGS
        self.rm   = rm
        self.frs1 = frs1
        self.frd  = frd

    def set_bytecode(self, bytecode):
        self.frs1 = (bytecode>>15)&0x1F
        self.frd =  (bytecode>>7)&0x1F

    def gen_bytecode_int(self, is_spike_resolution: bool):
        # rv32f
        if self.instr_str == "fsqrt.s":
            return rv32f_fsqrts(self.frd, self.frs1, self.rm)
        # rv32d
        elif self.instr_str == "fsqrt.d":
            return rv32d_fsqrtd(self.frd, self.frs1, self.rm)
        # rv32d
        elif self.instr_str == "fcvt.d.s":
            return rv32d_fcvtds(self.frd, self.frs1, self.rm)
        # rv32d
        elif self.instr_str == "fcvt.s.d":
            return rv32d_fcvtsd(self.frd, self.frs1, self.rm)
        # Default case
        else:
            raise ValueError(f"Unexpected instruction string: `{self.instr_str}`.")


# Floating point instructions of 2 source floats but an integer destination
FloatIntRd2Instructions = ("feq.s", "flt.s", "fle.s", "feq.d", "flt.d", "fle.d")
class FloatIntRd2Instruction(CFInstruction):
    authorized_instr_strs = FloatIntRd2Instructions

    def __init__(self, fuzzerstate, instr_str: str, rd: int, frs1: int, frs2: int, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, iscompressed)
        raise NotImplementedError
        
        if DO_ASSERT:
            assert frs1 >= 0
            assert frs1 < MAX_NUM_PICKABLE_REGS
            assert frs2 >= 0
            assert frs2 < MAX_NUM_PICKABLE_REGS
            assert rd >= 0
            assert rd < MAX_NUM_PICKABLE_REGS
        self.frs1 = frs1
        self.frs2 = frs2
        self.rd   = rd
        
    def set_bytecode(self, bytecode):
        self.frs1 = (bytecode>>15)&0x1F
        self.frs2 = (bytecode>>20)&0x1F
        self.frd =  (bytecode>>7)&0x1F

    def gen_bytecode_int(self, is_spike_resolution: bool):
        # rv32f
        if self.instr_str == "feq.s":
            return rv32f_feqs(self.rd, self.frs1, self.frs2)
        elif self.instr_str == "flt.s":
            return rv32f_flts(self.rd, self.frs1, self.frs2)
        elif self.instr_str == "fle.s":
            return rv32f_fles(self.rd, self.frs1, self.frs2)
        # rv32d
        elif self.instr_str == "feq.d":
            return rv32d_feqd(self.rd, self.frs1, self.frs2)
        elif self.instr_str == "flt.d":
            return rv32d_fltd(self.rd, self.frs1, self.frs2)
        elif self.instr_str == "fle.d":
            return rv32d_fled(self.rd, self.frs1, self.frs2)
        # Default case
        else:
            raise ValueError(f"Unexpected instruction string: `{self.instr_str}`.")

# Flating point instructions of 1 source float but an integer destination
FloatIntRd1Instructions = ("fmv.x.w", "fclass.s", "fclass.d", "fmv.x.d")
class FloatIntRd1Instruction(CFInstruction):
    authorized_instr_strs = FloatIntRd1Instructions

    def __init__(self, fuzzerstate, instr_str: str, rd: int, frs1: int, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, iscompressed)
        raise NotImplementedError
        
        if DO_ASSERT:
            assert frs1 >= 0
            assert frs1 < MAX_NUM_PICKABLE_REGS
            assert rd >= 0
            assert rd < MAX_NUM_PICKABLE_REGS
        self.frs1 = frs1
        self.rd   = rd

    def set_bytecode(self, bytecode):
        self.frs1 = (bytecode>>15)&0x1F
        self.rd =  (bytecode>>7)&0x1F

    def gen_bytecode_int(self, is_spike_resolution: bool):
        # rv32f
        if self.instr_str == "fmv.x.w":
            return rv32f_fmvxw(self.rd, self.frs1)
        elif self.instr_str == "fclass.s":
            return rv32f_fclasss(self.rd, self.frs1)
        # rv32d
        elif self.instr_str == "fclass.d":
            return rv32d_fclassd(self.rd, self.frs1)
        # rv64d
        elif self.instr_str == "fmv.x.d":
            return rv64d_fmvxd(self.rd, self.frs1)
        # Default case
        else:
            raise ValueError(f"Unexpected instruction string: `{self.instr_str}`.")

# Flating point instructions of 1 source int but a float destination
FloatIntRs1Instructions = ("fmv.w.x", "fmv.d.x")
class FloatIntRs1Instruction(CFInstruction):
    authorized_instr_strs = FloatIntRs1Instructions

    def __init__(self, fuzzerstate, instr_str: str, frd: int, rs1: int, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, iscompressed)
        raise NotImplementedError
        
        if DO_ASSERT:
            assert rs1 >= 0
            assert rs1 < MAX_NUM_PICKABLE_REGS
            assert frd >= 0
            assert frd < MAX_NUM_PICKABLE_REGS
        self.rs1 = rs1
        self.frd = frd
 
    def set_bytecode(self, bytecode):
        self.rs1 = (bytecode>>15)&0x1F
        self.frd =  (bytecode>>7)&0x1F

    def gen_bytecode_int(self, is_spike_resolution: bool):
        # rv32f
        if self.instr_str == "fmv.w.x":
            return rv32f_fmvwx(self.frd, self.rs1)
        # rv64d
        elif self.instr_str == "fmv.d.x":
            return rv64d_fmvdx(self.frd, self.rs1)
        # Default case
        else:
            raise ValueError(f"Unexpected instruction string: `{self.instr_str}`.")

###
# Atomic instructions
###

# Atomic instructions are not yet supported.

###
# CSR instructions
###

# Any instruction with an immediate
class CSRInstruction(CFInstruction):
    # static
    authorized_instr_strs = ("csrrw", "csrrs", "csrrc", "csrrwi", "csrrsi", "csrrci")
    # Checks the immediate size.
    def assert_csr_size(self):
        if DO_ASSERT:
            assert hasattr(self, 'csr_id')
            assert self.csr_id >= 0
            assert self.csr_id <  1 << 12

    def __init__(self, fuzzerstate, instr_str: str, csr_id: int, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, iscompressed)
        self.csr_id = csr_id
        self.assert_csr_size()
        
        

# CSR operations without immediate
CSRRegInstructions = "csrrw", "csrrs", "csrrc"
class CSRRegInstruction(CSRInstruction):
    authorized_instr_strs = CSRRegInstructions
    def __init__(self, fuzzerstate, instr_str: str, rd: int, rs1: int, csr_id: CSR_IDS, iscompressed: bool = False, is_satp_smode = (False, None), mpp_val = None):
        super().__init__(fuzzerstate, instr_str, csr_id, iscompressed)
        if DO_ASSERT:
            assert rd >= 0
            assert rd < MAX_NUM_PICKABLE_REGS, f"rd: {rd}, MAX_NUM_PICKABLE_REGS: {MAX_NUM_PICKABLE_REGS}"
            assert rs1 >= 0
            assert rs1 < MAX_NUM_PICKABLE_REGS or rs1 in NONPICKABLE_REGISTERS, f"rs1: {rs1}, MAX_NUM_PICKABLE_REGS: {MAX_NUM_PICKABLE_REGS}"
        self.rd  = rd
        self.rs1 =  rs1
        self.is_satp_smode = is_satp_smode
        self.mpp_val = mpp_val


    def gen_bytecode_int(self, is_spike_resolution: bool):
        # rv32i
        if self.instr_str == "csrrw":
            return zicsr_csrrw(self.rd, self.rs1, self.csr_id)
        elif self.instr_str == "csrrs":
            return zicsr_csrrs(self.rd, self.rs1, self.csr_id)
        elif self.instr_str == "csrrc":
            return zicsr_csrrc(self.rd, self.rs1, self.csr_id)
        # Default case
        else:
            raise ValueError(f"Unexpected instruction string: `{self.instr_str}`.")

    def get_str(self, is_spike_resolution: bool = True, color_taint: bool = False):
        return f"{self.get_preamble()}: {self.instr_str} {ABI_INAMES[self.rd]}, {self.csr_id.name}, {ABI_INAMES[self.rs1]}"

# CSR operations with immediate
CSRImmInstructions = "csrrwi", "csrrsi", "csrrci"
class CSRImmInstruction(CSRInstruction):
    authorized_instr_strs = CSRImmInstructions

    def __init__(self, fuzzerstate, instr_str: str, rd: int, uimm: int, csr_id: int, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, csr_id, iscompressed)
        if DO_ASSERT:
            assert rd >= 0
            assert rd < MAX_NUM_PICKABLE_REGS
            assert uimm >= 0
            assert uimm < 1 << 5
        self.rd   = rd
        self.uimm = uimm

    def gen_bytecode_int(self, is_spike_resolution: bool):
        # rv32i
        if self.instr_str == "csrrwi":
            return zicsr_csrrwi(self.rd, self.uimm, self.csr_id)
        elif self.instr_str == "csrrsi":
            return zicsr_csrrsi(self.rd, self.uimm, self.csr_id)
        elif self.instr_str == "csrrci":
            return zicsr_csrrci(self.rd, self.uimm, self.csr_id)
        # Default case
        else:
            raise ValueError(f"Unexpected instruction string: `{self.instr_str}`.")

    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = False):
        return f"{self.get_preamble()}: {self.instr_str} {ABI_INAMES[self.rd]}, {self.csr_id.name}, {hex(self.uimm)}"

###
# Placeholder instructions
###

# For offset producers and consumers.
# The offset producers and consumers do not yet know the final immediate values, and are used differently in the spike resolution from the actual simulation.
# 1. For the spike resolution
#   a. The offset producer creates the target address (or branch decision register).
#   b. The offset consumer forwards this offset which is also the target address in this case.
# 2. For the actual simulation
#   a. The offset producer computes an offset dependent on the resolution.
#   b. The offset consumer computes the generated, target address, by making the difference between the dependent register and the offset. This instruction does not require the spike resolution to be known, but still is different between the two scenari.


# Does not inherit from CFInstruction.
class PlaceholderProducerInstr0(BaseInstruction):
    # When it is instantiated, the producer instructions do not know the offset yet, just the target address.
    def __init__(self, fuzzerstate, rd: int, producer_id: int):
        super().__init__(fuzzerstate,"lui (PlaceholderProducerInstr0)")
        self.rd = rd
        self.producer_id = producer_id
        self.relocation_offset = 0
        self.spike_resolution_offset = None
        self.rtl_offset = None
        self.produce_va_layout = None
        self.produce_priv_level = None

    def get_preamble(self):
        if self.produce_priv_level is not None and self.produce_va_layout is not None:
            return super().get_preamble() +  f": {int(self.producer_id)}/{self.produce_priv_level.name[0]}/{self.produce_va_layout}"
        else:
            return super().get_preamble() +  f": {int(self.producer_id)}/None/None"

    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = False):
        if is_spike_resolution:
            if self.spike_resolution_offset is not None:
                spike_res_off = self.spike_resolution_offset
                if USE_MMU and self.fuzzerstate.is_design_64bit and self.produce_va_layout != -1: 
                    spike_res_off = (self.spike_resolution_offset | 0x80000000) & 0xffffffff # TODO double check if the check of the 64th bit is valid
                return  f"{self.get_preamble()}: {self.instr_str} {ABI_INAMES[self.rd]}, {hex(li_into_reg(to_unsigned(spike_res_off, self.fuzzerstate.is_design_64bit), False)[0])}"
            return f"{self.get_preamble()}: {self.instr_str} {ABI_INAMES[self.rd]}, [undetermined]"
        else:
            if self.rtl_offset is not None:
                rtl_off = self.rtl_offset
                if USE_MMU and self.fuzzerstate.is_design_64bit and self.produce_va_layout != -1:
                    rtl_off = (self.rtl_offset | 0x80000000) & 0xffffffff # TODO double check if the check of the 64th bit is valid
                return f"{self.get_preamble()}: {self.instr_str} {ABI_INAMES[self.rd]}, {hex(li_into_reg(to_unsigned(rtl_off, self.fuzzerstate.is_design_64bit), False)[0])}"
            else:
                return f"{self.get_preamble()}: {self.instr_str} {ABI_INAMES[self.rd]}, (None)"

    def gen_bytecode_int(self, is_spike_resolution: bool):
        # If this is the spike resolution, then load the target address using lui
        if is_spike_resolution:
            # If this is a virtual address, we set bit 32 to one to sign extend and crop the value so that it can be loaded into the register
            spike_res_off = self.spike_resolution_offset
            if USE_MMU and self.fuzzerstate.is_design_64bit and self.produce_va_layout != -1: 
                spike_res_off = (self.spike_resolution_offset | 0x80000000) & 0xffffffff # TODO double check if the check of the 64th bit is valid
            if DO_ASSERT:
                assert spike_res_off < (1 << 32), f"{hex(spike_res_off)}"
            return rv32i_lui(self.rd, li_into_reg(to_unsigned(spike_res_off, self.fuzzerstate.is_design_64bit), False)[0])
        else:
            rtl_off = self.rtl_offset
            if USE_MMU and self.fuzzerstate.is_design_64bit and self.produce_va_layout != -1:
                rtl_off = (self.rtl_offset | 0x80000000) & 0xffffffff # TODO double check if the check of the 64th bit is valid
            if DO_ASSERT:
                assert rtl_off is not None, "Producer0 cannot produce final bytecode because it does not yet know the final offset."
            return rv32i_lui(self.rd, li_into_reg(to_unsigned(rtl_off, self.fuzzerstate.is_design_64bit), False)[0])

# Does not inherit from CFInstruction.
class PlaceholderProducerInstr1(BaseInstruction):
    # When it is instantiated, the producer instructions do not know the offset yet, just the target address.
    def __init__(self, fuzzerstate, rd: int, producer_id: int):
        super().__init__(fuzzerstate,"addi (PlaceholderProducerInstr1)")
        self.rd = rd
        self.producer_id = producer_id
        self.relocation_offset = 0
        self.spike_resolution_offset = None # Is also the target address
        self.rtl_offset = None
        self.produce_va_layout = None
        self.produce_priv_level = None

    def get_preamble(self):
        if self.produce_priv_level is not None and self.produce_va_layout is not None:
            return super().get_preamble() +  f": {int(self.producer_id)}/{self.produce_priv_level.name[0]}/{self.produce_va_layout}"
        else:
            return super().get_preamble() +  f": {int(self.producer_id)}/None/None"

    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = False):
        if is_spike_resolution:
            if self.spike_resolution_offset is not None:
                spike_res_off = self.spike_resolution_offset
                if USE_MMU and self.fuzzerstate.is_design_64bit and self.produce_va_layout != -1:
                    spike_res_off = (self.spike_resolution_offset | 0x80000000) & 0xffffffff
                return f"{self.get_preamble()}: {self.instr_str} {ABI_INAMES[self.rd]}, {ABI_INAMES[self.rd]}, {hex(li_into_reg(to_unsigned(spike_res_off, self.fuzzerstate.is_design_64bit), False)[1])}"
            return f"{self.get_preamble()}: {self.instr_str} {ABI_INAMES[self.rd]}, {ABI_INAMES[self.rd]}, [undetermined]"
        else:
            if self.rtl_offset is not None:
                rtl_off = self.rtl_offset
                if USE_MMU and self.fuzzerstate.is_design_64bit and self.produce_va_layout != -1: 
                    rtl_off = (self.rtl_offset | 0x80000000) & 0xffffffff # TODO double check if the check of the 64th bit is valid
                return f"{self.get_preamble()}: {self.instr_str} {ABI_INAMES[self.rd]}, {ABI_INAMES[self.rd]}, {hex(li_into_reg(to_unsigned(rtl_off, self.fuzzerstate.is_design_64bit), False)[1])}"
            else:
                return f"{self.get_preamble()}: {self.instr_str} {ABI_INAMES[self.rd]}, {ABI_INAMES[self.rd]}, (None)"

    def gen_bytecode_int(self, is_spike_resolution: bool):
        # If this is the spike resolution, then load the target address using addi
        if is_spike_resolution:
            spike_res_off = self.spike_resolution_offset
            if USE_MMU and self.fuzzerstate.is_design_64bit and self.produce_va_layout != -1:
                spike_res_off = (self.spike_resolution_offset | 0x80000000) & 0xffffffff
            if DO_ASSERT:
                assert spike_res_off < (1 << 32)
            return rv32i_addi(self.rd, self.rd, li_into_reg(to_unsigned(spike_res_off, self.fuzzerstate.is_design_64bit), False)[1])
        else:
            rtl_off = self.rtl_offset
            if USE_MMU and self.fuzzerstate.is_design_64bit and self.produce_va_layout != -1: 
                rtl_off = (self.rtl_offset | 0x80000000) & 0xffffffff # TODO double check if the check of the 64th bit is valid
            if DO_ASSERT:
                assert rtl_off is not None, "Producer1 cannot produce final bytecode because it does not yet know the final rtl_offset."
            return rv32i_addi(self.rd, self.rd, li_into_reg(to_unsigned(rtl_off, self.fuzzerstate.is_design_64bit), False)[1])


# Does not inherit from CFInstruction.
class PlaceholderPreConsumerInstr(BaseInstruction):
    # @param rdep: the register that creates the dependency
    def __init__(self, fuzzerstate, rdep: int, producer_id: int, is_rprod: bool = False):
        super().__init__(fuzzerstate,"and (PlaceholderPreConsumerInstr)")
        self.rdep = rdep
        self.is_rprod = is_rprod
        self.producer_id = producer_id
        self.produce_va_layout = None
        self.produce_priv_level = None

    def get_preamble(self):
        if self.produce_priv_level is not None and self.produce_va_layout is not None:
            return super().get_preamble() +  f": {int(self.producer_id)}/{self.produce_priv_level.name[0]}/{self.produce_va_layout}"
        else:
            return super().get_preamble() +  f": {int(self.producer_id)}/None/None"

    def get_str(self, is_spike_resolution: bool = False, color_taint: bool = False):
        if USE_MMU and self.fuzzerstate.is_design_64bit and self.is_rprod and self.produce_va_layout != -1:
            return f"{self.get_preamble()}: {self.instr_str} {ABI_INAMES[self.rdep]},  {ABI_INAMES[self.rdep]}, {ABI_INAMES[RPROD_MASK_REGISTER_ID]}"
        elif USE_MMU and self.fuzzerstate.is_design_64bit and self.produce_va_layout != -1:
            return f"{self.get_preamble()}: {self.instr_str} {ABI_INAMES[self.rdep]},  {ABI_INAMES[self.rdep]}, {ABI_INAMES[RDEP_MASK_REGISTER_ID_VIRT]}"
        else:
            return f"{self.get_preamble()}: {self.instr_str} {ABI_INAMES[self.rdep]},  {ABI_INAMES[self.rdep]}, {ABI_INAMES[RDEP_MASK_REGISTER_ID]}"

    def gen_bytecode_int(self, is_spike_resolution: bool):
        # Reduce the size of the rdep id to 32 bits

        ##
        # When in bare, we use a 32 bit RDEP_MASK_REGISTER_ID for both.
        # If we are translating or generating the MEPC, we need to use the RPROD_MASK_REGISTER_ID loaded with the right value for the next layout
        # to generate the RPROD reg. The issue is that bit 32 is always xored with one in resol, but not necessarly in the final (which interferes because we set bit 32 to 1 manually 
        # to produce the final 32 bits). The detail is that since we deal with absolute addreses in virtual memory, we don't need to reolocated, so we set,
        # The high bits to the correct value here already. Thus we cannot have a dependant register which modifies those bits. 
        ##

        if USE_MMU and self.fuzzerstate.is_design_64bit and self.is_rprod and self.produce_va_layout != -1:
            return rv32i_and(self.rdep, self.rdep, RPROD_MASK_REGISTER_ID)
        elif USE_MMU and self.fuzzerstate.is_design_64bit and self.produce_va_layout != -1:
            return rv32i_and(self.rdep, self.rdep, RDEP_MASK_REGISTER_ID_VIRT)
        else:
            return rv32i_and(self.rdep, self.rdep, RDEP_MASK_REGISTER_ID)

# Does not inherit from CFInstruction.
class PlaceholderConsumerInstr(BaseInstruction):
    # @param rd: the generated register, i.e., the target address for example
    # @param rdep: the register that creates the dependency
    # @param producer_id: is required to feed spike's feedback
    def __init__(self, fuzzerstate, rd: int, rdep: int, rprod: int, producer_id: int):
        super().__init__(fuzzerstate,f"xor (PlaceholderConsumerInstr)")
        self.rd = rd
        self.rdep = rdep
        self.rprod = rprod
        self.producer_id = producer_id
        self.dont_relocate_spike = False # We want to relocate spike for addresses, but not for some CSRs such as medeleg.
        self.produce_va_layout = None
        self.produce_priv_level = None

    def get_preamble(self):
        if self.produce_priv_level is not None and self.produce_va_layout is not None:
            return super().get_preamble() +  f": {int(self.producer_id)}/{self.produce_priv_level.name[0]}/{self.produce_va_layout}"
        else:
            return super().get_preamble() +  f": {int(self.producer_id)}/None/None"

    def get_str(self, is_spike_resolution: bool = False, color_taint: bool = False):
        if is_spike_resolution:
            if USE_MMU and self.produce_va_layout != -1:
                return f"{self.get_preamble()}: nop (PlaceholderConsumerInstr)"
            else:
                return f"{self.get_preamble()}: {self.instr_str} {ABI_INAMES[self.rd]}, {ABI_INAMES[self.rprod]}, {ABI_INAMES[RELOCATOR_REGISTER_ID]}"
        else:
            return f"{self.get_preamble()}: {self.instr_str} {ABI_INAMES[self.rd]}, {ABI_INAMES[self.rdep]}, {ABI_INAMES[self.rprod]}"
        
    def gen_bytecode_int(self, is_spike_resolution: bool):
        if DO_ASSERT:
            assert not self.dont_relocate_spike, "We do not yet support dont_relocate_spike because it causes other problems that cause vals to change from the DUT by an offset of 0x80000000."
        # If this is the spike resolution, then just transmit the produced register
        if is_spike_resolution:
            if USE_MMU and self.produce_va_layout != -1:
                return rv32i_addi(0, 0, 0) # nop, if we are in virtual address space, we already use absolute addresses (only in sv39, sv48)
            else:
                return rv32i_xor(self.rd, self.rprod, RELOCATOR_REGISTER_ID) # self.rprod - 0
        else:
            return rv32i_xor(self.rd, self.rdep, self.rprod) # self.rdep - self.rprod

def is_placeholder(obj):
    return isinstance(obj, PlaceholderProducerInstr0) or isinstance(obj, PlaceholderProducerInstr1) or isinstance(obj, PlaceholderPreConsumerInstr) or isinstance(obj, PlaceholderConsumerInstr)


###
# Raw data
###

class RawDataWord:
    # @param intentionally_signed: When unset, we expect a non-negative wordval
    def __init__(self, fuzzerstate, wordval: int, signed: bool = False):
        self.fuzzerstate = fuzzerstate
        self.paddr = fuzzerstate.ctxsv_bb_base_addr + 4*len(fuzzerstate.ctxsv_bb) + SPIKE_STARTADDR # NOCOMPRESSED
        if DO_ASSERT:
            if signed:
                assert wordval >= -(1 << 31)
                assert wordval < (1 << 32), f"signed wordval: {wordval}, 1 << 32: {1 << 32}"
            else:
                assert wordval >= 0
                assert wordval < (1 << 32), f"unsigned wordval: {hex(wordval)}, 1 << 32: {hex(1 << 32)}"
        self.wordval = wordval
        if signed:
            if wordval < 0:
                self.wordval = wordval + (1 << 32)

    def gen_bytecode_int(self, is_spike_resolution: bool):
        return self.wordval
    
    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = False):
        return f"{self.get_preamble()}: {hex(self.wordval)} (RAW DATA)"

    def print(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF):
        print(self.get_str(is_spike_resolution))

    def write(self, is_spike_resolution: bool = False):
        self.fuzzerstate.memview.write(self.paddr, self.gen_bytecode_int(is_spike_resolution), 4)

###
# For exceptions
###

# This is a superclass for exceptions. This is useful for how we generate the produced registers.
# When an exception is encountered, we find back the last corresponding tvec write and set its expected value properly.
# Inheritance from ExceptionInstruction allows us to distinguish, for example, a real JAL form a JAL to a misaligned address that should cause an exception.
# It also serves to abstract exception types in general parts of the codebase such as basicblock.py.
class ExceptionInstruction(BaseInstruction):
    # @param producer_id: Used for exceptions (typically intentionally faulty jalr/loads/stores) that require a produced register for themselves in addition to the target address (held in the corresponding tvec). Keep None if none is needed.
    # @param is_mtvec: if the exception will be handled in machine mode. If false, then stvec.
    # Remargk: is_mtvec also determines which of mepc and sepc will be set.
    def __init__(self, fuzzerstate, is_mtvec: bool, producer_id: int = None):
        super().__init__(fuzzerstate, f'ExceptionInstruction')
        self.is_mtvec = is_mtvec
        self.producer_id = producer_id
        self.va_layout_after_op = fuzzerstate.effective_curr_layout # The layout that is entered after the exception is raised.
        self.priv_level_after_op = fuzzerstate.privilegestate.privstate # The privstate has already been changed at this point.

class SimpleIllegalInstruction(ExceptionInstruction):
    def __init__(self, fuzzerstate, is_mtvec):
        super().__init__(fuzzerstate, is_mtvec, None)

    def gen_bytecode_int(self, is_spike_resolution: bool):
        return 0x00000000

    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = False):
            return f"{self.get_preamble()}: unimp (SimpleIllegalInstruction)"


# Exception that encapsulates an instruction that causes an exception, such as a misaligned JAL.
class SimpleExceptionEncapsulator(ExceptionInstruction):
    def __init__(self, fuzzerstate, is_mtvec, producer_id: int, instr, exception_op_type: ExceptionCauseVal):
        super().__init__(fuzzerstate, is_mtvec, producer_id)
        if DO_ASSERT:
            assert producer_id is None, "SimpleExceptionEncapsulator does not support a producer_id. If we want to support it, then we need to adapt gen_producer_id_to_tgtaddr in basicblock.py."
            assert exception_op_type in ExceptionCauseVal
            assert self.paddr == instr.paddr

        self.instr = instr
        self.exception_op_type = exception_op_type
        # print(f"{self.get_str()} goes into {self.priv_level_after_op.name}")

    def gen_bytecode_int(self, is_spike_resolution: bool):
        return self.instr.gen_bytecode_int(is_spike_resolution)

    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = False):
        return f"{self.instr.get_str(is_spike_resolution)} (SimpleExceptionEncapsulator for {self.producer_id})"
    
    def reset_addr(self):
        self.instr.reset_addr()
        return super().reset_addr()

def is_tolerate_transient_exec_str(fuzzerstate, instr_str: str):
    if "openc910" in fuzzerstate.design_name:
        if instr_str in IntLoadInstruction.authorized_instr_strs:
            return TOLERATE_OPENC910_TRANSIENT_EXEC_TAINTED_ADDR_LOAD
        elif instr_str in IntStoreInstruction.authorized_instr_strs:
            return TOLERATE_OPENC910_TRANSIENT_EXEC_TAINTED_ADDR_STORE
        elif instr_str in R12DInstruction.authorized_instr_strs:
            return TOLERATE_OPENC910_TRANSIENT_EXEC_TAINTED_CT_VIOLATION
        elif instr_str in JALRInstruction.authorized_instr_strs:
            return TOLERATE_OPENC910_TRANSIENT_EXEC_TAINTED_JALR
        elif instr_str in BranchInstruction.authorized_instr_strs:
            return TOLERATE_OPENC910_TRANSIENT_EXEC_TAINTED_BRANCH
        
    elif "cva6" in fuzzerstate.design_name:
        if instr_str in IntLoadInstruction.authorized_instr_strs:
            return TOLERATE_CVA6_TRANSIENT_EXEC_TAINTED_ADDR_LOAD
        elif instr_str in IntStoreInstruction.authorized_instr_strs:
            return TOLERATE_CVA6_TRANSIENT_EXEC_TAINTED_ADDR_STORE
        elif instr_str in R12DInstruction.authorized_instr_strs:
            return TOLERATE_CVA6_TRANSIENT_EXEC_TAINTED_CT_VIOLATION
        elif instr_str in JALRInstruction.authorized_instr_strs:
            return TOLERATE_CVA6_TRANSIENT_EXEC_TAINTED_JALR
        elif instr_str in BranchInstruction.authorized_instr_strs:
            return TOLERATE_CVA6_TRANSIENT_EXEC_TAINTED_BRANCH

    elif "boom" in fuzzerstate.design_name:
        if instr_str in IntLoadInstruction.authorized_instr_strs:
            return TOLERATE_BOOM_TRANSIENT_EXEC_TAINTED_ADDR_LOAD
        elif instr_str in IntStoreInstruction.authorized_instr_strs:
            return TOLERATE_BOOM_TRANSIENT_EXEC_TAINTED_ADDR_STORE
        elif instr_str in R12DInstruction.authorized_instr_strs:
            return TOLERATE_BOOM_TRANSIENT_EXEC_TAINTED_CT_VIOLATION
        elif instr_str in JALRInstruction.authorized_instr_strs:
            return TOLERATE_BOOM_TRANSIENT_EXEC_TAINTED_JALR
        elif instr_str in BranchInstruction.authorized_instr_strs:
            return TOLERATE_BOOM_TRANSIENT_EXEC_TAINTED_BRANCH

    elif "rocket" in fuzzerstate.design_name:
        if instr_str in IntLoadInstruction.authorized_instr_strs:
            return TOLERATE_ROCKET_TRANSIENT_EXEC_TAINTED_ADDR_LOAD
        elif instr_str in IntStoreInstruction.authorized_instr_strs:
            return TOLERATE_ROCKET_TRANSIENT_EXEC_TAINTED_ADDR_STORE
        elif instr_str in R12DInstruction.authorized_instr_strs:
            return TOLERATE_ROCKET_TRANSIENT_EXEC_TAINTED_CT_VIOLATION
        elif instr_str in JALRInstruction.authorized_instr_strs:
            return TOLERATE_ROCKET_TRANSIENT_EXEC_TAINTED_JALR
        elif instr_str in BranchInstruction.authorized_instr_strs:
            return TOLERATE_ROCKET_TRANSIENT_EXEC_TAINTED_BRANCH

    assert False # Should never reach this

def is_tolerate_transient_exec(fuzzerstate, instr: BaseInstruction, exception: Exception):
    if isinstance (exception,TaintedRegisterException): 
        if "openc910" in fuzzerstate.design_name:
            if isinstance(instr, IntLoadInstruction):
                return TOLERATE_OPENC910_TRANSIENT_EXEC_TAINTED_ADDR_LOAD
            elif isinstance(instr, IntStoreInstruction):
                return TOLERATE_OPENC910_TRANSIENT_EXEC_TAINTED_ADDR_STORE
            elif isinstance(instr, R12DInstruction):
                return TOLERATE_OPENC910_TRANSIENT_EXEC_TAINTED_CT_VIOLATION
            elif isinstance(instr, JALRInstruction):
                return TOLERATE_OPENC910_TRANSIENT_EXEC_TAINTED_JALR
            elif isinstance(instr, BranchInstruction):
                return TOLERATE_OPENC910_TRANSIENT_EXEC_TAINTED_BRANCH

        elif "cva6" in fuzzerstate.design_name:
            if isinstance(instr, IntLoadInstruction):
                return TOLERATE_CVA6_TRANSIENT_EXEC_TAINTED_ADDR_LOAD
            elif isinstance(instr, IntStoreInstruction):
                return TOLERATE_CVA6_TRANSIENT_EXEC_TAINTED_ADDR_STORE
            elif isinstance(instr, R12DInstruction):
                return TOLERATE_CVA6_TRANSIENT_EXEC_TAINTED_CT_VIOLATION
            elif isinstance(instr, JALRInstruction):
                return TOLERATE_CVA6_TRANSIENT_EXEC_TAINTED_JALR
            elif isinstance(instr, BranchInstruction):
                return TOLERATE_CVA6_TRANSIENT_EXEC_TAINTED_BRANCH

        elif "boom" in fuzzerstate.design_name:
            if isinstance(instr, IntLoadInstruction):
                return TOLERATE_BOOM_TRANSIENT_EXEC_TAINTED_ADDR_LOAD
            elif isinstance(instr, IntStoreInstruction):
                return TOLERATE_BOOM_TRANSIENT_EXEC_TAINTED_ADDR_STORE
            elif isinstance(instr, R12DInstruction):
                return TOLERATE_BOOM_TRANSIENT_EXEC_TAINTED_CT_VIOLATION
            elif isinstance(instr, JALRInstruction):
                return TOLERATE_BOOM_TRANSIENT_EXEC_TAINTED_JALR
            elif isinstance(instr, BranchInstruction):
                return TOLERATE_BOOM_TRANSIENT_EXEC_TAINTED_BRANCH

        elif "rocket" in fuzzerstate.design_name:
            if isinstance(instr, IntLoadInstruction):
                return TOLERATE_ROCKET_TRANSIENT_EXEC_TAINTED_ADDR_LOAD
            elif isinstance(instr, IntStoreInstruction):
                return TOLERATE_ROCKET_TRANSIENT_EXEC_TAINTED_ADDR_STORE
            elif isinstance(instr, R12DInstruction):
                return TOLERATE_ROCKET_TRANSIENT_EXEC_TAINTED_CT_VIOLATION
            elif isinstance(instr, JALRInstruction):
                return TOLERATE_ROCKET_TRANSIENT_EXEC_TAINTED_JALR
            elif isinstance(instr, BranchInstruction):
                return TOLERATE_ROCKET_TRANSIENT_EXEC_TAINTED_BRANCH
        
    assert False # Should never reach this


# Wrapper for instructions that are only executed speculatively, so should not have any architectually visible effects.
class SpeculativeInstructionEncapsulator(BaseInstruction):
    def __init__(self, fuzzerstate, instr):
        super().__init__(fuzzerstate, "SpeculativeInstructionEncapsulator")
        self.instr = instr
        self.instr.isdead = True
        self.iscompressed = instr.iscompressed
        
        self.paddr = self.instr.paddr
        self.vaddr = self.instr.vaddr
        self.priv_level = self.instr.priv_level
        self.va_layout = self.instr.va_layout
        

    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = False):
        return f"{self.instr.get_str(is_spike_resolution)} (SpeculativeInstructionEncapsulator)"

    def reset_addr(self):
        self.instr.reset_addr()
        return super().reset_addr()

    def gen_bytecode_int(self, is_spike_resolution: bool):
        return self.instr.gen_bytecode_int(is_spike_resolution)

    def execute(self, is_spike_resolution: bool = True):
        # We try executing them. They may fail, which is ok since they only execute transiently. We only care
        # to track legitimate control flows during the transient window for triaging.
        try:
            self.instr.execute(is_spike_resolution)
        except Exception as e:
            if isinstance(e, TaintedRegisterException) and is_tolerate_transient_exec(self.fuzzerstate, self.instr):
                pass
            # TODO do more specific triaging here
            elif isinstance(e, TaintedCSRException):
                pass
            elif isinstance(e, MemException):
                pass
            else:
                raise e



# This is a wrapper class for a misaligned load or store.
# As opposed to usual load and store operations used above, this class chooses a consumed register by itself.
class MisalignedMemInstruction(ExceptionInstruction):
    MISALIGNED_LH  = 0
    MISALIGNED_LW  = 1
    MISALIGNED_LHU = 2
    MISALIGNED_LWU = 3
    MISALIGNED_LD  = 4
    MISALIGNED_SH  = 5
    MISALIGNED_SW  = 6
    MISALIGNED_SD  = 7
    MISALIGNED_FLW = 8 # Requires F extension
    MISALIGNED_FSW = 9
    MISALIGNED_FLD = 10 # Requires D extension
    MISALIGNED_FSD = 11

    def __init__(self,fuzzerstate, is_mtvec: bool, is_load: bool, iscompressed: bool = False):
        super().__init__(fuzzerstate, is_mtvec, None) # We compute the producer id later

        from milesan.randomize.pickreg import IntRegIndivState
        # First, choose a consumed register.
        if self.priv_level in fuzzerstate.taint_sink_privs:
            if DO_ASSERT:
                assert fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PAGE_ADDR) or fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PAGE_T0_ADDR)
            if not fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PAGE_ADDR):
                rs1 = fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.PAGE_ADDR_T0)
            elif not  fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PAGE_ADDR_T0):
                rs1 = fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.PAGE_ADDR)
            else:
                rs1 = fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.PAGE_ADDR if random.random()<0.5 else IntRegIndivState.PAGE_ADDR_T0)
        else:
            if DO_ASSERT:
                assert fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PAGE_T0_ADDR)
            rs1 = fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.PAGE_ADDR)

        # Here, in principle no need for "self." in producer_id because it is already known by the wrapped instance.
        # But it is practical to have it here to discriminate between exceptions that require a consumed register and those that do not.
        self.producer_id = fuzzerstate.intregpickstate.get_producer_id(rs1)
        # fuzzerstate.intregpickstate.set_regstate(rs1, IntRegIndivState.RELOCUSED)

        # Second, choose a random memory instruction type that can be misaligned.
        meminstr_type_weights = [
          is_load,                                       # MISALIGNED_LH
          is_load,                                       # MISALIGNED_LW
          is_load and fuzzerstate.is_design_64bit,       # MISALIGNED_LHU
          is_load and fuzzerstate.is_design_64bit,       # MISALIGNED_LWU
          is_load and fuzzerstate.is_design_64bit,       # MISALIGNED_LD
          not is_load,                                   # MISALIGNED_SH
          not is_load,                                   # MISALIGNED_SW
          (not is_load) and fuzzerstate.is_design_64bit, # MISALIGNED_SD
          is_load and fuzzerstate.design_has_fpu,        # MISALIGNED_FLW
          (not is_load) and fuzzerstate.design_has_fpu,  # MISALIGNED_FSW
          is_load and fuzzerstate.design_has_fpud,       # MISALIGNED_FLD
          (not is_load) and fuzzerstate.design_has_fpud  # MISALIGNED_FSD
        ]
        meminstr_type = random.choices(range(len(meminstr_type_weights)), meminstr_type_weights)[0]
        if meminstr_type in [MisalignedMemInstruction.MISALIGNED_SH,
                            MisalignedMemInstruction.MISALIGNED_SW,
                            MisalignedMemInstruction.MISALIGNED_SD,
                            MisalignedMemInstruction.MISALIGNED_FSW,
                            MisalignedMemInstruction.MISALIGNED_FSD]:
                            self.exceptioncause_val = ExceptionCauseVal.ID_STORE_AMO_ADDR_MISALIGNED
        else:
            self.exceptioncause_val = ExceptionCauseVal.ID_LOAD_ADDR_MISALIGNED
        # Third, the destination register for loads, and the source register for stores does not matter because will not be architecturally accessed.
        random_reg = random.randrange(MAX_NUM_PICKABLE_REGS)
        # Finally, pick a readable or writable address, since page or access faults would have priority
        # if meminstr_type in (MisalignedMemInstruction.MISALIGNED_LH, MisalignedMemInstruction.MISALIGNED_LW, MisalignedMemInstruction.MISALIGNED_LHU, MisalignedMemInstruction.MISALIGNED_LWU, MisalignedMemInstruction.MISALIGNED_LD, MisalignedMemInstruction.MISALIGNED_FLW, MisalignedMemInstruction.MISALIGNED_FLD):
        memrange = 0, fuzzerstate.memsize
        # Choose a misaligned address in the range
        if meminstr_type in (MisalignedMemInstruction.MISALIGNED_LH, MisalignedMemInstruction.MISALIGNED_LHU, MisalignedMemInstruction.MISALIGNED_SH):
            curr_access_size = 2
        elif meminstr_type in (MisalignedMemInstruction.MISALIGNED_LW, MisalignedMemInstruction.MISALIGNED_LWU, MisalignedMemInstruction.MISALIGNED_SW, MisalignedMemInstruction.MISALIGNED_FLW, MisalignedMemInstruction.MISALIGNED_FSW):
            curr_access_size = 4
        else:
            curr_access_size = 8
        memrange_base, memrange_size = memrange[0], memrange[1] - memrange[0]
        if DO_ASSERT:
            assert memrange_base >= 0, "memrange_base: %d" % memrange_base
            assert memrange_base + memrange_size <= fuzzerstate.memsize, "memrange_base: %d, memrange_size: %d, fuzzerstate.memsize: %d" % (memrange_base, memrange_size, fuzzerstate.memsize)
            assert memrange_size > curr_access_size, "memrange_size: %d, curr_access_size: %d" % (memrange_size, curr_access_size)
        
        random_block = (random.randrange(memrange_base, memrange_base + memrange_size) // curr_access_size) * curr_access_size
        random_offset = random.randrange(1, curr_access_size)
        self.misaligned_addr = random_block + random_offset

        if DO_ASSERT:
            assert self.misaligned_addr >= memrange_base, "misaligned_addr: %d, memrange_base: %d" % (self.misaligned_addr, memrange_base)
            assert self.misaligned_addr < memrange_base + memrange_size, "misaligned_addr: %d, memrange_base: %d, memrange_size: %d" % (self.misaligned_addr, memrange_base, memrange_size)
            assert self.misaligned_addr % curr_access_size != 0, "misaligned_addr: %d, curr_access_size: %d" % (self.misaligned_addr, curr_access_size)

        # Instantiate the wrapped instruction
        imm = 0
        if meminstr_type == MisalignedMemInstruction.MISALIGNED_LH:
            self.meminstr = IntLoadInstruction(fuzzerstate,"lh", random_reg, rs1, imm, self.producer_id, iscompressed)
        elif meminstr_type == MisalignedMemInstruction.MISALIGNED_LW:
            self.meminstr = IntLoadInstruction(fuzzerstate,"lw", random_reg, rs1, imm, self.producer_id, iscompressed)
        elif meminstr_type == MisalignedMemInstruction.MISALIGNED_LHU:
            self.meminstr = IntLoadInstruction(fuzzerstate,"lhu", random_reg, rs1, imm, self.producer_id, iscompressed)
        elif meminstr_type == MisalignedMemInstruction.MISALIGNED_LWU:
            self.meminstr = IntLoadInstruction(fuzzerstate,"lwu", random_reg, rs1, imm, self.producer_id, iscompressed)
        elif meminstr_type == MisalignedMemInstruction.MISALIGNED_LD:
            self.meminstr = IntLoadInstruction(fuzzerstate,"ld", random_reg, rs1, imm, self.producer_id, iscompressed)
        elif meminstr_type == MisalignedMemInstruction.MISALIGNED_SH:
            self.meminstr = IntStoreInstruction(fuzzerstate,"sh", rs1, random_reg, imm, self.producer_id, iscompressed)
        elif meminstr_type == MisalignedMemInstruction.MISALIGNED_SW:
            self.meminstr = IntStoreInstruction(fuzzerstate,"sw", rs1, random_reg, imm, self.producer_id, iscompressed)
        elif meminstr_type == MisalignedMemInstruction.MISALIGNED_SD:
            self.meminstr = IntStoreInstruction(fuzzerstate,"sd", rs1, random_reg, imm, self.producer_id, iscompressed)
        elif meminstr_type == MisalignedMemInstruction.MISALIGNED_FLW:
            if DO_ASSERT:
                assert fuzzerstate.design_has_fpu
            self.meminstr = FloatLoadInstruction(fuzzerstate,"flw", random_reg, rs1, imm, self.producer_id, iscompressed)
        elif meminstr_type == MisalignedMemInstruction.MISALIGNED_FSD:
            if DO_ASSERT:
                assert fuzzerstate.design_has_fpud
            self.meminstr = FloatStoreInstruction(fuzzerstate,"fsd", rs1, random_reg, imm, self.producer_id, iscompressed)
        elif meminstr_type == MisalignedMemInstruction.MISALIGNED_FSW:
            if DO_ASSERT:
                assert fuzzerstate.design_has_fpu
            self.meminstr = FloatStoreInstruction(fuzzerstate,"fsw", rs1, random_reg, imm, self.producer_id, iscompressed)
        elif meminstr_type == MisalignedMemInstruction.MISALIGNED_FLD:
            if DO_ASSERT:
                assert fuzzerstate.design_has_fpud
            self.meminstr = FloatLoadInstruction(fuzzerstate,"fld", random_reg, rs1, imm, self.producer_id, iscompressed)
        else:
            raise NotImplementedError('Unsupported meminstrtype: ' + str(meminstr_type))
        # print('Generated misaligned memory instruction: ' + str(self.meminstr.instr_str), 'misaligned address', hex(self.misaligned_addr))

    def gen_bytecode_int(self, is_spike_resolution: bool):
        return self.meminstr.gen_bytecode_int(is_spike_resolution)

    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = False):
        return f"{self.meminstr.get_str(is_spike_resolution)} (MisalignedMemInstruction for {self.producer_id})"

    def reset_addr(self):
        self.meminstr.reset_addr()
        return super().reset_addr()

###
# CSR writers
###

# @remark we use a specific instruction for mstatus to find them easily when an exception occurs, to transmit back the expected value to the producer
# @brief this instruction writes to mtvec or stvec
class MstatusWriterInstruction(BaseInstruction):
    def __init__(self, fuzzerstate, rd: int, rs1: int, producer_id: int, instr_str: str, mstatus_mask: int):
        super().__init__(fuzzerstate, instr_str)
        self.mstatus_mask = mstatus_mask
        self.producer_id = producer_id

        self.old_sum_mprv = fuzzerstate.status_sum_mprv

        self.csr_instr = CSRRegInstruction(instr_str, rd, rs1, CSR_IDS.MSTATUS)

    def gen_bytecode_int(self, is_spike_resolution: bool):
        return self.csr_instr.gen_bytecode_int(is_spike_resolution)

    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = False):
        return self.csr_instr.get_str() + f" ({self.instr_str})"

    def reset_addr(self):
        self.csr_instr.reset_addr()
        return super().reset_addr()


# @remark we use a specific instruction for xtvec to find them easily when an exception occurs, to transmit back the expected value to the producer
# @brief this instruction writes to mtvec or stvec
class TvecWriterInstruction(BaseInstruction):
    def __init__(self, fuzzerstate, is_mtvec: bool, rd: int, rs1: int, producer_id: int):
        super().__init__(fuzzerstate,"TvecWriterInstruction")
        self.producer_id = producer_id
        self.is_mtvec = is_mtvec # A bit redundant with the content of csr_instr, but practical.
        csr_id = CSR_IDS.MTVEC if is_mtvec else CSR_IDS.STVEC
        self.csr_instr = CSRRegInstruction(fuzzerstate, "csrrw", rd, rs1, csr_id)
        assert self.paddr == self.csr_instr.paddr

    def gen_bytecode_int(self, is_spike_resolution: bool):
        return self.csr_instr.gen_bytecode_int(is_spike_resolution)

    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = False):
        return self.csr_instr.get_str() + f" ({self.instr_str} for {self.producer_id})"

    def reset_addr(self):
        self.csr_instr.reset_addr()
        return super().reset_addr()

# @remark we use a specific instruction for xtvec to find them easily when an exception occurs, to transmit back the expected value to the producer
# @brief this instruction writes to mepc or sepc
class EPCWriterInstruction(BaseInstruction):
    def __init__(self, fuzzerstate, is_mepc: bool, rd: int, rs1: int, producer_id: int):
        super().__init__(fuzzerstate,'EPCWriterInstruction')
        self.producer_id = producer_id
        self.is_mepc = is_mepc # A bit redundant with the content of csr_instr, but practical.

        csr_id = CSR_IDS.MEPC if is_mepc else CSR_IDS.SEPC
        self.csr_instr = CSRRegInstruction(fuzzerstate, "csrrw", rd, rs1, csr_id)
        assert self.paddr == self.csr_instr.paddr

    def gen_bytecode_int(self, is_spike_resolution: bool):
        return self.csr_instr.gen_bytecode_int(is_spike_resolution)
    
    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = False):
        return self.csr_instr.get_str() + f" ({self.instr_str} for {self.producer_id})"

    def reset_addr(self):
        self.csr_instr.reset_addr()
        return super().reset_addr()

# @brief this instruction writes to mtvec or stvec
# @The value written may differ between Spike and CPU
class GenericCSRWriterInstruction(BaseInstruction):
    def __init__(self, fuzzerstate, csr_id: int, rd: int, rs1: int, producer_id: int, val_to_write_spike: int, val_to_write_cpu: int):
        super().__init__(fuzzerstate,'GenericCSRWriterInstruction')
        if DO_ASSERT:
            assert csr_id in CSR_IDS
            # These two CSRs are treated separately in TvecWriterInstruction
            assert csr_id != CSR_IDS.MTVEC and csr_id != CSR_IDS.STVEC
            # Currently to ease analysis, we impose val_to_write_spike == val_to_write_cpu

        self.producer_id = producer_id
        self.csr_id = csr_id
        self.val_to_write_spike = val_to_write_spike
        self.val_to_write_cpu = val_to_write_cpu
        assert val_to_write_cpu == val_to_write_spike

        self.csr_instr = CSRRegInstruction(fuzzerstate,"csrrw", rd, rs1, csr_id)
        assert self.paddr == self.csr_instr.paddr

    def gen_bytecode_int(self, is_spike_resolution: bool):
        return self.csr_instr.gen_bytecode_int(is_spike_resolution)
    
    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = False):
        return self.csr_instr.get_str() + f" ({self.instr_str} for {self.producer_id})"

    def reset_addr(self):
        self.csr_instr.reset_addr()
        return super().reset_addr()

class PrivilegeDescentInstruction(BaseInstruction):
    def __init__(self, fuzzerstate,is_mret: bool):
        super().__init__(fuzzerstate, "mret" if is_mret else "sret")
        self.is_mret = is_mret
        self.va_layout_after_op = fuzzerstate.effective_curr_layout # The layout that is entered after we descend privilege.
        self.priv_level_after_op = fuzzerstate.privilegestate.privstate # The privstate has already been changed at this point.

    def gen_bytecode_int(self, is_spike_resolution: bool):
        if self.is_mret:
            return rvprivileged_mret()
        else:
            return rvprivileged_sret()


def is_spike_design_addr_mismatch_instr(instr: BaseInstruction):
    return isinstance(instr, (JALRInstruction, JALInstruction, PlaceholderProducerInstr0, PlaceholderProducerInstr1,PlaceholderPreConsumerInstr, PlaceholderConsumerInstr)) or "auipc" in instr.instr_str
