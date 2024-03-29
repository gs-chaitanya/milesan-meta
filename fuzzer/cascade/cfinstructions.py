from cascade.cfinstructionclasses import *
from cascade.registers import Int32RegState
from rv.asmutil import *
import ctypes

    
## R12DInstrucions ##
class AddInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("add", rd, rs1, rs2, iscompressed, fuzzerstate)   

        
class SubInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sub", rd, rs1, rs2, iscompressed, fuzzerstate)   


class SllInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sll", rd, rs1, rs2, iscompressed, fuzzerstate)   

class SltInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("slt", rd, rs1, rs2, iscompressed, fuzzerstate)   

class SltuInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sltu", rd, rs1, rs2, iscompressed, fuzzerstate)   

class XorInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("xor", rd, rs1, rs2, iscompressed, fuzzerstate)   

class SrlInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("srl", rd, rs1, rs2, iscompressed, fuzzerstate)   

class SraInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sra", rd, rs1, rs2, iscompressed, fuzzerstate)   

class OrInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("or", rd, rs1, rs2, iscompressed, fuzzerstate)   

class AndInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("and", rd, rs1, rs2, iscompressed, fuzzerstate)   

## RegImmInstructions ##
class AddiInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("addi", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

class SlliInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("slli", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

class SltiInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("slti", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

class SltiuInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sltiu", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

class XoriInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("xori", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

class SrliInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("srli", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

class SraiInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("srai", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

class OriInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("ori", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

class AndiInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("andi", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

## ImmRdInstructions ##
class LuiInstruction(ImmRdInstruction):
    def __init__(self, rd: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("lui", rd, imm, fuzzerstate.is_design_64bit, iscompressed, False, fuzzerstate)   

class AuipcInstruction(ImmRdInstruction):
    def __init__(self, rd: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("auipc", rd, imm, fuzzerstate.is_design_64bit, iscompressed, False, fuzzerstate)   
        
class JalInstruction(JALInstruction):
    def __init__(self, rd: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("jal", rd, imm, iscompressed, fuzzerstate)   

class JalrInstruction(JALRInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, producer_id: int, is_design_64bit: bool, iscompressed: bool = False, fuzzerstate=None):
        super().__init__("jalr", rd, rs1, imm, producer_id, is_design_64bit, iscompressed, fuzzerstate)




## Extended Placeholder Instructions ##
#TODO: all these need to be adjusted for non-spike resolution execution
class ExtPlaceholderProducerInstr0(PlaceholderProducerInstr0):
    def __init__(self, rd: int, producer_id: int, is_design_64bit: bool, fuzzerstate = None):
        super().__init__(rd, producer_id, is_design_64bit, fuzzerstate)

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        imm = li_into_reg(to_unsigned(self.spike_resolution_offset, self.is_design_64bit), False)[0]
        res = to_unsigned(imm, self.fuzzerstate.is_design_64bit)<<12
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self, res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        self.writeback_t0(0x0,res)

        
class ExtPlaceholderProducerInstr1(PlaceholderProducerInstr1):
    def __init__(self, rd: int, producer_id: int, is_design_64bit: bool, fuzzerstate = None):
        super().__init__(rd, producer_id, is_design_64bit, fuzzerstate)

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        uimm = li_into_reg(to_unsigned(self.spike_resolution_offset, self.is_design_64bit), False)[1]
        res = self.fuzzerstate.intregpickstate.regs[self.rd].get_val() + uimm
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self, res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        self.writeback_t0(0x0,res)

class ExtPlaceholderPreConsumerInstr(PlaceholderPreConsumerInstr):
    def __init__(self,rdep: int,fuzzerstate = None):
        super().__init__(rdep, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rdep].get_val() & self.fuzzerstate.intregpickstate.regs[RDEP_MASK_REGISTER_ID].get_val()
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rdep].set_val(res)

    def execute_t0(self, res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rdep = self.fuzzerstate.intregpickstate.regs[self.rdep].get_val()
        rmask = self.fuzzerstate.intregpickstate.regs[RDEP_MASK_REGISTER_ID].get_val()

        rdep_taint = self.fuzzerstate.intregpickstate.regs[self.rdep].get_val_t0()
        rmask_taint = self.fuzzerstate.intregpickstate.regs[RDEP_MASK_REGISTER_ID].get_val_t0()

        rdep_and_rmask_taint= rdep & rmask_taint
        rmask_and_rdep_taint = rmask & rdep_taint

        rdep_and_rmask_taint = rdep_taint & rmask_taint
        rdep_taint_and_rmask_or_reverse = rdep_and_rmask_taint | rmask_and_rdep_taint

        res_t0 = rdep_and_rmask_taint | rdep_taint_and_rmask_or_reverse

        self.writeback_t0(res_t0, res)

class ExtPlaceholderConsumerInstr(PlaceholderConsumerInstr):
    def __init__(self, rd: int, rdep: int, rprod: int, producer_id: int, fuzzerstate = None):
        super().__init__(rd, rdep, rprod, producer_id, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rprod].get_val() ^ self.fuzzerstate.intregpickstate.regs[RELOCATOR_REGISTER_ID].get_val()
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self, res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res_t0 = self.fuzzerstate.intregpickstate.regs[self.rprod].get_val_t0() ^ self.fuzzerstate.intregpickstate.regs[RELOCATOR_REGISTER_ID].get_val_t0()
        self.writeback_t0(res_t0,res)

