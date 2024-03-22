from cascade.cfinstructionclasses import R12DInstruction, RegImmInstruction, ImmRdInstruction
from cascade.registers import Int32RegState
import ctypes
MAX_32b = 0xFFFFFFFF


## R12DInstrucions ##
class AddInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("add", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        self.fuzzerstate.intregpickstate.regs[self.rd].val.value = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value + self.fuzzerstate.intregpickstate.regs[self.rs2].val.value

class SubInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sub", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        self.fuzzerstate.intregpickstate.regs[self.rd].val.value = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value - self.fuzzerstate.intregpickstate.regs[self.rs2].val.value

class SllInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sll", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        self.fuzzerstate.intregpickstate.regs[self.rd].val.value = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value << self.fuzzerstate.intregpickstate.regs[self.rs2].val.value

class SltInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("slt", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        self.fuzzerstate.intregpickstate.regs[self.rd].val.value = ctypes.c_int32(self.fuzzerstate.intregpickstate.regs[self.rs1].val.value).value < ctypes.c_int32(self.fuzzerstate.intregpickstate.regs[self.rs2].val.value).value

class SltuInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sltu", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        self.fuzzerstate.intregpickstate.regs[self.rd].val.value = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value < self.fuzzerstate.intregpickstate.regs[self.rs2].val.value

class XorInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("xor", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        self.fuzzerstate.intregpickstate.regs[self.rd].val.value = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value ^ self.fuzzerstate.intregpickstate.regs[self.rs2].val.value

class SrlInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("srl", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        self.fuzzerstate.intregpickstate.regs[self.rd].val.value = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value >> self.fuzzerstate.intregpickstate.regs[self.rs2].val.value

class SraInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sra", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].val.value
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs2].val.value
        shamt = rs2_val
        mask = MAX_32b<<(32-shamt)
        mask &= MAX_32b
        rd_val = (rs1_val >> shamt) | mask
        self.fuzzerstate.intregpickstate.regs[self.rd].val.value = rd_val


class OrInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("or", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        self.fuzzerstate.intregpickstate.regs[self.rd].val.value = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value | self.fuzzerstate.intregpickstate.regs[self.rs2].val.value

class AndInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("and", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        self.fuzzerstate.intregpickstate.regs[self.rd].val.value = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value & self.fuzzerstate.intregpickstate.regs[self.rs2].val.value






## RegImmInstructions ##
class AddiInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("addi", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        self.fuzzerstate.intregpickstate.regs[self.rd].val.value = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value + ctypes.c_uint32(self.imm).value

class SlliInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("slli", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        self.fuzzerstate.intregpickstate.regs[self.rd].val.value = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value << ctypes.c_uint32(self.imm).value

class SltiInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("slti", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        self.fuzzerstate.intregpickstate.regs[self.rd].val.value = ctypes.c_int32(self.fuzzerstate.intregpickstate.regs[self.rs1].val.value).value < ctypes.c_int32(ctypes.c_uint32(self.imm).value).value

class SltiuInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sltiu", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        self.fuzzerstate.intregpickstate.regs[self.rd].val.value = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value < ctypes.c_uint32(self.imm).value

class XoriInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("xori", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        self.fuzzerstate.intregpickstate.regs[self.rd].val.value = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value ^ ctypes.c_uint32(self.imm).value

class SrliInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("srli", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        self.fuzzerstate.intregpickstate.regs[self.rd].val.value = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value >> ctypes.c_uint32(self.imm).value

class SraiInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("srai", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        imm_val = ctypes.c_uint32(self.imm).value
        rs1_val = ctypes.c_uint32(self.imm).value
        shamt = imm_val
        mask = MAX_32b<<(32-shamt)
        mask &= MAX_32b
        rd_val = (rs1_val >> shamt) | mask
        self.fuzzerstate.intregpickstate.regs[self.rd].val.value = rd_val


class OriInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("ori", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        self.fuzzerstate.intregpickstate.regs[self.rd].val.value = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value | ctypes.c_uint32(self.imm).value

class AndiInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("andi", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        self.fuzzerstate.intregpickstate.regs[self.rd].val.value = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value & ctypes.c_uint32(self.imm).value



## ImmRdInstructions ##
class LuiInstruction(ImmRdInstruction):
    def __init__(self, rd: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("lui", rd, imm, fuzzerstate.is_design_64bit, iscompressed, False, fuzzerstate)   

    def execute(self):
        self.fuzzerstate.intregpickstate.regs[self.rd].val.value = ctypes.c_uint32(self.imm).value

class AuipcInstruction(ImmRdInstruction):
    def __init__(self, rd: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("auipc", rd, imm, fuzzerstate.is_design_64bit, iscompressed, False, fuzzerstate)   

    def execute(self):
        pass



