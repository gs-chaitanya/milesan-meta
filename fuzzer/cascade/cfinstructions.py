from cascade.cfinstructionclasses import R12DInstruction, RegImmInstruction, ImmRdInstruction
from cascade.registers import Int32RegState
import ctypes
MAX_32b = 0xFFFFFFFF
MAX_64b = 0xFFFFFFFFFFFFFFFF

## R12DInstrucions ##
class AddInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("add", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value + self.fuzzerstate.intregpickstate.regs[self.rs2].val.value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SubInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sub", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value - self.fuzzerstate.intregpickstate.regs[self.rs2].val.value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SllInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sll", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        shamt =  self.fuzzerstate.intregpickstate.regs[self.rs2].val.value & 0x1F
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value << shamt
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SltInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("slt", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        res = ctypes.c_int32(self.fuzzerstate.intregpickstate.regs[self.rs1].val.value).value < ctypes.c_int32(self.fuzzerstate.intregpickstate.regs[self.rs2].val.value).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SltuInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sltu", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value < self.fuzzerstate.intregpickstate.regs[self.rs2].val.value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class XorInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("xor", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value ^ self.fuzzerstate.intregpickstate.regs[self.rs2].val.value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SrlInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("srl", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        shamt =  self.fuzzerstate.intregpickstate.regs[self.rs2].val.value & 0x1F
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value >> shamt
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)


class SraInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sra", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].val.value
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs2].val.value
        shamt = rs2_val&0x1F
        mask = MAX_32b<<(32-shamt)
        mask &= MAX_32b
        rd_val = (rs1_val >> shamt) | mask
        res = rd_val
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)


class OrInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("or", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value | self.fuzzerstate.intregpickstate.regs[self.rs2].val.value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class AndInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("and", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value & self.fuzzerstate.intregpickstate.regs[self.rs2].val.value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)






## RegImmInstructions ##
class AddiInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("addi", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value + ctypes.c_uint32(self.imm).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SlliInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("slli", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value << ctypes.c_uint32(self.imm).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SltiInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("slti", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        res = ctypes.c_int32(self.fuzzerstate.intregpickstate.regs[self.rs1].val.value).value < ctypes.c_int32(ctypes.c_uint32(self.imm).value).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SltiuInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sltiu", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value < ctypes.c_uint32(self.imm).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class XoriInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("xori", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value ^ ctypes.c_uint32(self.imm).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SrliInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("srli", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val() >> ctypes.c_uint32(self.imm).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SraiInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("srai", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        imm_val = ctypes.c_uint64(self.imm).value if self.is_design_64bit else ctypes.c_uint32(self.imm).value
        n_bits = 63 if self.is_design_64bit else 31
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        msb = (rs1_val>>n_bits)&1
        shamt = imm_val
        mask = MAX_32b<<(n_bits-shamt)
        mask &= MAX_32b
        res = (rs1_val >> shamt) | (mask*msb)
        # print(f"msb: {msb}: is 64 bit: {self.is_design_64bit}: rs1: {rs1_val}")
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)


class OriInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("ori", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value | ctypes.c_uint32(self.imm).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class AndiInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("andi", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value & ctypes.c_uint32(self.imm).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)



## ImmRdInstructions ##
class LuiInstruction(ImmRdInstruction):
    def __init__(self, rd: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("lui", rd, imm, fuzzerstate.is_design_64bit, iscompressed, False, fuzzerstate)   

    def execute(self):
        res = ctypes.c_uint32(self.imm).value<<12 # TODO: sign-extend to 64 bits
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class AuipcInstruction(ImmRdInstruction):
    def __init__(self, rd: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("auipc", rd, imm, fuzzerstate.is_design_64bit, iscompressed, False, fuzzerstate)   

    def execute(self): # TODO: sign extension not right I think
        imm_val = ctypes.c_uint32(self.imm).value & 0xFFFFF # 20 bit immediate
        # msb = (imm_val>>19)&1
        mask = (MAX_64b<<32)&MAX_64b # extend to 64 bits
        uimm = (imm_val & 0xFFFFF) << 12
        res = self.addr+uimm
        msb = (res>>31)&1
        res |= (mask*msb)
        # print(f"msb:{msb}: uimm: {hex(uimm)}, pc: {hex(self.addr)}, imm: {hex(ctypes.c_uint32(self.imm).value)} res: {hex(res)}")
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)






