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

