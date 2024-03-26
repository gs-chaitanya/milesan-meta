from cascade.cfinstructionclasses import *
from cascade.registers import Int32RegState
from rv.asmutil import li_into_reg, twos_complement, to_unsigned
import ctypes
MAX_32b = 0xFFFFFFFF
MAX_64b = 0xFFFFFFFFFFFFFFFF

## R12DInstrucions ##
class AddInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("add", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value + self.fuzzerstate.intregpickstate.regs[self.rs2].val.value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SubInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sub", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value - self.fuzzerstate.intregpickstate.regs[self.rs2].val.value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SllInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sll", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        shamt =  self.fuzzerstate.intregpickstate.regs[self.rs2].val.value & 0x1F
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value << shamt
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SltInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("slt", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = ctypes.c_int32(self.fuzzerstate.intregpickstate.regs[self.rs1].val.value).value < ctypes.c_int32(self.fuzzerstate.intregpickstate.regs[self.rs2].val.value).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SltuInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sltu", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value < self.fuzzerstate.intregpickstate.regs[self.rs2].val.value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class XorInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("xor", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value ^ self.fuzzerstate.intregpickstate.regs[self.rs2].val.value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SrlInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("srl", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        shamt =  self.fuzzerstate.intregpickstate.regs[self.rs2].val.value & 0x1F
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value >> shamt
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)


class SraInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sra", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
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
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value | self.fuzzerstate.intregpickstate.regs[self.rs2].val.value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class AndInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("and", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value & self.fuzzerstate.intregpickstate.regs[self.rs2].val.value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)






## RegImmInstructions ##
class AddiInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("addi", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value + ctypes.c_uint32(self.imm).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SlliInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("slli", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value << ctypes.c_uint32(self.imm).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SltiInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("slti", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = ctypes.c_int32(self.fuzzerstate.intregpickstate.regs[self.rs1].val.value).value < ctypes.c_int32(ctypes.c_uint32(self.imm).value).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SltiuInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sltiu", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value < ctypes.c_uint32(self.imm).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class XoriInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("xori", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value ^ ctypes.c_uint32(self.imm).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SrliInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("srli", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val() >> ctypes.c_uint32(self.imm).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SraiInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("srai", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
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
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].val.value | ctypes.c_uint32(self.imm).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class AndiInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("andi", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
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
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        imm_val = ctypes.c_uint32(self.imm).value & 0xFFFFF # 20 bit immediate
        # msb = (imm_val>>19)&1
        mask = (MAX_64b<<32)&MAX_64b # extend to 64 bits
        uimm = (imm_val & 0xFFFFF) << 12
        res = self.addr+uimm
        msb = (res>>31)&1
        res |= (mask*msb)
        # print(f"msb:{msb}: uimm: {hex(uimm)}, pc: {hex(self.addr)}, imm: {hex(ctypes.c_uint32(self.imm).value)} res: {hex(res)}")
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)


class JalInstruction(JALInstruction):
    def __init__(self, rd: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("jal", rd, imm, iscompressed, fuzzerstate)   

    def execute(self):
        res = self.addr+4
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class JalrInstruction(JALRInstruction):
    def __init__(self, instr_str: str, rd: int, rs1: int, imm: int, producer_id: int, is_design_64bit: bool, iscompressed: bool = False, fuzzerstate=None):
        super().__init__(instr_str, rd, rs1, imm, producer_id, is_design_64bit, iscompressed, fuzzerstate)

    def execute(self):
        res = self.addr+4
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)



## Extended Placeholder Instructions ##
#TODO: all these need to be adjusted for non-spike resolution execution
class ExtPlaceholderProducerInstr0(PlaceholderProducerInstr0):
    def __init__(self, rd: int, producer_id: int, is_design_64bit: bool, fuzzerstate = None):
        super().__init__(rd, producer_id, is_design_64bit, fuzzerstate)

    def execute(self):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        imm = li_into_reg(to_unsigned(self.spike_resolution_offset, self.is_design_64bit), False)[0]
        res = ctypes.c_uint32(imm).value<<12 # TODO: sign-extend to 64 bits
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def check_regs(self,reg_cmp,pc): # TODO: check rdep, rprod for spike_resolution or final elf
        mismatch = self.fuzzerstate.intregpickstate.regs[self.rd].check(reg_cmp[0],pc)
        assert not mismatch, f"{hex(mismatch[0])}: {self.instr_str}: Value mismatch for {mismatch[1]}: {hex(mismatch[2])} != {hex(mismatch[3])}\n\t Traceback: {compute_reg_traceback(self.rd,self.addr,self.fuzzerstate).get_str()}"

class ExtPlaceholderProducerInstr1(PlaceholderProducerInstr1):
    def __init__(self, rd: int, producer_id: int, is_design_64bit: bool, fuzzerstate = None):
        super().__init__(rd, producer_id, is_design_64bit, fuzzerstate)

    def execute(self):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        imm = li_into_reg(to_unsigned(self.spike_resolution_offset, self.is_design_64bit), False)[1]
        res = self.fuzzerstate.intregpickstate.regs[self.rd].val.value + ctypes.c_uint32(imm).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def check_regs(self,reg_cmp,pc):
        mismatch = self.fuzzerstate.intregpickstate.regs[self.rd].check(reg_cmp[0],pc)
        assert not mismatch, f"{hex(mismatch[0])}: {self.instr_str}: Value mismatch for {mismatch[1]}: {hex(mismatch[2])} != {hex(mismatch[3])}\n\t Traceback: {compute_reg_traceback(self.rd,self.addr,self.fuzzerstate).get_str()}"

class ExtPlaceholderPreConsumerInstr(PlaceholderPreConsumerInstr):
    def __init__(self,rdep: int,fuzzerstate = None):
        super().__init__(rdep, fuzzerstate)   

    def execute(self):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rdep].val.value & self.fuzzerstate.intregpickstate.regs[RDEP_MASK_REGISTER_ID].val.value
        self.fuzzerstate.intregpickstate.regs[self.rdep].set_val(res)

    def check_regs(self,reg_cmp,pc): # rdep and rs1 should be the same register
        assert len(reg_cmp) == 2, f"Missing registers for check_regs: got{len(reg_cmp)}, require 2."
        for i,reg in enumerate([self.rdep, RDEP_MASK_REGISTER_ID]):
            mismatch = self.fuzzerstate.intregpickstate.regs[reg].check(reg_cmp[i],pc)
            assert not mismatch, f"{hex(mismatch[0])}: {self.instr_str}: Value mismatch for {mismatch[1]}: {hex(mismatch[2])} != {hex(mismatch[3])}\n\t Traceback: {compute_reg_traceback(reg,self.addr,self.fuzzerstate).get_str()}"

class ExtPlaceholderConsumerInstr(PlaceholderConsumerInstr):
    def __init__(self, rd: int, rdep: int, rprod: int, producer_id: int, fuzzerstate = None):
        super().__init__(rd, rdep, rprod, producer_id, fuzzerstate)   

    def execute(self):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rprod].val.value ^ self.fuzzerstate.intregpickstate.regs[RELOCATOR_REGISTER_ID].val.value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def check_regs(self,reg_cmp,pc): # TODO: check rdep, rprod for spike_resolution or final elf
        assert len(reg_cmp) == 3, f"Missing registers for check_regs: got{len(reg_cmp)}, require 3."
        for i,reg in enumerate([self.rd, self.rprod, RELOCATOR_REGISTER_ID]):
            mismatch = self.fuzzerstate.intregpickstate.regs[reg].check(reg_cmp[i],pc)
            assert not mismatch, f"{hex(mismatch[0])}: {self.instr_str}: Value mismatch for {mismatch[1]}: {hex(mismatch[2])} != {hex(mismatch[3])}\n\t Traceback: {compute_reg_traceback(reg,self.addr,self.fuzzerstate).get_str()}"
