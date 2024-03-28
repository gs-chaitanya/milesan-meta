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

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val() + self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        # Compute taint propagation before writing back result
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self, res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        # Left side of the xor
        rs1_and_not_rs1_taint = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val() & (~self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0())
        rs2_and_not_rs2_taint = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val() & (~self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_t0())
        rs1_plus_rs2_not_taints = rs1_and_not_rs1_taint + rs2_and_not_rs2_taint # Smallest possible result

        # Right side of the xor
        rs1_and_rs1_taint = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val() & self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        rs2_and_rs2_taint = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val() & self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_t0()
        rs1_plus_rs2_taints = rs1_and_rs1_taint + rs2_and_rs2_taint # Largest possible result

        polarization = rs1_plus_rs2_not_taints ^ rs1_plus_rs2_taints

        transport = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0() | self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_t0()

        # The result of the shadow addition.
        res_t0 = polarization | transport
      
        self.writeback_t0(res_t0, res)
        
class SubInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sub", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val() - self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        # Compute taint propagation before writing back result
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self, res): # TODO: sign-extension?
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_and_not_rs1_taint = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val() & (~self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0())
        rs2_and_not_rs2_taint = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val() & (~self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_t0())

        rs1_or_rs1_taint = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val() | self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        rs2_or_rs2_taint = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val() | self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_t0()
        
        rs1_one_minus_rs2_zero = rs1_or_rs1_taint - rs2_and_not_rs2_taint # Largest term from max possible r1 value and smallest possible r2 value
        rs2_zero_minus_rs1_one = rs1_and_not_rs1_taint - rs2_or_rs2_taint # Smallest term from smallest possible rs1 and largest possible rs2

        polarization = rs1_one_minus_rs2_zero ^ rs2_zero_minus_rs1_one

        transport = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0() | self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_t0()

        # The result of the addition.
        res_t0 = polarization | transport

        # print(f"res_t0: {hex(res_t0)}")        
        self.writeback_t0(res_t0, res)



class SllInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sll", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        shamt =  self.fuzzerstate.intregpickstate.regs[self.rs2].get_val() & 0x1F
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val() << shamt
        # Compute taint before writing back result
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)
            
    def execute_t0(self, res): #TODO: also implement precise shift?
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        if self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_t0() & 0x1F: # rs2 is tainted so result is fully tainted
            res_t0 = MAX_32b
        else:
            shamt = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val() & 0x1F 
            res_t0 = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_t0()  << shamt
        self.writeback_t0(res_t0, res)

class SltInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("slt", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = ctypes.c_int32(self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()).value < ctypes.c_int32(self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self,res):#TODO: 
        signed_rs1 = ctypes.c_int32(self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()).value
        signed_rs2 = ctypes.c_int32(self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()).value
        rs1_and_not_rs1_taint = signed_rs1 & (~self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0())
        rs2_and_not_rs2_taint = signed_rs2 & (~self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_t0())

        rs1_or_rs1_taint = signed_rs1 | self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        rs2_or_rs2_taint = signed_rs2 | self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_t0()
        
        min_res = rs1_and_not_rs1_taint
class SltuInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sltu", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val() < self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class XorInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("xor", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val() ^ self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SrlInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("srl", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        shamt =  self.fuzzerstate.intregpickstate.regs[self.rs2].get_val() & 0x1F
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val() >> shamt
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)


class SraInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sra", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        shamt = rs2_val&0x1F
        mask = MAX_32b<<(32-shamt)
        mask &= MAX_32b
        rd_val = (rs1_val >> shamt) | mask
        res = rd_val
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)


class OrInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("or", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val() | self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class AndInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("and", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val() & self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)






## RegImmInstructions ##
class AddiInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("addi", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val() + ctypes.c_uint32(self.imm).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SlliInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("slli", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val() << ctypes.c_uint32(self.imm).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SltiInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("slti", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = ctypes.c_int32(self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()).value < ctypes.c_int32(ctypes.c_uint32(self.imm).value).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SltiuInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sltiu", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val() < ctypes.c_uint32(self.imm).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class XoriInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("xori", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val() ^ ctypes.c_uint32(self.imm).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SrliInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("srli", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val() >> ctypes.c_uint32(self.imm).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class SraiInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("srai", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
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

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val() | ctypes.c_uint32(self.imm).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class AndiInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("andi", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val() & ctypes.c_uint32(self.imm).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)



## ImmRdInstructions ##
class LuiInstruction(ImmRdInstruction):
    def __init__(self, rd: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("lui", rd, imm, fuzzerstate.is_design_64bit, iscompressed, False, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        res = ctypes.c_uint32(self.imm).value<<12 # TODO: sign-extend to 64 bits
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class AuipcInstruction(ImmRdInstruction):
    def __init__(self, rd: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("auipc", rd, imm, fuzzerstate.is_design_64bit, iscompressed, False, fuzzerstate)   

    def execute(self, taint_en: bool = False): # TODO: sign extension not right I think
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

    def execute(self, taint_en: bool = False):
        res = self.addr+4
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

class JalrInstruction(JALRInstruction):
    def __init__(self, instr_str: str, rd: int, rs1: int, imm: int, producer_id: int, is_design_64bit: bool, iscompressed: bool = False, fuzzerstate=None):
        super().__init__(instr_str, rd, rs1, imm, producer_id, is_design_64bit, iscompressed, fuzzerstate)

    def execute(self, taint_en: bool = False):
        res = self.addr+4
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)



## Extended Placeholder Instructions ##
#TODO: all these need to be adjusted for non-spike resolution execution
class ExtPlaceholderProducerInstr0(PlaceholderProducerInstr0):
    def __init__(self, rd: int, producer_id: int, is_design_64bit: bool, fuzzerstate = None):
        super().__init__(rd, producer_id, is_design_64bit, fuzzerstate)

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        imm = li_into_reg(to_unsigned(self.spike_resolution_offset, self.is_design_64bit), False)[0]
        res = ctypes.c_uint32(imm).value<<12 # TODO: sign-extend to 64 bits
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def check_regs(self,reg_cmp,pc): # TODO: check rdep, rprod for spike_resolution or final elf
        mismatch = self.fuzzerstate.intregpickstate.regs[self.rd].check(reg_cmp[self.rd],pc)
        assert not mismatch, f"{hex(mismatch[0])}: {self.instr_str}: Value mismatch for {mismatch[1]}: {hex(mismatch[2])} != {hex(mismatch[3])}\n\t Traceback: {compute_reg_traceback(self.rd,self.addr,self.fuzzerstate).get_str()}"

class ExtPlaceholderProducerInstr1(PlaceholderProducerInstr1):
    def __init__(self, rd: int, producer_id: int, is_design_64bit: bool, fuzzerstate = None):
        super().__init__(rd, producer_id, is_design_64bit, fuzzerstate)

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        imm = li_into_reg(to_unsigned(self.spike_resolution_offset, self.is_design_64bit), False)[1]
        res = self.fuzzerstate.intregpickstate.regs[self.rd].get_val() + ctypes.c_uint32(imm).value
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def check_regs(self,reg_cmp,pc):
        mismatch = self.fuzzerstate.intregpickstate.regs[self.rd].check(reg_cmp[self.rd],pc)
        assert not mismatch, f"{hex(mismatch[0])}: {self.instr_str}: Value mismatch for {mismatch[1]}: {hex(mismatch[2])} != {hex(mismatch[3])}\n\t Traceback: {compute_reg_traceback(self.rd,self.addr,self.fuzzerstate).get_str()}"

class ExtPlaceholderPreConsumerInstr(PlaceholderPreConsumerInstr):
    def __init__(self,rdep: int,fuzzerstate = None):
        super().__init__(rdep, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rdep].get_val() & self.fuzzerstate.intregpickstate.regs[RDEP_MASK_REGISTER_ID].get_val()
        self.fuzzerstate.intregpickstate.regs[self.rdep].set_val(res)

    def check_regs(self,reg_cmp,pc): # rdep and rs1 should be the same register
        assert len(reg_cmp) == len(set([self.rdep, RDEP_MASK_REGISTER_ID])), f"Missing registers for check_regs: got {len(reg_cmp)}, require {len(set([self.rdep, RDEP_MASK_REGISTER_ID]))}."
        for reg in [self.rdep, RDEP_MASK_REGISTER_ID]:
            mismatch = self.fuzzerstate.intregpickstate.regs[reg].check(reg_cmp[reg],pc)
            assert not mismatch, f"{hex(mismatch[0])}: {self.instr_str}: Value mismatch for {mismatch[1]}: {hex(mismatch[2])} != {hex(mismatch[3])}\n\t Traceback: {compute_reg_traceback(reg,self.addr,self.fuzzerstate).get_str()}"

class ExtPlaceholderConsumerInstr(PlaceholderConsumerInstr):
    def __init__(self, rd: int, rdep: int, rprod: int, producer_id: int, fuzzerstate = None):
        super().__init__(rd, rdep, rprod, producer_id, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rprod].get_val() ^ self.fuzzerstate.intregpickstate.regs[RELOCATOR_REGISTER_ID].get_val()
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def check_regs(self,reg_cmp,pc): # TODO: check rdep, rprod for spike_resolution or final elf
        assert len(reg_cmp) == len(set([self.rd, self.rprod, RELOCATOR_REGISTER_ID])), f"Missing registers for check_regs: got {len(reg_cmp)}, require {len(set([self.rd, self.rprod, RELOCATOR_REGISTER_ID]))}."
        for reg in [self.rd, self.rprod, RELOCATOR_REGISTER_ID]:
            mismatch = self.fuzzerstate.intregpickstate.regs[reg].check(reg_cmp[reg],pc)
            assert not mismatch, f"{hex(mismatch[0])}: {self.instr_str}: Value mismatch for {mismatch[1]}: {hex(mismatch[2])} != {hex(mismatch[3])}\n\t Traceback: {compute_reg_traceback(reg,self.addr,self.fuzzerstate).get_str()}"
