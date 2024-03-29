from cascade.cfinstructionclasses import *
from cascade.registers import Int32RegState
from rv.asmutil import *
import ctypes

    
## R12DInstrucions ##
class AddInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("add", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        res = add(rs1_val,rs2_val, self.fuzzerstate.is_design_64bit)
        # Compute taint propagation before writing back result
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self, res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        rs2_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_t0()
        # Compute the taint results of the operation.
        res_t0 = add_t0(rs1_val, rs1_val_t0, rs2_val, rs2_val_t0)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res,add)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res)
        
class SubInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sub", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        res = sub(rs1_val,rs2_val, self.fuzzerstate.is_design_64bit)
        # Compute taint propagation before writing back result
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self, res): # TODO: sign-extension?
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        rs2_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_t0()
        # Compute the taint results of the operation.
        res_t0 = sub_t0(rs1_val, rs1_val_t0, rs2_val, rs2_val_t0)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res,sub)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res)


class SllInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sll", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        res = sll(rs1_val,rs2_val, self.fuzzerstate.is_design_64bit)
        # Compute taint before writing back result
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)
            
    def execute_t0(self, res): # TODO: sign-extension?
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        rs2_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_t0()
        # Compute the taint results of the operation.
        res_t0 = sll_t0(rs1_val, rs1_val_t0, rs2_val, rs2_val_t0)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res,sll)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res)

class SltInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("slt", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False): # convert unsigned to signed
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        res = slt(rs1_val, rs2_val, self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self,res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        rs2_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_t0()
        # Compute the taint results of the operation.
        res_t0 = slt_t0(rs1_val, rs1_val_t0, rs2_val, rs2_val_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res,slt)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res)

class SltuInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sltu", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        res = sltu(rs1_val,rs2_val, self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self,res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        rs2_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_t0()
        # Compute the taint results of the operation.
        res_t0 = sltu_t0(rs1_val, rs1_val_t0, rs2_val, rs2_val_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res,sltu)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res)

class XorInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("xor", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        res = xor(rs1_val,rs2_val, self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self,res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        rs2_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_t0()
        # Compute the taint results of the operation.
        res_t0 = xor_t0(rs1_val, rs1_val_t0, rs2_val, rs2_val_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res,xor)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res)

class SrlInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("srl", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        res = srl(rs1_val,rs2_val,self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)
    
    def execute_t0(self,res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        rs2_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_t0()
        # Compute the taint results of the operation.
        res_t0 = srl_t0(rs1_val, rs1_val_t0, rs2_val, rs2_val_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res,srl)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res)


class SraInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sra", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        res = sra(rs1_val,rs2_val, self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self,res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        rs2_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_t0()
        # Compute the taint results of the operation.
        res_t0 = sra_t0(rs1_val, rs1_val_t0, rs2_val, rs2_val_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res,sra)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res)


class OrInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("or", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        res = or_(rs1_val,rs2_val, self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self,res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        rs2_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_t0()
        # Compute the taint results of the operation.
        res_t0 = or_t0(rs1_val, rs1_val_t0, rs2_val, rs2_val_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res,or_)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res)

class AndInstruction(R12DInstruction):
    def __init__(self, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("and", rd, rs1, rs2, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        res = and_(rs1_val,rs2_val,self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self,res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        rs2_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_t0()
        # Compute the taint results of the operation.
        res_t0 = and_t0(rs1_val, rs1_val_t0, rs2_val, rs2_val_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res,and_)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res)



## RegImmInstructions ##
class AddiInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("addi", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        res = addi(rs1_val, self.imm, self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self,res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        # Compute the taint results of the operation.
        res_t0 = addi_t0(rs1_val, rs1_val_t0, self.imm, self.imm_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res,addi)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res)

class SlliInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("slli", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        res = slli(rs1_val,self.imm, self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self,res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        # Compute the taint results of the operation.
        res_t0 = slli_t0(rs1_val, rs1_val_t0, self.imm, self.imm_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res,slli)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res)



class SltiInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("slti", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        res = slti(rs1_val, self.imm, self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self,res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        # Compute the taint results of the operation.
        res_t0 = slti_t0(rs1_val, rs1_val_t0, self.imm, self.imm_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res,slti)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res)


class SltiuInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("sltiu", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        res = sltiu(rs1_val, self.imm, self.fuzzerstate.is_design_64bit)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self,res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        # Compute the taint results of the operation.
        res_t0 = sltiu_t0(rs1_val, rs1_val_t0, self.imm, self.imm_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res,sltiu)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res)



class XoriInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("xori", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        res = xori(rs1_val, self.imm, self.fuzzerstate.is_design_64bit)

        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self,res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        # Compute the taint results of the operation.
        res_t0 = xori_t0(rs1_val, rs1_val_t0, self.imm, self.imm_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res,xori)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res)


class SrliInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("srli", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = srli(self.fuzzerstate.intregpickstate.regs[self.rs1].get_val(), self.imm, self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self,res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        # Compute the taint results of the operation.
        res_t0 = srli_t0(rs1_val, rs1_val_t0, self.imm, self.imm_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res,srli)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res)


class SraiInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("srai", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        res = srai(rs1_val, self.imm, self.fuzzerstate.is_design_64bit)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self,res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        # Compute the taint results of the operation.
        res_t0 = srai_t0(rs1_val, rs1_val_t0, self.imm, self.imm_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res,srai)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res)


class OriInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("ori", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        res = ori(rs1_val, self.imm, self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self,res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        # Compute the taint results of the operation.
        res_t0 = ori_t0(rs1_val, rs1_val_t0, self.imm, self.imm_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res,ori)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res)

class AndiInstruction(RegImmInstruction):
    def __init__(self, rd: int, rs1: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("andi", rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        res = andi(rs1_val, self.imm, self.fuzzerstate.is_design_64bit)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self,res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        # Compute the taint results of the operation.
        res_t0 = andi_t0(rs1_val, rs1_val_t0, self.imm, self.imm_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res,andi)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res)


## ImmRdInstructions ##
class LuiInstruction(ImmRdInstruction):
    def __init__(self, rd: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("lui", rd, imm, fuzzerstate.is_design_64bit, iscompressed, False, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        # res = to_unsigned(self.imm, self.fuzzerstate.is_design_64bit)<<12 # TODO: sign-extend to 64 bits
        res = lui(None, self.imm, self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self,res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        # Compute the taint results of the operation.
        res_t0 = lui_t0(rs1_val, rs1_val_t0, self.imm, self.imm_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res,lui)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res)

class AuipcInstruction(ImmRdInstruction):
    def __init__(self, rd: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("auipc", rd, imm, fuzzerstate.is_design_64bit, iscompressed, False, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        # res = to_unsigned(self.imm, self.fuzzerstate.is_design_64bit)<<12 # TODO: sign-extend to 64 bits
        res = auipc(self.addr, self.imm, self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self,res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        # Compute the taint results of the operation, we assume PC is untainted
        res_t0 = auipc_t0(self.addr, 0x0, self.imm, self.imm_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res,auipc)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res)
        

class JalInstruction(JALInstruction):
    def __init__(self, rd: int, imm: int, iscompressed: bool = False, fuzzerstate = None):
        super().__init__("jal", rd, imm, iscompressed, fuzzerstate)   

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = jal(self.addr, 0x0, self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self, res):
        self.writeback_t0(0x0, res)

class JalrInstruction(JALRInstruction):
    def __init__(self, instr_str: str, rd: int, rs1: int, imm: int, producer_id: int, is_design_64bit: bool, iscompressed: bool = False, fuzzerstate=None):
        super().__init__(instr_str, rd, rs1, imm, producer_id, is_design_64bit, iscompressed, fuzzerstate)

    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = jalr(self.addr, 0x0, self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)

    def execute_t0(self, res):
        self.writeback_t0(0x0, res)


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

