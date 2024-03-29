from cascade.randomize.pickbytecodetaints import CFINSTRCLASS_TAINT_PROBS, RD_INT_TAINT_PROBS_MASK, RS_INT_TAINT_PROBS_MASK, RD_FLOAT_TAINT_PROBS_MASK, RS_FLOAT_TAINT_PROBS_MASK, CFINSTRCLASS_TAINT_ONLY_ONE, OPCODE_FIELD_MASKS, OPCODE_FIELD_BITS, DONT_TAINT_REGS, CFINSTRCLASS_INJECT_PROBS
from cfinstructionclasses import *
from cascade.util import CFInstructionClass
from rv.asmutil import INSTR_FUNCS_T0
from cascade.registers import ABI_INAMES

import random
import numpy as np

# Ensures that the register and its taint mask excludes some registers we don't want to get tainted
def clean_reg_taint(reg, reg_t0, skip_regs):
    for skip in skip_regs:
        if (reg^skip)&~reg_t0 == 0: # untainted bits match
            # print(f"Untainted bits match: {hex(reg)} and {hex(skip)} with taint {hex(reg_t0)}")
            for i in range(5):
                reg_t0 &= ~(1<<i)
                if (reg^skip)&~reg_t0 != 0:
                    # print(f"Untainted bits dont match: {hex(reg)} and {hex(skip)} with taint {hex(reg_t0)}")
                    break
    return reg_t0
###
# Abstract classes with taint
###
# does not inhereit from BaseInstruction
class BaseInstruction_t0:
    def __init__(self):
        self.instr_func_t0 = INSTR_FUNCS_T0[self.instr_str]

# does not inherit from ImmInstruction
class ImmInstruction_t0(BaseInstruction_t0):
    def __init__(self):
        super().__init__()
        self.imm_t0 = 0x00

###
# Concrete classes with taint: integers
###

class R12Dinstrucion_t0(R12DInstruction, BaseInstruction_t0):
    def __init__(self, instr_str: str, rd: int, rs1: int, rs2: int, iscompressed: bool = False, fuzzerstate=None):
        super().__init__(instr_str, rd, rs1, rs2, iscompressed, fuzzerstate)
        self.rs1_t0 = 0
        self.rs2_t0 = 0
        self.rd_t0 = 0
        
    def compute_taints(self):
        if self.rs1 in DONT_TAINT_REGS and self.rs2 in DONT_TAINT_REGS and self.rd in DONT_TAINT_REGS:
            self.injectable = False
            return

        if self.rd in [self.rs1, self.rs2]:
            self.injectable = False
            return

        probs = CFINSTRCLASS_TAINT_PROBS[CFInstructionClass.R12D]
        p_rs1_t0 = probs["rs1"]*RS_INT_TAINT_PROBS_MASK[self.rs1]
        p_rs2_t0 = probs["rs2"]*RS_INT_TAINT_PROBS_MASK[self.rs2]
        p_rd_t0 = probs["rd"]*RD_INT_TAINT_PROBS_MASK[self.rd]

        if not CFINSTRCLASS_TAINT_ONLY_ONE: # several bytecode fields can be tainted
            self.rs1_t0 = 0
            self.rs2_t0 = 0
            self.rd_t0 = 0
            while self.rs1_t0 == 0 and self.rs2_t0 == 0 and self.rd_t0 == 0:
                self.rs1_t0 = np.random.choice([OPCODE_FIELD_MASKS["rs"],0], 1, p=[p_rs1_t0, 1-p_rs1_t0])[0].item()
                self.rs2_t0 = np.random.choice([OPCODE_FIELD_MASKS["rs"],0], 1, p=[p_rs2_t0, 1-p_rs2_t0])[0].item()
                self.rd_t0 = np.random.choice([OPCODE_FIELD_MASKS["rd"],0], 1, p=[p_rd_t0, 1-p_rd_t0])[0].item()
        else:
            ps_t0 = np.asarray([p_rs1_t0,p_rs2_t0,p_rd_t0]).astype("float64")
            if ps_t0.sum() == 0:
                self.injectable = False
                return
            ps_t0 = ps_t0/ps_t0.sum()
            rs1_rand_val = (1<<random.randint(0,4))&OPCODE_FIELD_MASKS["rs"]
            rs2_rand_val = (1<<random.randint(0,4))&OPCODE_FIELD_MASKS["rs"]
            rsd_rand_val = (1<<random.randint(0,4))&OPCODE_FIELD_MASKS["rs"]

            bytecode_t0 = np.random.choice([rs1_rand_val<<OPCODE_FIELD_BITS["rs1"],rs2_rand_val<<OPCODE_FIELD_BITS["rs2"],rsd_rand_val<<OPCODE_FIELD_BITS["rd"]], 1, p=ps_t0)[0].item()
            
            self.set_bytecode_t0(bytecode_t0)

        if self.rs1_t0 | self.rs2_t0 | self.rd_t0 == 0:
            self.injectable = False

        return self.injectable

        # returns the taints for the bytecode. We use the existing gen_bytecode_int method while temporarily overwriting class attributes
    def gen_bytecode_int_t0(self, is_spike_resolution: bool):
        assert(self.injectable), "Generating bytecode_t0 for non-injectable instruction. This should not happen."
        rd = self.rd
        rs1 = self.rs1
        rs2 = self.rs2
        self.rd = self.rd_t0
        self.rs1 = self.rs1_t0
        self.rs2 = self.rs2_t0
        taint_bytecode = self.gen_bytecode_int(is_spike_resolution)
        
        self.rd = 0x00
        self.rs1 = 0x00
        self.rs2 = 0x00
        taint_bytecode_mask = self.gen_bytecode_int(is_spike_resolution)
        
        self.rd = rd
        self.rs1 = rs1
        self.rs2 = rs2
        masked_taint = taint_bytecode ^ taint_bytecode_mask
        assert(masked_taint), f"No taints injected: {hex(masked_taint)}, rd_t0: {hex(self.rd_t0)}, rs1_t0: {hex(self.rs1_t0)}, rs2_t0: {hex(self.rs2_t0)},  this should not happen."
        
        return masked_taint

    def set_bytecode_t0(self, bytecode_t0):
        self.rs1_t0 = (bytecode_t0>>OPCODE_FIELD_BITS["rs1"])&OPCODE_FIELD_MASKS["rs"]
        self.rs2_t0 = (bytecode_t0>>OPCODE_FIELD_BITS["rs2"])&OPCODE_FIELD_MASKS["rs"]
        self.rd_t0 =  (bytecode_t0>>OPCODE_FIELD_BITS["rd"])&OPCODE_FIELD_MASKS["rd"]

    def check_regs_t0(self,reg_cmp):
        if self.fuzzerstate is None:
            return
        for reg_id,reg_val in reg_cmp.items():
            # print(f"{hex(pc)}: Checking register taint: {ABI_INAMES[reg_id]}:{hex(reg_val)}")
            mismatch = self.fuzzerstate.intregpickstate.regs[reg_id].check_t0(reg_val)
            assert not mismatch, f"{hex(self.addr)}: {self.instr_str}: Taint mismatch for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n\t Traceback: {compute_reg_traceback(reg_id,self.addr,self.fuzzerstate,reg_val).get_str()}"

    def execute_t0(self, res):
        if self.addr == -1:
            print(f"Skipping execution of {self.get_str()}")
            return
        assert self.fuzzerstate is not None, f"fuzzerstate not set, cannot execute {self.get_str()}" 
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        rs2_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_t0()
        # Compute the taint results of the operation.
        res_t0 = self.instr_func_t0(rs1_val, rs1_val_t0, rs2_val, rs2_val_t0)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res)

    # Overrides function in R12DInstructionClass
    def execute(self, taint_en: bool = False):
        if self.addr == -1:
            print(f"Skipping execution of {self.get_str()}")
            return
        assert self.fuzzerstate is not None, f"fuzzerstate not set, cannot execute {self.get_str()}" 
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        res = self.instr_func(rs1_val,rs2_val, self.fuzzerstate.is_design_64bit)
        # Compute taint propagation before writing back result
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)


    # This function writes back the tainted value to the destination register. Since the fields for the source and destination registers
    # could also be tainted, the alternative values for those executions (i.e. where the registers were chosen differently according to their taints)
    # are computed and written back to the set of registers derived from the taints in the rd field.
    def writeback_t0(self, res_t0, res):
        for alt_rd_id, alt_rd in self.fuzzerstate.intregpickstate.regs.items():
            if alt_rd_id == self.rd: continue
            if (alt_rd_id^self.rd)&(~self.rd_t0) == 0 and self.rd_t0 != 0: # only differ in the tainted bits, therefore this register will get tainted
                taints = alt_rd.get_val()^self.fuzzerstate.intregpickstate.regs[self.rd].get_val() # the taint vector is one in the bits that difer and 0 elsewhere
                alt_rd.set_val_t0(taints | res_t0) # or with taint result from addition
                self.fuzzerstate.intregpickstate.regs[self.rd].set_val_t0(taints | res_t0)
                print(f"writeback_t0: {ABI_INAMES[alt_rd_id]} <- {hex(taints | res_t0)} ({ABI_INAMES[alt_rd_id]} ^ {ABI_INAMES[self.rd]})")


    def compute_alt_res_t0(self, res, f):
        res_t0 = 0x0
        for alt_rs1_id, alt_rs1 in self.fuzzerstate.intregpickstate.regs.items():
            for alt_rs2_id, alt_rs2 in self.fuzzerstate.intregpickstate.regs.items():
                if ((alt_rs1_id^self.rs1)&(~self.rs1_t0) == 0 and self.rs1_t0 != 0) and ((alt_rs2_id^self.rs2)&(~self.rs2_t0) == 0 and self.rs2_t0 != 0) : # only differ in the tainted bits, therefore this register could have been used for addition instead and we need to derive the taints
                    print(f"{ABI_INAMES[alt_rs1_id]} matches {ABI_INAMES[self.rs1]} and {ABI_INAMES[alt_rs2_id]} matches {ABI_INAMES[self.rs2]} in untainted bits")
                    alt_res = self.inst_func(alt_rs1.get_val(),alt_rs2.get_val())
                    res_t0 |= alt_res^res


class ImmRdInstruction_t0(ImmRdInstruction, ImmInstruction_t0):
    def __init__(self, instr_str: str, rd: int, imm: int, is_design_64bit: bool, iscompressed: bool = False, is_rd_nonpickable_ok: bool = False, fuzzerstate=None):
        super().__init__(instr_str, rd, imm, is_design_64bit, iscompressed, is_rd_nonpickable_ok, fuzzerstate)
        self.rd_t0 = 0

    def compute_taints(self):
        probs = CFINSTRCLASS_TAINT_PROBS[CFInstructionClass.IMMRD]
        p_imm_t0 = probs["imm"]
        p_rd_t0 = probs["rd"]*RD_INT_TAINT_PROBS_MASK[self.rd]

        if self.rd in DONT_TAINT_REGS:
            self.injectable = False
            return

        if not CFINSTRCLASS_TAINT_ONLY_ONE: # several bytecode fields can be tainted
            self.imm_t0 = 0
            self.rd_t0 = 0
            while self.imm_t0 == 0 and self.rd_t0 == 0:
                self.imm_t0 = np.random.choice([OPCODE_FIELD_MASKS["immi"],0], 1, p=[p_imm_t0, 1-p_imm_t0])[0].item()
                self.rd_t0 = np.random.choice([OPCODE_FIELD_MASKS["rd"],0], 1, p=[p_rd_t0, 1-p_rd_t0])[0].item()
        else:
            ps_t0 = np.asarray([p_imm_t0,p_rd_t0]).astype("float64")
            ps_t0 = ps_t0/ps_t0.sum()
            bytecode_t0 = np.random.choice([OPCODE_FIELD_MASKS["immi"]<<OPCODE_FIELD_BITS["immi"],OPCODE_FIELD_MASKS["rd"]<<OPCODE_FIELD_BITS["rd"]],1, p=ps_t0)[0].item()
            self.imm_t0 = (bytecode_t0>>OPCODE_FIELD_BITS["immi"])&OPCODE_FIELD_MASKS["immi"]
            self.rd_t0 =  (bytecode_t0>>OPCODE_FIELD_BITS["rd"])&OPCODE_FIELD_MASKS["rd"]

        self.rd_t0 = clean_reg_taint(self.rd,self.rd_t0,DONT_TAINT_REGS)
        # print(f"rd: {self.rd_t0} {p_rd_t0}, rs1: {self.rs1_t0} {p_rs1_t0}, imm: {self.imm_t0} {p_imm_t0}")
        # assert(self.imm_t0 or self.rd_t0), "Did not taint anything, this should not happen."
        if self.imm_t0 | self.rd_t0 == 0:
            self.injectable = False

    def gen_bytecode_int_t0(self, is_spike_resolution: bool):
        assert(self.injectable), "Generating bytecode_t0 for non-injectable instruction. This should not happen."
        rd = self.rd
        imm = self.imm
        self.rd = self.rd_t0 # set regs to taints to get taint bytecode
        self.imm = self.imm_t0
        taint_bytecode = self.gen_bytecode_int(is_spike_resolution)
        self.rd = 0x00 # set regs to 0 to get taint bytecode mask to remove func and opcode fields
        self.imm = 0x00
        taint_bytecode_mask = self.gen_bytecode_int(is_spike_resolution)
        self.rd = rd
        self.imm = imm
        masked_taint = taint_bytecode ^ taint_bytecode_mask
        assert(masked_taint), f"No taints injected: {hex(masked_taint)}, rd_t0: {hex(self.rd_t0)}, imm_t0: {hex(self.imm_t0)},  this should not happen."
        return masked_taint

    def writeback_t0(self, res_t0, res):
        for alt_rd_id, alt_rd in self.fuzzerstate.intregpickstate.regs.items():
            if alt_rd_id == self.rd: continue
            if (alt_rd_id^self.rd)&(~self.rd_t0) == 0 and self.rd_t0 != 0: # only differ in the tainted bits, therefore this register will get tainted
                taints = alt_rd.get_val()^self.fuzzerstate.intregpickstate.regs[self.rd].get_val() # the taint vector is one in the bits that difer and 0 elsewhere
                alt_rd.set_val_t0(taints | res_t0) # or with taint result from addition
                self.fuzzerstate.intregpickstate.regs[self.rd].set_val_t0(taints | res_t0)
                print(f"writeback_t0: {ABI_INAMES[alt_rd_id]} <- {hex(taints | res_t0)} ({ABI_INAMES[alt_rd_id]} ^ {ABI_INAMES[self.rd]})")
    
    def execute_t0(self,res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        # Compute the taint results of the operation. The address is never tainted.
        res_t0 = self.instr_func_t0(self.addr, 0x0, self.imm, self.imm_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res,self.instr_func)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res)

    # Overrides function in ImmRdInstructionClass
    def execute(self, taint_en: bool = False):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.instr_func(self.addr, self.imm, self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)


    
class RegImmInstruction_t0(RegImmInstruction, ImmInstruction_t0):
    def __init__(self, instr_str: str, rd: int, rs1: int, imm: int, is_design_64bit: bool, iscompressed: bool = False, fuzzerstate=None, is_rd_nonpickable_ok: bool = False):
        super().__init__(instr_str, rd, rs1, imm, is_design_64bit, iscompressed, fuzzerstate, is_rd_nonpickable_ok)
        self.rs1_t0 = 0
        self.rd_t0 = 0
    def copmute_taints(self):
        probs = CFINSTRCLASS_TAINT_PROBS[CFInstructionClass.REGIMM]
        p_rs1_t0 = probs["rs1"]*RS_INT_TAINT_PROBS_MASK[self.rs1]
        p_imm_t0 = probs["imm"]
        p_rd_t0 = probs["rd"]*RD_INT_TAINT_PROBS_MASK[self.rd]

        has_shamt = self.instr_str in RegImmShiftInstructions
        if not CFINSTRCLASS_TAINT_ONLY_ONE: # several bytecode fields can be tainted
            self.rs1_t0 = 0
            self.imm_t0 = 0
            self.rd_t0 = 0
            while self.rs1_t0 == 0 and self.imm_t0 == 0 and self.rd_t0 == 0:
                self.rs1_t0 = np.random.choice([OPCODE_FIELD_MASKS["rs"],0], 1, p=[p_rs1_t0, 1-p_rs1_t0])[0].item()
                self.imm_t0 = np.random.choice([OPCODE_FIELD_MASKS["immi"] if not has_shamt else 0x1F,0], 1, p=[p_imm_t0, 1-p_imm_t0])[0].item()
                self.rd_t0 = np.random.choice([OPCODE_FIELD_MASKS["rd"],0], 1, p=[p_rd_t0, 1-p_rd_t0])[0].item()
        else:
            ps_t0 = np.asarray([p_rs1_t0, p_imm_t0,p_rd_t0]).astype("float64")
            ps_t0 = ps_t0/ps_t0.sum()
            bytecode_t0 = np.random.choice([OPCODE_FIELD_MASKS["rs"]<<OPCODE_FIELD_BITS["rs1"],OPCODE_FIELD_MASKS["immi"]<<OPCODE_FIELD_BITS["immi"],OPCODE_FIELD_MASKS["rd"]<<OPCODE_FIELD_BITS["rd"]],1, p=ps_t0)[0].item()
            self.rs1_t0 = (bytecode_t0>>OPCODE_FIELD_BITS["rs1"])&OPCODE_FIELD_MASKS["rs"]
            self.imm_t0 = (bytecode_t0>>OPCODE_FIELD_BITS["immi"])&(OPCODE_FIELD_MASKS["immi"] if not has_shamt else OPCODE_FIELD_MASKS["shamt"])
            self.rd_t0 =  (bytecode_t0>>OPCODE_FIELD_BITS["rd"])&OPCODE_FIELD_MASKS["rd"]

        self.rs1_t0 = clean_reg_taint(self.rs1, self.rs1_t0,[self.rs1])
        self.rd_t0 = clean_reg_taint(self.rd, self.rd_t0,DONT_TAINT_REGS)

        # print(f"rd: {self.rd_t0} {p_rd_t0}, rs1: {self.rs1_t0} {p_rs1_t0}, imm: {self.imm_t0} {p_imm_t0}")
        # assert(self.rs1_t0 or self.imm_t0 or self.rd_t0), "Did not taint anything, this should not happen."
        if self.rs1_t0 | self.imm_t0 | self.rd_t0 == 0:
            self.injectable = False

        # returns the taints for the bytecode. We use the existing gen_bytecode_int method while temporarily overwriting class attributes
    def gen_bytecode_int_t0(self, is_spike_resolution: bool):
        assert(self.injectable), "Generating bytecode_t0 for non-injectable instruction. This should not happen."
        rd = self.rd
        rs1 = self.rs1
        imm = self.imm
        self.rd = self.rd_t0 # set regs to taints to get taint bytecode
        self.rs1 = self.rs1_t0
        self.imm = self.imm_t0
        taint_bytecode = self.gen_bytecode_int(is_spike_resolution)
        self.rd = 0x00 # set regs to 0 to get taint bytecode mask to remove func and opcode fields
        self.rs1 = 0x00
        self.imm = 0x00
        taint_bytecode_mask = self.gen_bytecode_int(is_spike_resolution)
        self.rd = rd
        self.rs1 = rs1
        self.imm = imm
        masked_taint = taint_bytecode ^ taint_bytecode_mask
        assert(masked_taint), f"No taints injected: {hex(masked_taint)}, rd_t0: {hex(self.rd_t0)}, rs1_t0: {hex(self.rs1_t0)}, imm_t0: {hex(self.imm_t0)},  this should not happen."
        return masked_taint

    def writeback_t0(self, res_t0, res):
        for alt_rd_id, alt_rd in self.fuzzerstate.intregpickstate.regs.items():
            if alt_rd_id == self.rd: continue
            if (alt_rd_id^self.rd)&(~self.rd_t0) == 0 and self.rd_t0 != 0: # only differ in the tainted bits, therefore this register will get tainted
                taints = alt_rd.get_val()^self.fuzzerstate.intregpickstate.regs[self.rd].get_val() # the taint vector is one in the bits that difer and 0 elsewhere
                alt_rd.set_val_t0(taints | res_t0) # or with taint result from addition
                self.fuzzerstate.intregpickstate.regs[self.rd].set_val_t0(taints | res_t0)
                print(f"writeback_t0: {ABI_INAMES[alt_rd_id]} <- {hex(taints | res_t0)} ({ABI_INAMES[alt_rd_id]} ^ {ABI_INAMES[self.rd]})")

    def compute_alt_res_t0(self, res, f):
        return 0x0 # skip possible immediates for now

    def execute_t0(self,res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        # Compute the taint results of the operation.
        res_t0 = self.instr_func_t0(rs1_val, rs1_val_t0, self.imm, self.imm_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res)

class JALInstruction_t0(JALInstruction):
    def __init__(self, instr_str: str, rd: int, rs1: int, imm: int, producer_id: int, is_design_64bit: bool, iscompressed: bool = False, fuzzerstate=None):
        super().__init__(instr_str, rd, rs1, imm, producer_id, is_design_64bit, iscompressed, fuzzerstate)
        
    def execute_t0(self, res):
        self.writeback_t0(0x0, res)


class JALRInstruction_t0(JALRInstruction):
    def __init__(self, instr_str: str, rd: int, rs1: int, imm: int, producer_id: int, is_design_64bit: bool, iscompressed: bool = False, fuzzerstate=None):
        super().__init__(instr_str, rd, rs1, imm, producer_id, is_design_64bit, iscompressed, fuzzerstate)
        
    def execute_t0(self, res):
        self.writeback_t0(0x0, res)

## Extended Placeholder Instructions ##
#TODO: all these need to be adjusted for non-spike resolution execution
class PlaceholderProducerInstr0_t0(PlaceholderProducerInstr0):
    def __init__(self, rd: int, producer_id: int, is_design_64bit: bool, fuzzerstate = None):
        super().__init__(rd, producer_id, is_design_64bit, fuzzerstate)

    def execute_t0(self, res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        self.writeback_t0(0x0,res)

        
class PlaceholderProducerInstr1_t0(PlaceholderProducerInstr1):
    def __init__(self, rd: int, producer_id: int, is_design_64bit: bool, fuzzerstate = None):
        super().__init__(rd, producer_id, is_design_64bit, fuzzerstate)

    def execute_t0(self, res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        self.writeback_t0(0x0,res)

    def execute(self):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        uimm = li_into_reg(to_unsigned(self.spike_resolution_offset, self.is_design_64bit), False)[1]
        res = self.fuzzerstate.intregpickstate.regs[self.rd].get_val() + uimm
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)


class PlaceholderPreConsumerInstr_t0(PlaceholderPreConsumerInstr):
    def __init__(self,rdep: int,fuzzerstate = None):
        super().__init__(rdep, fuzzerstate)   

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

    def execute(self):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rdep].get_val() & self.fuzzerstate.intregpickstate.regs[RDEP_MASK_REGISTER_ID].get_val()
        self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rdep].set_val(res)

class PlaceholderConsumerInstr_t0(PlaceholderConsumerInstr):
    def __init__(self, rd: int, rdep: int, rprod: int, producer_id: int, fuzzerstate = None):
        super().__init__(rd, rdep, rprod, producer_id, fuzzerstate)   

    def execute_t0(self, res):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res_t0 = self.fuzzerstate.intregpickstate.regs[self.rprod].get_val_t0() ^ self.fuzzerstate.intregpickstate.regs[RELOCATOR_REGISTER_ID].get_val_t0()
        self.writeback_t0(res_t0,res)

    def execute(self):
        assert self.fuzzerstate is not None, "fuzzerstate not set."
        res = self.fuzzerstate.intregpickstate.regs[self.rprod].get_val() ^ self.fuzzerstate.intregpickstate.regs[RELOCATOR_REGISTER_ID].get_val()
        self.execute_t0(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)


