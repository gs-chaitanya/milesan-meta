from params.fuzzparams import TAINT_EN
from cascade.randomize.pickbytecodetaints import CFINSTRCLASS_TAINT_PROBS, RD_INT_TAINT_PROBS_MASK, RS_INT_TAINT_PROBS_MASK, RD_FLOAT_TAINT_PROBS_MASK, RS_FLOAT_TAINT_PROBS_MASK, CFINSTRCLASS_TAINT_ONLY_ONE, OPCODE_FIELD_MASKS, OPCODE_FIELD_BITS, DONT_TAINT_REGS, CFINSTRCLASS_INJECT_PROBS
from cascade.cfinstructionclasses import *
from cascade.util import CFInstructionClass, ExceptionCauseVal
from rv.asmutil import INSTR_FUNCS_T0, INSTR_FUNCS
from cascade.registers import ABI_INAMES
from params.runparams import PRINT_CHECK_REGS_T0, PRINT_WRITEBACK_T0, PRINT_INSTRUCTION_EXECUTION_IN_SITU
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

def filter_reg_t0_traceback(reg_id, addr, fuzzerstate, correct_val: int = None, is_spike_resolution: bool = False):
    last_instr = compute_reg_traceback(reg_id, addr, fuzzerstate, correct_val)
    dep_regs = set()
    instr_stream = []
    for bb_instrs in reversed(fuzzerstate.instr_objs_seq):
        for instr_obj in reversed(bb_instrs):
            if instr_obj.addr == last_instr.addr: # start collecting depending registers
                instr_stream += [instr_obj]
                if hasattr(instr_obj,"rs1"):
                    dep_regs |= {instr_obj.rs1}
                if hasattr(instr_obj,"rs2"):
                    dep_regs |= {instr_obj.rs2}
                if hasattr(instr_obj,"rdep"):
                    dep_regs |= {instr_obj.rdep}
                if hasattr(instr_obj,"rprod"):    
                    dep_regs |= {instr_obj.rprod}

            elif hasattr(instr_obj,"rd") and instr_obj.rd in dep_regs and instr_obj.addr in fuzzerstate.intregpickstate.writeback_trace_final :
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
            elif isinstance(instr_obj, PlaceholderPreConsumerInstr) and instr_obj.rdep in dep_regs and instr_obj.addr in fuzzerstate.intregpickstate.writeback_trace_final:
                instr_stream += [instr_obj]
  
    
    if PRINT_FILTERED_REG_TRACEBACK:
        print("*** FILTERED TAINT TRACEBACK ***")
        for instr_obj in reversed(instr_stream):
            if instr_obj.addr not in fuzzerstate.intregpickstate.writeback_trace_in_situ:
                assert instr_obj.addr not in fuzzerstate.intregpickstate.writeback_trace_final
                continue
            rd_spike,val_t0_spike = fuzzerstate.intregpickstate.writeback_trace_in_situ[instr_obj.addr]
            rd_final,val_t0_final = fuzzerstate.intregpickstate.writeback_trace_final[instr_obj.addr]
            if rd_final != rd_spike or val_t0_final != val_t0_spike:
                print("Mismatch between in-situ and final simulation:")
                instr_obj.print(True)
                print(f"{ABI_INAMES[rd_spike]}<-{hex(val_t0_spike)}")
                instr_obj.print(False)
                print(f"{ABI_INAMES[rd_final]}<-{hex(val_t0_final)}")

        for (addr_spike,trace_spike),(addr_final, trace_final) in zip(fuzzerstate.intregpickstate.writeback_trace_in_situ.items(),fuzzerstate.intregpickstate.writeback_trace_final.items()):
            assert addr_spike == addr_final
            assert trace_spike[0] == trace_final[0]
            if trace_spike[1] != trace_final[1]:
                print(f"MISMATCH {hex(addr_spike)}: {ABI_INAMES[trace_spike[0]]} <- {hex(trace_spike[1])}/{hex(trace_final[1])} (spike/final)")
            else:
                print(f"{hex(addr_spike)}: {ABI_INAMES[trace_spike[0]]} <- {hex(trace_spike[1])}")

    return last_instr
###
# Abstract classes with taint
###
# does not inhereit from BaseInstruction
class BaseInstruction_t0(BaseInstruction):
    instr_func_t0 = None
    
    def __init__(self, fuzzerstate, instr_str):
        super().__init__(fuzzerstate, instr_str)
        self.instr_func_t0 = INSTR_FUNCS_T0[self.instr_str]

    def check_regs_t0(self,reg_cmp):
        assert self.fuzzerstate.taint_en
        for reg_id,reg_val in reg_cmp.items():
            if reg_id not in self.fuzzerstate.intregpickstate.regs:
                # print(f"{hex(self.addr)}: Ignoring register taint: {ABI_INAMES[reg_id]}")
                continue
            if reg_val and PRINT_CHECK_REGS_T0:
                print(f"{hex(self.addr)}: Checking register taint: {ABI_INAMES[reg_id]}:{hex(reg_val)}")
            mismatch = self.fuzzerstate.intregpickstate.regs[reg_id].check_t0(reg_val)
            assert not mismatch, f"{hex(self.addr)}: {self.instr_str}: Taint mismatch for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n\t Traceback: {compute_reg_traceback(reg_id,self.addr,self.fuzzerstate,reg_val).get_str()}"

    def execute_t0(self):
        assert self.fuzzerstate.taint_en
        raise Exception(f"Function execute_t0() called on abstract class BaseInstruction_t0 {self.get_str()}.")

    def inject_taint(self, is_spike_resolution: bool = True):
        self.set_bytecode(self.gen_bytecode_int(is_spike_resolution) ^ self.gen_bytecode_int_t0(is_spike_resolution))


class CFInstruction_t0(BaseInstruction_t0):
    def __init__(self, fuzzerstate, instr_str):
        super().__init__(fuzzerstate, instr_str)

class RDInstruction_t0(CFInstruction_t0):
    def __init__(self, fuzzerstate, instr_str):
        super().__init__(fuzzerstate, instr_str)
        self.rd_t0 = 0
    # This function writes back the tainted value to the destination register. Since the fields for the source and destination registers
    # could also be tainted, the alternative values for those executions (i.e. where the registers were chosen differently according to their taints)
    # are computed and written back to the set of registers derived from the taints in the rd field.
    def writeback_t0(self, res_t0, res, is_spike_resolution: bool):
        assert self.fuzzerstate.taint_en
        if self.rd_t0 == 0:
            self.fuzzerstate.intregpickstate.regs[self.rd].set_val_t0(res_t0)
            self.fuzzerstate.intregpickstate.add_writeback_trace(self.addr, self.rd, res_t0, is_spike_resolution)
            if PRINT_WRITEBACK_T0: 
                print(f"writeback_t0: {self.get_str(is_spike_resolution)}: {ABI_INAMES[self.rd]} <- {hex(res_t0)}")
            return

        for alt_rd_id, alt_rd in self.fuzzerstate.intregpickstate.regs.items():
            if (alt_rd_id^self.rd)&(~self.rd_t0) == 0: # only differ in the tainted bits, therefore this register will get tainted
                taints = alt_rd.get_val()^res # the taint vector is one in the bits that differ
                alt_rd.set_val_t0(taints | res_t0) # or with taint result from addition
                self.fuzzerstate.intregpickstate.add_writeback_trace(self.addr, self.rd, taints | res_t0, is_spike_resolution)
                if PRINT_WRITEBACK_T0: 
                    print(f"writeback_t0: {self.get_str(is_spike_resolution)}: {ABI_INAMES[alt_rd_id]} <- {hex(taints | res_t0)} (= {hex(res_t0)} | ({hex(alt_rd.get_val())} ^ {hex(res)}) )")

# does not inherit from ImmInstruction
class ImmInstruction_t0(CFInstruction_t0):
    def __init__(self, fuzzerstate, instr_str):
        super().__init__(fuzzerstate, instr_str)
        self.imm_t0 = 0x00

###
# Concrete classes with taint: integers
###

class R12DInstruction_t0(R12DInstruction, RDInstruction_t0):
    def __init__(self, fuzzerstate, instr_str: str, rd: int, rs1: int, rs2: int, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, rd, rs1, rs2, iscompressed)
        self.rs1_t0 = 0
        self.rs2_t0 = 0
        self.rd_t0 = 0
        
    def compute_taints(self):
        assert self.fuzzerstate.taint_en
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
                return False
            ps_t0 = ps_t0/ps_t0.sum()
            skip_regs = set(range(len(ABI_INAMES))) - set(self.fuzzerstate.intregpickstate.regs.keys())
            rs1_rand_val = (1<<random.randint(0,4))&OPCODE_FIELD_MASKS["rs"]
            rs1_rand_val = clean_reg_taint(self.rs1, rs1_rand_val, skip_regs)
            rs2_rand_val = (1<<random.randint(0,4))&OPCODE_FIELD_MASKS["rs"]
            rs2_rand_val = clean_reg_taint(self.rs2, rs2_rand_val, skip_regs)
            rd_rand_val = (1<<random.randint(0,4))&OPCODE_FIELD_MASKS["rd"]
            rd_rand_val = clean_reg_taint(self.rd, rd_rand_val, skip_regs)

            bytecode_t0 = np.random.choice([rs1_rand_val<<OPCODE_FIELD_BITS["rs1"],rs2_rand_val<<OPCODE_FIELD_BITS["rs2"],rd_rand_val<<OPCODE_FIELD_BITS["rd"]], 1, p=ps_t0)[0].item()
            
            self.set_bytecode_t0(bytecode_t0)

        if (self.rs1_t0 | self.rs2_t0 | self.rd_t0) == 0:
            self.injectable = False
    

        return self.injectable

        # returns the taints for the bytecode. We use the existing gen_bytecode_int method while temporarily overwriting class attributes
    def gen_bytecode_int_t0(self, is_spike_resolution: bool):
        assert self.fuzzerstate.taint_en
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

    def execute_t0(self, res, is_spike_resolution: bool):
        assert self.fuzzerstate.taint_en
        if self.addr == -1:
            print(f"Skipping execution of {self.get_str()}")
            return
        assert self.instr_func_t0 is not None, f"Cannot execute {self.get_str()}: no instr_func_t0 found."
        assert self.fuzzerstate is not None, f"fuzzerstate not set, cannot execute {self.get_str()}" 
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        rs2_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_t0()
        # Compute the taint results of the operation.
        res_t0 = self.instr_func_t0(rs1_val, rs1_val_t0, rs2_val, rs2_val_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res, is_spike_resolution)

    # Overrides function in R12DInstructionClass
    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        if self.addr == -1:
            print(f"Skipping execution of {self.get_str()}")
            return
        assert self.instr_func is not None, f"Cannot execute {self.get_str()}: no instr_func found."
        assert self.fuzzerstate is not None, f"fuzzerstate not set, cannot execute {self.get_str()}" 
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        res = self.instr_func(rs1_val,rs2_val, self.fuzzerstate.is_design_64bit)
        # Compute taint propagation before writing back result
        if taint_en:
            self.execute_t0(res, is_spike_resolution)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)
        self.fuzzerstate.advance_minstret()

    def compute_alt_res_t0(self, res):
        assert self.fuzzerstate.taint_en
        res_t0 = 0x0
        for alt_rs1_id, alt_rs1 in self.fuzzerstate.intregpickstate.regs.items():
            for alt_rs2_id, alt_rs2 in self.fuzzerstate.intregpickstate.regs.items():
                if ((alt_rs1_id^self.rs1)&(~self.rs1_t0) == 0 and self.rs1_t0 != 0) and ((alt_rs2_id^self.rs2)&(~self.rs2_t0) == 0 and self.rs2_t0 != 0) : # only differ in the tainted bits, therefore this register could have been used for addition instead and we need to derive the taints
                    print(f"{ABI_INAMES[alt_rs1_id]} matches {ABI_INAMES[self.rs1]} and {ABI_INAMES[alt_rs2_id]} matches {ABI_INAMES[self.rs2]} in untainted bits")
                    alt_res = self.instr_func(alt_rs1.get_val(),alt_rs2.get_val())
                    res_t0 |= alt_res^res
        return res_t0


class ImmRdInstruction_t0(ImmRdInstruction, ImmInstruction_t0, RDInstruction_t0):
    def __init__(self, fuzzerstate, instr_str: str, rd: int, imm: int, iscompressed: bool = False, is_rd_nonpickable_ok: bool = False):
        super().__init__(fuzzerstate, instr_str, rd, imm, iscompressed, is_rd_nonpickable_ok)
        self.rd_t0 = 0

    def compute_taints(self):
        assert self.fuzzerstate.taint_en
        probs = CFINSTRCLASS_TAINT_PROBS[CFInstructionClass.IMMRD]
        p_imm_t0 = probs["imm"]
        p_rd_t0 = probs["rd"]*RD_INT_TAINT_PROBS_MASK[self.rd]

        if self.instr_str == "auipc":
            self.injectable = False
            return False

        if not CFINSTRCLASS_TAINT_ONLY_ONE: # several bytecode fields can be tainted
            self.imm_t0 = 0
            self.rd_t0 = 0
            while self.imm_t0 == 0 and self.rd_t0 == 0:
                self.imm_t0 = np.random.choice([OPCODE_FIELD_MASKS["immu"],0], 1, p=[p_imm_t0, 1-p_imm_t0])[0].item()
                self.rd_t0 = np.random.choice([OPCODE_FIELD_MASKS["rd"],0], 1, p=[p_rd_t0, 1-p_rd_t0])[0].item()
        else:
            ps_t0 = np.asarray([p_imm_t0,p_rd_t0]).astype("float64")
            if ps_t0.sum() == 0:
                self.injectable = False
                return False
            ps_t0 = ps_t0/ps_t0.sum()
            skip_regs = set(range(len(ABI_INAMES))) - set(self.fuzzerstate.intregpickstate.regs.keys())
            rd_rand_val = (1<<random.randint(0,4))&OPCODE_FIELD_MASKS["rd"]
            rd_rand_val = clean_reg_taint(self.rd, rd_rand_val, skip_regs)
            # imm_rand_val = (1<<random.randint(0,19))&OPCODE_FIELD_MASKS["immu"]
            imm_rand_val = random.randint(0, OPCODE_FIELD_MASKS["immu"])
            if p_imm_t0 and not p_rd_t0 and self.rd == 0:
                self.injectable = False
                return False
            
            bytecode_t0 = np.random.choice([imm_rand_val<<OPCODE_FIELD_BITS["immu"],rd_rand_val<<OPCODE_FIELD_BITS["rd"]],1, p=ps_t0)[0].item()

            self.set_bytecode_t0(bytecode_t0)

        # print(f"rd: {self.rd_t0} {p_rd_t0}, rs1: {self.rs1_t0} {p_rs1_t0}, imm: {self.imm_t0} {p_imm_t0}")
        # assert(self.imm_t0 or self.rd_t0), "Did not taint anything, this should not happen."
        if (self.imm_t0 | self.rd_t0) == 0:
            self.injectable = False

        return self.injectable

    def gen_bytecode_int_t0(self, is_spike_resolution: bool):
        assert self.fuzzerstate.taint_en
        assert self.injectable , "Generating bytecode_t0 for non-injectable instruction. This should not happen."
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

    def set_bytecode_t0(self, bytecode_t0):
        assert self.fuzzerstate.taint_en
        self.imm_t0 = (bytecode_t0>>OPCODE_FIELD_BITS["immu"])&OPCODE_FIELD_MASKS["immu"]
        self.rd_t0 =  (bytecode_t0>>OPCODE_FIELD_BITS["rd"])&OPCODE_FIELD_MASKS["rd"]
 
    def compute_alt_res_t0(self, res):
        assert self.fuzzerstate.taint_en
        return 0x0 # skip possible immediates for now

    def execute_t0(self, res, is_spike_resolution: bool):
        assert self.fuzzerstate.taint_en
        # Compute the taint results of the operation. The address is never tainted.
        res_t0 = self.instr_func_t0(self.addr, 0x0, self.imm, self.imm_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res, is_spike_resolution)

    # Overrides function in ImmRdInstructionClass
    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        res = self.instr_func(self.addr, self.imm, self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res, is_spike_resolution)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)
        self.fuzzerstate.advance_minstret()


class RegImmInstruction_t0(RegImmInstruction, ImmInstruction_t0, RDInstruction_t0):
    def __init__(self, fuzzerstate, instr_str: str, rd: int, rs1: int, imm: int, iscompressed: bool = False, is_rd_nonpickable_ok: bool = False):
        super().__init__(fuzzerstate, instr_str, rd, rs1, imm, iscompressed, is_rd_nonpickable_ok)
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
        assert self.fuzzerstate.taint_en
        assert self.injectable, "Generating bytecode_t0 for non-injectable instruction. This should not happen."
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

    def compute_alt_res_t0(self, res):
        assert self.fuzzerstate.taint_en
        return 0x0 # skip possible immediates for now

    def execute_t0(self, res, is_spike_resolution: bool):
        assert self.fuzzerstate.taint_en
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        # Compute the taint results of the operation.
        res_t0 = self.instr_func_t0(rs1_val, rs1_val_t0, self.imm, self.imm_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res, is_spike_resolution)

    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        res = self.instr_func(rs1_val, self.imm, self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res, is_spike_resolution)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)
        self.fuzzerstate.advance_minstret()



class JALInstruction_t0(JALInstruction, ImmInstruction_t0, RDInstruction_t0):
    def __init__(self, fuzzerstate, instr_str: str, rd: int, imm: int, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, rd, imm, iscompressed)
        self.rd_t0 = 0

    def execute_t0(self, res, is_spike_resolution):
        assert self.fuzzerstate.taint_en
        # We assume the PC does not get tainted, therefore the result of JAL is never either.
        self.writeback_t0(0x0, res, is_spike_resolution)

    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        res = self.instr_func(self.addr, 0x0, self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res, is_spike_resolution)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)
        self.fuzzerstate.advance_minstret()


class JALRInstruction_t0(JALRInstruction, ImmInstruction_t0, RDInstruction_t0):
    def __init__(self, fuzzerstate, instr_str: str, rd: int, rs1: int, imm: int, producer_id: int, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, rd, rs1, imm, producer_id, iscompressed)
        self.rd_t0 = 0
        self.rs1_t0 = 0

    def execute_t0(self, res, is_spike_resolution: bool):
        assert self.fuzzerstate.taint_en
        assert self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0() == 0, "JALR source register is tainted. This is not allowed."
        # We assume the PC does not get tainted, therefore the result of JAL is never either.
        self.writeback_t0(0x0, res, is_spike_resolution)

    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        res = self.instr_func(self.addr, 0x0, self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res, is_spike_resolution)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)
        self.fuzzerstate.advance_minstret()



## Extended Placeholder Instructions ##
#TODO: all these need to be adjusted for non-spike resolution execution
class PlaceholderProducerInstr0_t0(PlaceholderProducerInstr0, RDInstruction_t0):
    def __init__(self, fuzzerstate, rd: int, producer_id: int):
        super().__init__(fuzzerstate, rd, producer_id)
        self.rd_t0 = 0

    def execute_t0(self, res, is_spike_resolution: bool):
        assert self.fuzzerstate.taint_en
        self.writeback_t0(0x0,res,is_spike_resolution)

    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        if is_spike_resolution:
            if self.spike_resolution_offset is None:
                # if PRINT_INSTRUCTION_EXECUTION_IN_SITU:
                #     print(f"{self.get_str(is_spike_resolution)}: spike_resolution_offset not yet determined. Setting rd_t0 to 0.")
                if taint_en:
                    self.execute_t0(None,is_spike_resolution)
                return
            else:
                imm = li_into_reg(to_unsigned(self.spike_resolution_offset, self.fuzzerstate.is_design_64bit), False)[0]
        else:
            assert self.rtl_offset is not None
            imm = li_into_reg(to_unsigned(self.rtl_offset, self.fuzzerstate.is_design_64bit), False)[0]

        res = to_unsigned(imm, self.fuzzerstate.is_design_64bit)<<12
        if taint_en:
            self.execute_t0(res,is_spike_resolution)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)
        self.fuzzerstate.advance_minstret()

   
class PlaceholderProducerInstr1_t0(PlaceholderProducerInstr1, RDInstruction_t0):
    def __init__(self, fuzzerstate, rd: int, producer_id: int):
        super().__init__(fuzzerstate, rd, producer_id)
        self.rd_t0 = 0

    def execute_t0(self, res, is_spike_resolution: bool):
        assert self.fuzzerstate.taint_en
        rd_t0 = self.fuzzerstate.intregpickstate.regs[self.rd].get_val_t0()
        assert rd_t0 == 0, "rd is tainted, this should not happen."
        self.writeback_t0(0x0,res,is_spike_resolution)

    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        if is_spike_resolution:
            if self.spike_resolution_offset is None:
                # if PRINT_INSTRUCTION_EXECUTION_IN_SITU:
                #     print(f"{self.get_str(is_spike_resolution)}: spike_resolution_offset not yet determined. Skipping.")
                assert self.fuzzerstate.intregpickstate.regs[self.rd].get_val_t0() == 0
                if taint_en:
                    self.execute_t0(None,is_spike_resolution)
                return
            else:
                uimm = li_into_reg(to_unsigned(self.spike_resolution_offset, self.fuzzerstate.is_design_64bit), False)[1]
        else:
            uimm = li_into_reg(to_unsigned(self.rtl_offset, self.fuzzerstate.is_design_64bit), False)[1]
        
        res = self.fuzzerstate.intregpickstate.regs[self.rd].get_val() + uimm
        if taint_en:
            self.execute_t0(res, is_spike_resolution)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)
        self.fuzzerstate.advance_minstret()

# Does not inherit from RDInstruction_t0 since it writes to rdep
class PlaceholderPreConsumerInstr_t0(PlaceholderPreConsumerInstr, BaseInstruction_t0):
    def __init__(self, fuzzerstate, rdep: int):
        super().__init__(fuzzerstate, rdep)
        self.rdep_t0 = 0

    def execute_t0(self, res, is_spike_resolution):
        assert self.fuzzerstate.taint_en
        rdep = self.fuzzerstate.intregpickstate.regs[self.rdep].get_val()
        rmask = self.fuzzerstate.intregpickstate.regs[RDEP_MASK_REGISTER_ID].get_val()

        rdep_taint = self.fuzzerstate.intregpickstate.regs[self.rdep].get_val_t0()
        assert rdep_taint == 0, "rdep is tainted, this should not happen."
        rmask_taint = self.fuzzerstate.intregpickstate.regs[RDEP_MASK_REGISTER_ID].get_val_t0()
        assert rmask_taint == 0, "rmask is tainted, this should not happen."

        rdep_and_rmask_taint= rdep & rmask_taint
        rmask_and_rdep_taint = rmask & rdep_taint

        rdep_and_rmask_taint = rdep_taint & rmask_taint
        rdep_taint_and_rmask_or_reverse = rdep_and_rmask_taint | rmask_and_rdep_taint

        res_t0 = rdep_and_rmask_taint | rdep_taint_and_rmask_or_reverse

        self.writeback_t0(res_t0, res, is_spike_resolution)

    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        res = self.fuzzerstate.intregpickstate.regs[self.rdep].get_val() & self.fuzzerstate.intregpickstate.regs[RDEP_MASK_REGISTER_ID].get_val()
        if taint_en:
            self.execute_t0(res, is_spike_resolution)
        self.fuzzerstate.intregpickstate.regs[self.rdep].set_val(res)
        self.fuzzerstate.advance_minstret()

    # This function writes back the tainted value to the destination register which is the rdep for this class.
    # Since the fields for the source and destination registers could also be tainted, the alternative values for 
    # those executions (i.e. where the registers were chosen differently according to their taints)
    # are computed and written back to the set of registers derived from the taints in the rdep field.
    def writeback_t0(self, res_t0, res, is_spike_resolution):
        assert self.fuzzerstate.taint_en
        if self.rdep_t0 == 0:
            self.fuzzerstate.intregpickstate.regs[self.rdep].set_val_t0(res_t0)
            self.fuzzerstate.intregpickstate.add_writeback_trace(self.addr, self.rdep, res_t0, is_spike_resolution)
            if PRINT_WRITEBACK_T0: 
                print(f"writeback_t0: {self.get_str(is_spike_resolution)}: {ABI_INAMES[self.rdep]} <- {hex(res_t0)}")
            return

        for alt_rdep_id, alt_rdep in self.fuzzerstate.intregpickstate.regs.items():
            if (alt_rdep_id^self.rdep)&(~self.rdep_t0) == 0 and self.rdep_t0 != 0: # only differ in the tainted bits, therefore this register will get tainted
                taints = alt_rdep.get_val()^res # the taint vector is one in the bits that differ
                alt_rdep.set_val_t0(taints | res_t0) # or with taint result from addition
                self.fuzzerstate.intregpickstate.add_writeback_trace(self.addr, self.rdep, taints | res_t0, is_spike_resolution)
                if PRINT_WRITEBACK_T0:
                    print(f"writeback_t0: {ABI_INAMES[alt_rdep_id]} <- {hex(taints | res_t0)} ({ABI_INAMES[alt_rdep_id]} ^ {ABI_INAMES[self.rdep]})")


class PlaceholderConsumerInstr_t0(PlaceholderConsumerInstr, RDInstruction_t0):
    def __init__(self, fuzzerstate, rd: int, rdep: int, rprod: int, producer_id: int):
        super().__init__(fuzzerstate, rd, rdep, rprod, producer_id)
        self.rd_t0 = 0
        self.rdep_t0 = 0
        self.rprod_t0 = 0

    def execute_t0(self, res, is_spike_resolution: bool = True):
        assert self.fuzzerstate.taint_en
        assert self.instr_func_t0 is not None, f"Cannot execute {self.get_str()}: no instr_func_t0 found."
        assert self.fuzzerstate is not None, f"fuzzerstate not set, cannot execute {self.get_str()}" 
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rprod].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rprod].get_val_t0()
        if is_spike_resolution:
            rs2_val = self.fuzzerstate.intregpickstate.regs[RELOCATOR_REGISTER_ID].get_val()
            rs2_val_t0 = self.fuzzerstate.intregpickstate.regs[RELOCATOR_REGISTER_ID].get_val_t0()
            assert rs2_val_t0 == 0, f"reloc register {ABI_INAMES[RELOCATOR_REGISTER_ID]} is tainted, this should not happen."
        else:
            rs2_val = self.fuzzerstate.intregpickstate.regs[self.rdep].get_val()
            rs2_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rdep].get_val_t0()
            assert rs2_val_t0 == 0, f"rdep {ABI_INAMES[self.rdep]} is tainted, this should not happen. {filter_reg_t0_traceback(self.rdep, self.addr,self.fuzzerstate,None, is_spike_resolution)}"

        assert rs1_val_t0 == 0, f"rprod is tainted, this should not happen."
        # Compute the taint results of the operation.
        res_t0 = self.instr_func_t0(rs1_val, rs1_val_t0, rs2_val, rs2_val_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res)

        assert res_t0 == 0, f"Result of {self.get_str()} is tainted, this should not happen."
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res, is_spike_resolution)

    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        if is_spike_resolution:
            res = self.fuzzerstate.intregpickstate.regs[self.rprod].get_val() ^ self.fuzzerstate.intregpickstate.regs[RELOCATOR_REGISTER_ID].get_val()
        else:
            res = self.fuzzerstate.intregpickstate.regs[self.rprod].get_val() ^ self.fuzzerstate.intregpickstate.regs[self.rdep].get_val()  
        if taint_en:
            self.execute_t0(res, is_spike_resolution)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)
        self.fuzzerstate.advance_minstret()

    def compute_alt_res_t0(self, res):
        assert self.fuzzerstate.taint_en
        res_t0 = 0x0
        for alt_rs1_id, alt_rs1 in self.fuzzerstate.intregpickstate.regs.items():
            if ((alt_rs1_id^self.rprod)&(~self.rprod_t0) == 0 and self.rprod_t0 != 0) : # only differ in the tainted bits, therefore this register could have been used for addition instead and we need to derive the taints
                print(f"{ABI_INAMES[alt_rs1_id]} matches {ABI_INAMES[self.rprod]} in untainted bits")
                alt_res = self.instr_func(alt_rs1.get_val(), self.fuzzerstate.intregpickstate.regs[RELOCATOR_REGISTER_ID].get_val())
                res_t0 |= alt_res^res
        return res_t0




class IntLoadInstruction_t0(IntLoadInstruction, RDInstruction_t0):
    def __init__(self, fuzzerstate, instr_str: str, rd: int, rs1: int, imm: int, producer_id: int, iscompressed: bool = False, is_rd_nonpickable_ok: bool = False):
        super().__init__(fuzzerstate, instr_str, rd, rs1, imm, producer_id, iscompressed, is_rd_nonpickable_ok)
        self.rd_t0 = 0
        self.imm_t0 = 0
        self.rs1_t0 = 0
        self.n_bytes = 1 if instr_str in ["lb","lbu"] else 2 if instr_str in ["lh","lhu"] else 4 if instr_str == "lw" else 8 if instr_str == "ld" else -1
        assert self.n_bytes != -1
        self.mask = 2**(self.n_bytes*8)-1
        
    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        addr = INSTR_FUNCS["addi"](rs1_val,self.imm, self.fuzzerstate.is_design_64bit)
        try:
            res = self.fuzzerstate.memview.read(addr,self.n_bytes)
        except Exception as e:
            print(f"{self.get_str()} failed to read from addr {hex(addr)}. {ABI_INAMES[self.rs1]}:{hex(rs1_val)}")
            raise e
        if taint_en:
            self.execute_t0(res, is_spike_resolution)
        res = self.instr_func(res,self.fuzzerstate.is_design_64bit)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)
        self.fuzzerstate.advance_minstret()

    def execute_t0(self, res, is_spike_resolution):
        assert self.fuzzerstate.taint_en
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        assert rs1_val_t0 == 0, f"Source register {ABI_INAMES[self.rs1]} is tainted ({hex(rs1_val_t0)}), this is not allowed."
        assert self.imm_t0 == 0, f"Immediate is tainted ({hex(self.imm)}), this is not allowed."
        addr = INSTR_FUNCS["addi"](rs1_val, self.imm, self.fuzzerstate.is_design_64bit)
        res_t0 = self.fuzzerstate.memview.read_t0(addr,self.n_bytes)
        res_t0 = self.instr_func_t0(res_t0,self.fuzzerstate.is_design_64bit)
        # if res_t0:
        #     print(f"{self.get_str()} loaded tainted value from {hex(addr)}")
        self.writeback_t0(res_t0,res, is_spike_resolution) # We allow the rd field to be tainted, thus taint could be propagated to several destination registers.

class IntStoreInstruction_t0(IntStoreInstruction, BaseInstruction_t0):
    def __init__(self, fuzzerstate, instr_str: str, rs1: int, rs2: int, imm: int, producer_id: int, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, rs1, rs2, imm, producer_id, iscompressed)
        self.imm_t0 = 0
        self.rs1_t0 = 0
        self.rs2_t0 = 0
        self.n_bytes = 1 if instr_str == "sb" else 2 if instr_str == "sh" else 4 if instr_str == "sw" else 8 if instr_str == "sd" else -1
        assert self.n_bytes != -1
        self.mask = 2**(self.n_bytes*8)-1
    
    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        addr = INSTR_FUNCS["addi"](self.fuzzerstate.intregpickstate.regs[self.rs1].get_val(),self.imm, self.fuzzerstate.is_design_64bit)
        res = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        if taint_en:
            self.execute_t0(res, is_spike_resolution)
        self.fuzzerstate.memview.write(addr, res&self.mask, self.n_bytes)
        self.fuzzerstate.advance_minstret()

    def execute_t0(self, res, is_spike_resolution):
        assert self.fuzzerstate.taint_en
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs1_val_t0 =  self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        assert rs1_val_t0 == 0, f"Source register {ABI_INAMES[self.rs1]} is tainted ({hex(rs1_val_t0)}), this is not allowed."
        assert self.imm_t0 == 0, f"Immediate is tainted ({hex(self.imm)}), this is not allowed."
        addr = INSTR_FUNCS["addi"](rs1_val,self.imm, self.fuzzerstate.is_design_64bit)
        rs2_val_t0 =  self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_t0()
        self.fuzzerstate.memview.write_t0(addr,rs2_val_t0&self.mask, self.n_bytes) # We don't allow addresses to be tainted, thus we don't need a writeback here.


class RegdumpInstruction_t0(IntStoreInstruction_t0):
    def gen_bytecode_int(self, is_spike_resolution: bool):
        if is_spike_resolution:
            return rv32i_addi(0x0,0x0,0x0) # Return nop for spike resolution
        else:
            return super().gen_bytecode_int(is_spike_resolution)

    def get_str(self, is_spike_resolution):
        if not is_spike_resolution:
            return f"{hex(self.addr)}: {self.instr_str} {ABI_INAMES[self.rs2]}, {self.imm}({ABI_INAMES[self.rs1]})"
        else:
            return f"{hex(self.addr)}: nop"

    def check_regs_t0(self,val_t0):
        assert self.fuzzerstate.taint_en
        if PRINT_CHECK_REGS_T0:
            print(f"{hex(self.addr)}: Checking register taint: {ABI_INAMES[self.rs2]}:{hex(val_t0)}")
        mismatch = self.fuzzerstate.intregpickstate.regs[self.rs2].check_t0(val_t0)
        assert not mismatch, f"{hex(self.addr)}: {self.instr_str}: Taint mismatch for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n\t Traceback: {filter_reg_traceback(self.rs2,self.addr,self.fuzzerstate,val_t0,False).get_str(False)}"

    def check_regs(self,val):
        assert self.fuzzerstate.taint_en
        if PRINT_CHECK_REGS:
            print(f"{hex(self.addr)}: Checking register value: {ABI_INAMES[self.rs2]}:{hex(val)}")
        mismatch = self.fuzzerstate.intregpickstate.regs[self.rs2].check(val)

        assert not mismatch, f"{hex(self.addr)}: {self.instr_str}: Value mismatch for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n\t Traceback: {filter_reg_traceback(self.rs2,self.addr,self.fuzzerstate,val,False).get_str(False)}"

    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        if is_spike_resolution:
            self.fuzzerstate.advance_minstret()
        else:
            super().execute(taint_en,is_spike_resolution)

class SpecialInstruction_t0(SpecialInstruction, BaseInstruction_t0):
    def __init__(self, fuzzerstate, instr_str: str, rd: int = 0, rs1: int = 0, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, rd, rs1, iscompressed)

    def execute(self, taint_en, is_spike_resolution):
        self.fuzzerstate.advance_minstret()

    def execute_t0(self, res, is_spike_resolution):
        assert 0

class BranchInstruction_t0(BranchInstruction, BaseInstruction_t0):
    def __init__(self, fuzzerstate, instr_str: str, rs1: int, rs2: int, imm: int, plan_taken: bool, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, rs1, rs2, imm, plan_taken, iscompressed)

    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        if taint_en:
            self.execute_t0(None,is_spike_resolution)
        self.fuzzerstate.advance_minstret()

    def execute_t0(self,res,is_spike_resolution):
        assert self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0() == 0, f"{self.instr_str} source register is tainted. This is not allowed."
        assert self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_t0() == 0, f"{self.instr_str} source register is tainted. This is not allowed."


class CSRRegInstruction_t0(CSRRegInstruction, RDInstruction_t0):
    def __init__(self, fuzzerstate, instr_str: str, rd: int, rs1: int, csr_id: int, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, rd, rs1, csr_id, iscompressed)

    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        csr_val = self.fuzzerstate.csrfile.regs[self.csr_id].get_val()
        res = self.instr_func(rs1_val, csr_val, self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res,is_spike_resolution)
        self.fuzzerstate.csrfile.regs[self.csr_id].set_val(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(csr_val)
        if self.csr_id == CSR_IDS.MINSTRET and self.instr_str == "csrrw":
            return
        self.fuzzerstate.advance_minstret()

    def execute_t0(self,res,is_spike_resolution):
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs1_val_t0 = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0()
        csr_val = self.fuzzerstate.csrfile.regs[self.csr_id].get_val()
        csr_val_t0 = self.fuzzerstate.csrfile.regs[self.csr_id].get_val_t0()
        res_t0 = self.instr_func_t0(rs1_val, rs1_val_t0, csr_val, csr_val_t0, self.fuzzerstate.is_design_64bit)
        self.fuzzerstate.csrfile.regs[self.csr_id].set_val_t0(res_t0)
        self.writeback_t0(csr_val_t0,csr_val,is_spike_resolution)

class CSRImmInstruction_t0(CSRImmInstruction, RDInstruction_t0):
    def __init__(self, fuzzerstate, instr_str: str, rd: int, uimm: int, csr_id: int, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, rd, uimm, csr_id, iscompressed)
        self.uimm_t0 = 0

    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        csr_val = self.fuzzerstate.csrfile.regs[self.csr_id].get_val()
        res = self.instr_func(self.uimm, csr_val, self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res,is_spike_resolution)
        self.fuzzerstate.csrfile.regs[self.csr_id].set_val(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(csr_val)
        if self.csr_id == CSR_IDS.MINSTRET and self.instr_str == "csrrwi":
            return
        self.fuzzerstate.advance_minstret()

    def execute_t0(self,res,is_spike_resolution):
        csr_val = self.fuzzerstate.csrfile.regs[self.csr_id].get_val()
        csr_val_t0 = self.fuzzerstate.csrfile.regs[self.csr_id].get_val_t0()
        res_t0 = self.instr_func_t0(self.uimm, self.uimm_t0, csr_val, csr_val_t0, self.fuzzerstate.is_design_64bit)
        self.fuzzerstate.csrfile.regs[self.csr_id].set_val_t0(res_t0)
        self.writeback_t0(csr_val_t0,csr_val,is_spike_resolution)

def has_taint_trace(obj):
    return isinstance(obj, (RegImmInstruction_t0, ImmRdInstruction_t0, R12DInstruction_t0, CSRImmInstruction_t0, CSRRegInstruction_t0)) and obj.instr_str != "auipc"

class TvecWriterInstruction_t0(TvecWriterInstruction, BaseInstruction_t0):
    def __init__(self, fuzzerstate, is_mtvec: bool, rd: int, rs1: int, producer_id: int):
        super().__init__(fuzzerstate, is_mtvec, rd, rs1, producer_id)
        csr_id = CSR_IDS.MTVEC if is_mtvec else CSR_IDS.STVEC
        self.csr_instr = CSRRegInstruction_t0(fuzzerstate, "csrrw", rd, rs1, csr_id)
        assert self.addr == self.csr_instr.addr

    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        self.csr_instr.execute(taint_en,is_spike_resolution)
    
class EPCWriterInstruction_t0(EPCWriterInstruction, BaseInstruction_t0):  
    def __init__(self, fuzzerstate, is_mepc: bool, rd: int, rs1: int, producer_id: int):
        super().__init__(fuzzerstate, is_mepc, rd, rs1, producer_id)
        self.rd = rd
        self.rs1 = rs1
        self.csr_id = CSR_IDS.MEPC if is_mepc else CSR_IDS.SEPC
        self.csr_instr = CSRRegInstruction_t0(fuzzerstate, "csrrw", rd, rs1, self.csr_id)
        assert self.addr == self.csr_instr.addr

    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        self.csr_instr.execute(taint_en,is_spike_resolution)

class GenericCSRWriterInstruction_t0(GenericCSRWriterInstruction, BaseInstruction_t0):
    def __init__(self, fuzzerstate, csr_id: int, rd: int, rs1: int, producer_id: int, val_to_write_spike: int, val_to_write_cpu: int):
        super().__init__(fuzzerstate, csr_id, rd, rs1, producer_id, val_to_write_spike, val_to_write_cpu)
        self.rd = rd
        self.rs1 = rs1
        self.csr_instr = CSRRegInstruction_t0(fuzzerstate,"csrrw", rd, rs1, csr_id)
        assert self.addr == self.csr_instr.addr

    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        self.csr_instr.execute(taint_en,is_spike_resolution)

class SimpleExceptionEncapsulator_t0(SimpleExceptionEncapsulator, BaseInstruction_t0):
    def __init__(self, fuzzerstate, is_mtvec, producer_id: int, instr: BaseInstruction, exception_op_type: ExceptionCauseVal):
        super().__init__(fuzzerstate, is_mtvec, producer_id, instr)
        self.exception_op_type = exception_op_type
        assert self.addr == self.instr.addr

    def execute(self, taint_en, is_spike_resolution: bool = True):
        # print(f"{self.get_str(is_spike_resolution)}, setting MCAUSE to {self.exception_op_type}")
        self.fuzzerstate.csrfile.regs[CSR_IDS.MCAUSE].set_val(self.exception_op_type)
        self.fuzzerstate.csrfile.regs[CSR_IDS.MEPC].set_val(self.addr)

class SimpleIllegalInstruction_t0(SimpleIllegalInstruction, BaseInstruction_t0):
    def execute(self, taint_en, is_spike_resolution: bool = True):
        self.fuzzerstate.csrfile.regs[CSR_IDS.MCAUSE].set_val(ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION)
        self.fuzzerstate.csrfile.regs[CSR_IDS.MEPC].set_val(self.addr)

class MisalignedMemInstruction_t0(MisalignedMemInstruction, BaseInstruction_t0):
    def execute(self, taint_en, is_spike_resolution: bool = True):
        self.fuzzerstate.csrfile.regs[CSR_IDS.MCAUSE].set_val(self.exceptioncause_val)
        self.fuzzerstate.csrfile.regs[CSR_IDS.MEPC].set_val(self.addr)
