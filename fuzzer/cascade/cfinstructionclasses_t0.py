from params.fuzzparams import TAINT_EN
from cascade.randomize.pickbytecodetaints import OPCODE_FIELD_MASKS, OPCODE_FIELD_BITS
from cascade.cfinstructionclasses import *
from cascade.util import ExceptionCauseVal
from rv.asmutil import INSTR_FUNCS_T0, INSTR_FUNCS
from cascade.registers import ABI_INAMES
from rv.csrids import CSR_ABI_NAMES
from params.runparams import PRINT_CHECK_REGS_T0, PRINT_WRITEBACK_T0, PRINT_FILTERED_REG_TRACEBACK, DO_ASSERT
from common.spike import SPIKE_STARTADDR
import numpy as np
from rv.csrids import MPP_BIT, MIE_BIT, MPIE_BIT
from rv.csrids import SIE_BIT, SPIE_BIT, SPP_BIT
from rv.csrids import SIE_BIT, SPIE_BIT, SPP_BIT

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
            if instr_obj.addr == last_instr.paddr: # start collecting depending registers
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
            elif isinstance(instr_obj, PlaceholderPreConsumerInstr) and instr_obj.rdep in dep_regs and instr_obj.paddr in fuzzerstate.intregpickstate.writeback_trace_final:
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
            # else:
            #     print(f"{hex(addr_spike)}: {ABI_INAMES[trace_spike[0]]} <- {hex(trace_spike[1])}")

    return last_instr
###
# Abstract classes with taint
###
# does not inherit from BaseInstruction
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
                print(f"{hex(self.paddr)}: Checking register taint: {ABI_INAMES[reg_id]}:{hex(reg_val)}")
            mismatch = self.fuzzerstate.intregpickstate.regs[reg_id].check_t0(reg_val)
            assert not mismatch, f"{hex(self.paddr)}: {self.instr_str}: Taint mismatch for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n\t Traceback: {compute_reg_traceback(reg_id,self.paddr,self.fuzzerstate,reg_val).get_str()}"

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
            self.fuzzerstate.intregpickstate.add_writeback_trace(self, self.rd, res_t0, is_spike_resolution)
            return
        raise NotImplementedError
        for alt_rd_id, alt_rd in self.fuzzerstate.intregpickstate.regs.items():
            if (alt_rd_id^self.rd)&(~self.rd_t0) == 0: # only differ in the tainted bits, therefore this register will get tainted
                taints = alt_rd.get_val()^res # the taint vector is one in the bits that differ
                alt_rd.set_val_t0(taints | res_t0) # or with taint result from addition
                self.fuzzerstate.intregpickstate.add_writeback_trace(self.paddr, self.rd, taints | res_t0, is_spike_resolution)
                if PRINT_WRITEBACK_T0: 
                    print(f"writeback_t0: {self.get_str(is_spike_resolution)}: {ABI_INAMES[alt_rd_id]} <- {hex(taints | res_t0)} (= {hex(res_t0)} | ({hex(alt_rd.get_val())} ^ {hex(res)}) )")

# does not inherit from ImmInstruction
class ImmInstruction_t0(CFInstruction_t0):
    imm_t0: int
    def __init__(self, fuzzerstate, instr_str):
        super().__init__(fuzzerstate, instr_str)
        self.imm_t0 = 0x0

    def write_t0(self, is_spike_resolution: bool = False):
        if DO_ASSERT:
            assert self.paddr >= SPIKE_STARTADDR
            assert self.paddr < SPIKE_STARTADDR + self.fuzzerstate.memsize
        self.fuzzerstate.memview.write_t0(self.paddr, self.gen_bytecode_int_t0(is_spike_resolution), 4)
        # if self.imm_t0:
        #     print(f"{self.get_str()} adds taint extra with imm {hex(self.imm_t0)}")
        # else:
        #     print(f"{self.get_str()} reduces taint.")

###
# Concrete classes with taint: integers
###

class R12DInstruction_t0(R12DInstruction, RDInstruction_t0):
    def __init__(self, fuzzerstate, instr_str: str, rd: int, rs1: int, rs2: int, iscompressed: bool = False, is_rd_nonpickable_ok: bool = False):
        super().__init__(fuzzerstate, instr_str, rd, rs1, rs2, iscompressed, is_rd_nonpickable_ok)
        self.rs1_t0 = 0
        self.rs2_t0 = 0
        self.rd_t0 = 0

    def execute_t0(self, res, is_spike_resolution: bool):
        assert self.fuzzerstate.taint_en
        if self.paddr == -1:
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
        if self.paddr == -1:
            print(f"Skipping execution of {self.get_str()}")
            return
        assert self.instr_func is not None, f"Cannot execute {self.get_str()}: no instr_func found."
        assert self.fuzzerstate is not None, f"fuzzerstate not set, cannot execute {self.get_str()}" 
        if not is_spike_resolution:
            self.assert_addr()
            self.fuzzerstate.curr_pc += 4
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
    def __init__(self, fuzzerstate, instr_str: str, rd: int, imm: int, imm_t0: int = 0, iscompressed: bool = False, is_rd_nonpickable_ok: bool = False):
        super().__init__(fuzzerstate, instr_str, rd, imm, iscompressed, is_rd_nonpickable_ok)
        self.rd_t0 = 0       
        self.imm_t0 = imm_t0

    def gen_bytecode_int_t0(self, is_spike_resolution: bool):
        assert self.fuzzerstate.taint_en
        assert self.rd_t0 == 0, "Tainting register selection bits not supported yet."
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
        return masked_taint
 
    def compute_alt_res_t0(self, res):
        assert self.fuzzerstate.taint_en
        return 0x0 # skip possible immediates for now

    def execute_t0(self, res, is_spike_resolution: bool):
        assert self.fuzzerstate.taint_en
        # Compute the taint results of the operation. The address is never tainted.
        res_t0 = self.instr_func_t0(self.paddr, 0x0, self.imm, self.imm_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res)
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res, is_spike_resolution)

    # Overrides function in ImmRdInstructionClass
    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        if not is_spike_resolution:
            self.assert_addr()
            self.fuzzerstate.curr_pc += 4
        if USE_MMU:
            res = self.instr_func(self.vaddr, self.imm, self.fuzzerstate.is_design_64bit)
        else:
            res = self.instr_func(self.paddr, self.imm, self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res, is_spike_resolution)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)
        self.fuzzerstate.advance_minstret()



class RegImmInstruction_t0(RegImmInstruction, ImmInstruction_t0, RDInstruction_t0):
    def __init__(self, fuzzerstate, instr_str: str, rd: int, rs1: int, imm: int, imm_t0: int = 0, iscompressed: bool = False, is_rd_nonpickable_ok: bool = False):
        super().__init__(fuzzerstate, instr_str, rd, rs1, imm, iscompressed, is_rd_nonpickable_ok)
        self.rs1_t0 = 0
        self.rd_t0 = 0
        self.imm_t0 = imm_t0

    def gen_bytecode_int_t0(self, is_spike_resolution: bool):
        assert self.fuzzerstate.taint_en, "Taint is disabled. Enable to use this method."
        assert self.rs1_t0 == 0 and self.rd_t0 == 0, "Tainting register selection bits not supported yet."
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
        if not is_spike_resolution:
            self.assert_addr()
            self.fuzzerstate.curr_pc += 4
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
        if not is_spike_resolution:
            self.assert_addr()
            if USE_MMU:
                self.fuzzerstate.curr_pc = self.vaddr + self.imm
            else:
                self.fuzzerstate.curr_pc = self.paddr + self.imm
        if USE_MMU:
            res = self.instr_func(self.vaddr, 0x0, self.fuzzerstate.is_design_64bit)
        else:
            res = self.instr_func(self.paddr, 0x0, self.fuzzerstate.is_design_64bit)
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
        assert self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0() == 0, f"{self.get_str()}: source register is tainted. This is not allowed."
        # We assume the PC does not get tainted, therefore the result of JAL is never either.
        self.writeback_t0(0x0, res, is_spike_resolution)

    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        if not is_spike_resolution:
            self.assert_addr()
            self.fuzzerstate.curr_pc = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val() + self.imm
        if USE_MMU:
            res = self.instr_func(self.vaddr, 0x0, self.fuzzerstate.is_design_64bit)
        else:
            res = self.instr_func(self.paddr, 0x0, self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res, is_spike_resolution)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)
        self.fuzzerstate.advance_minstret()


## Extended Placeholder Instructions ##
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
                spike_res_off = self.spike_resolution_offset
                if USE_MMU and self.fuzzerstate.is_design_64bit and self.produce_va_layout != -1: 
                    spike_res_off = (self.spike_resolution_offset | 0x80000000) & 0xffffffff # TODO double check if the check of the 64th bit is valid
                imm = li_into_reg(to_unsigned(spike_res_off, self.fuzzerstate.is_design_64bit), False)[0]
        else:
            assert self.rtl_offset is not None
            rtl_off = self.rtl_offset
            if USE_MMU and self.fuzzerstate.is_design_64bit and self.produce_va_layout != -1:
                rtl_off = (self.rtl_offset | 0x80000000) & 0xffffffff # TODO double check if the check of the 64th bit is valid
            self.assert_addr()
            self.fuzzerstate.curr_pc += 4
            imm = li_into_reg(to_unsigned(rtl_off, self.fuzzerstate.is_design_64bit), False)[0]

        res = self.instr_func(None,imm,self.fuzzerstate.is_design_64bit)
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
                assert self.fuzzerstate.intregpickstate.regs[self.rd].get_val_t0() == 0
                if taint_en:
                    self.execute_t0(None,is_spike_resolution)
                return
            else:
                spike_res_off = self.spike_resolution_offset
                if USE_MMU and self.fuzzerstate.is_design_64bit and self.produce_va_layout != -1:
                    spike_res_off = (self.spike_resolution_offset | 0x80000000) & 0xffffffff
                uimm = li_into_reg(to_unsigned(spike_res_off, self.fuzzerstate.is_design_64bit), False)[1]
        else:
            rtl_off = self.rtl_offset
            if USE_MMU and self.fuzzerstate.is_design_64bit and self.produce_va_layout != -1: 
                rtl_off = (self.rtl_offset | 0x80000000) & 0xffffffff # TODO double check if the check of the 64th bit is valid
            self.assert_addr()
            self.fuzzerstate.curr_pc += 4
            uimm = li_into_reg(to_unsigned(rtl_off, self.fuzzerstate.is_design_64bit), False)[1]
        rd_val = self.fuzzerstate.intregpickstate.regs[self.rd].get_val()
        res = self.instr_func(rd_val, uimm, self.fuzzerstate.is_design_64bit)
        if taint_en:
            self.execute_t0(res, is_spike_resolution)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)
        self.fuzzerstate.advance_minstret()

# Does not inherit from RDInstruction_t0 since it writes to rdep
class PlaceholderPreConsumerInstr_t0(PlaceholderPreConsumerInstr, BaseInstruction_t0):
    def __init__(self, fuzzerstate, rdep: int, producer_id: int, is_rprod: bool = False):
        super().__init__(fuzzerstate, rdep, producer_id, is_rprod)
        self.rdep_t0 = 0

    def execute_t0(self, res, is_spike_resolution):
        assert self.fuzzerstate.taint_en
        rdep_taint = self.fuzzerstate.intregpickstate.regs[self.rdep].get_val_t0()
        assert rdep_taint == 0, "rdep is tainted, this should not happen."
        rmask_taint = self.fuzzerstate.intregpickstate.regs[RDEP_MASK_REGISTER_ID].get_val_t0()
        assert rmask_taint == 0, "rmask is tainted, this should not happen."
        self.writeback_t0(0, res, is_spike_resolution)

    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        if not is_spike_resolution:
            self.assert_addr()
            self.fuzzerstate.curr_pc += 4
        rdep_val = self.fuzzerstate.intregpickstate.regs[self.rdep].get_val()
        if USE_MMU and self.fuzzerstate.is_design_64bit and self.is_rprod and self.produce_va_layout != -1:
            mask = self.fuzzerstate.intregpickstate.regs[RPROD_MASK_REGISTER_ID].get_val()
        elif USE_MMU and self.fuzzerstate.is_design_64bit and self.produce_va_layout != -1:
            mask = self.fuzzerstate.intregpickstate.regs[RDEP_MASK_REGISTER_ID_VIRT].get_val()
        else:
            mask = self.fuzzerstate.intregpickstate.regs[RDEP_MASK_REGISTER_ID].get_val()
        res = self.instr_func(rdep_val,mask,self.fuzzerstate.is_design_64bit)
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
            self.fuzzerstate.intregpickstate.add_writeback_trace(self, self.rdep, res_t0, is_spike_resolution)
            return
        raise NotImplementedError
        for alt_rdep_id, alt_rdep in self.fuzzerstate.intregpickstate.regs.items():
            if (alt_rdep_id^self.rdep)&(~self.rdep_t0) == 0 and self.rdep_t0 != 0: # only differ in the tainted bits, therefore this register will get tainted
                taints = alt_rdep.get_val()^res # the taint vector is one in the bits that differ
                alt_rdep.set_val_t0(taints | res_t0) # or with taint result from addition
                self.fuzzerstate.intregpickstate.add_writeback_trace(self.paddr, self.rdep, taints | res_t0, is_spike_resolution)
                if PRINT_WRITEBACK_T0:
                    print(f"writeback_t0: {self.get_str(is_spike_resolution)}: {ABI_INAMES[alt_rdep_id]} <- {hex(taints | res_t0)} ({ABI_INAMES[alt_rdep_id]} ^ {ABI_INAMES[self.rdep]})")


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
            assert rs2_val_t0 == 0, f"rdep {ABI_INAMES[self.rdep]} is tainted, this should not happen. {filter_reg_t0_traceback(self.rdep, self.paddr,self.fuzzerstate,None, is_spike_resolution)}"

        assert rs1_val_t0 == 0, f"rprod is tainted, this should not happen."
        # Compute the taint results of the operation.
        res_t0 = self.instr_func_t0(rs1_val, rs1_val_t0, rs2_val, rs2_val_t0, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_t0 |= self.compute_alt_res_t0(res)

        assert res_t0 == 0, f"Result of {self.get_str()} is tainted, this should not happen."
        # Writeback taints according to tainted bits in rd.
        self.writeback_t0(res_t0, res, is_spike_resolution)

    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        if not is_spike_resolution:
            self.assert_addr()
            self.fuzzerstate.curr_pc += 4
        rprod_val = self.fuzzerstate.intregpickstate.regs[self.rprod].get_val()
        if is_spike_resolution:
            if USE_MMU and self.produce_va_layout != -1:
                self.fuzzerstate.advance_minstret()
                if taint_en:
                    self.execute_t0(0, is_spike_resolution)
                    self.fuzzerstate.advance_minstret()
                return
            rdep_val = self.fuzzerstate.intregpickstate.regs[RELOCATOR_REGISTER_ID].get_val()
        else:
            rdep_val = self.fuzzerstate.intregpickstate.regs[self.rdep].get_val()  
        res = self.instr_func(rprod_val,rdep_val,self.fuzzerstate.is_design_64bit)
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
        self.n_bytes = 1 if instr_str in ["lb","lbu"] else 2 if instr_str in ["lh","lhu"] else 4 if instr_str in ["lw","lwu"] else 8 if instr_str == "ld" else -1
        assert self.n_bytes != -1 # sanity check
        self.mask = 2**(self.n_bytes*8)-1
        
    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        if not is_spike_resolution:
            self.assert_addr()
            self.fuzzerstate.curr_pc += 4
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
        if not is_spike_resolution:
            self.assert_addr()
            self.fuzzerstate.curr_pc += 4
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
            return f"{hex(self.paddr)}: {self.instr_str} {ABI_INAMES[self.rs2]}, {self.imm}({ABI_INAMES[self.rs1]})"
        else:
            return f"{hex(self.paddr)}: nop"

    def check_regs_t0(self,val_t0):
        assert self.fuzzerstate.taint_en
        if PRINT_CHECK_REGS_T0:
            print(f"{hex(self.paddr)}: Checking register taint: {ABI_INAMES[self.rs2]}:{hex(val_t0)}")
        mismatch = self.fuzzerstate.intregpickstate.regs[self.rs2].check_t0(val_t0)
        assert not mismatch, f"{hex(self.paddr)}: {self.instr_str}: Taint mismatch for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n\t Traceback: {filter_reg_traceback(self.rs2,self.paddr,self.fuzzerstate,val_t0,False).get_str(False)}"

    def check_regs(self,val):
        if PRINT_CHECK_REGS:
            print(f"{hex(self.paddr)}: Checking register value: {ABI_INAMES[self.rs2]}:{hex(val)}")
        mismatch = self.fuzzerstate.intregpickstate.regs[self.rs2].check(val)
        assert not mismatch, f"{hex(self.paddr)}: {self.instr_str}: Value mismatch for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n\t Traceback: {filter_reg_traceback(self.rs2,self.paddr,self.fuzzerstate,val,False).get_str(False)}"

    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        if is_spike_resolution:
            self.fuzzerstate.advance_minstret()
        else:
            super().execute(taint_en,is_spike_resolution)

class SpecialInstruction_t0(SpecialInstruction, BaseInstruction_t0):
    def __init__(self, fuzzerstate, instr_str: str, rd: int = 0, rs1: int = 0, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, rd, rs1, iscompressed)

    def execute(self, taint_en, is_spike_resolution):
        if not is_spike_resolution:
            self.assert_addr()
            self.fuzzerstate.curr_pc += 4
        self.fuzzerstate.advance_minstret()

    def execute_t0(self, res, is_spike_resolution):
        assert 0



class BranchInstruction_t0(BranchInstruction, BaseInstruction_t0):
    def __init__(self, fuzzerstate, instr_str: str, rs1: int, rs2: int, imm: int, plan_taken: bool, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, rs1, rs2, imm, plan_taken, iscompressed)

    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        if not is_spike_resolution:
            self.assert_addr()
            self.fuzzerstate.curr_pc += self.imm if self.plan_taken else 4
        if taint_en:
            self.execute_t0(None,is_spike_resolution)
        self.fuzzerstate.advance_minstret()

    def execute_t0(self,res,is_spike_resolution):
        assert self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_t0() == 0, f"{self.get_str()}: source register is tainted. This is not allowed."
        assert self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_t0() == 0, f"{self.get_str()}: source register is tainted. This is not allowed."


class CSRRegInstruction_t0(CSRRegInstruction, RDInstruction_t0):
    def __init__(self, fuzzerstate, instr_str: str, rd: int, rs1: int, csr_id: int, iscompressed: bool = False, is_satp_smode = (False, None), mpp_val = None):
        super().__init__(fuzzerstate, instr_str, rd, rs1, csr_id, iscompressed, is_satp_smode, mpp_val)

    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        # if self.csr_id == CSR_IDS.MEDELEG:
        #     print(f"Executing {self.get_str()}: {hex(self.fuzzerstate.intregpickstate.regs[self.rd].get_val())}, {hex(self.fuzzerstate.csrfile.regs[self.csr_id].get_val())}, {hex(self.fuzzerstate.intregpickstate.regs[self.rs1].get_val())}")
        if not is_spike_resolution:
            self.assert_addr()
            self.fuzzerstate.curr_pc += 4
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
        if not is_spike_resolution:
            self.assert_addr()
            self.fuzzerstate.curr_pc += 4
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

# Used to check if a register dump should be inserted after instruction in Fuzzerstate::appen_and_execute if enabled.
def has_taint_trace(obj):
    return isinstance(obj, (RegImmInstruction_t0, ImmRdInstruction_t0, R12DInstruction_t0, CSRImmInstruction_t0, CSRRegInstruction_t0)) and obj.instr_str != "auipc"

class MstatusWriterInstruction_t0(MstatusWriterInstruction, BaseInstruction_t0):
    def __init__(self, rd: int, rs1: int, producer_id: int, instr_str: str, mstatus_mask: int, old_sum_mprv=...):
        super().__init__(rd, rs1, producer_id, instr_str, mstatus_mask, old_sum_mprv)
        self.csr_instr = CSRRegInstruction_t0(instr_str, rd, rs1, CSR_IDS.MSTATUS)

    def execute(self, taint_en, is_spike_resolution: bool = True):
        self.csr_instr.execute(taint_en, is_spike_resolution)
        
class TvecWriterInstruction_t0(TvecWriterInstruction, BaseInstruction_t0):
    def __init__(self, fuzzerstate, is_mtvec: bool, rd: int, rs1: int, producer_id: int):
        super().__init__(fuzzerstate, is_mtvec, rd, rs1, producer_id)
        csr_id = CSR_IDS.MTVEC if is_mtvec else CSR_IDS.STVEC
        self.csr_instr = CSRRegInstruction_t0(fuzzerstate, "csrrw", rd, rs1, csr_id)
        assert self.paddr == self.csr_instr.paddr

    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        self.csr_instr.execute(taint_en,is_spike_resolution)
    
class EPCWriterInstruction_t0(EPCWriterInstruction, BaseInstruction_t0):  
    def __init__(self, fuzzerstate, is_mepc: bool, rd: int, rs1: int, producer_id: int):
        super().__init__(fuzzerstate, is_mepc, rd, rs1, producer_id)
        self.rd = rd
        self.rs1 = rs1
        self.csr_id = CSR_IDS.MEPC if is_mepc else CSR_IDS.SEPC
        self.csr_instr = CSRRegInstruction_t0(fuzzerstate, "csrrw", rd, rs1, self.csr_id)
        assert self.paddr == self.csr_instr.paddr

    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        self.csr_instr.execute(taint_en,is_spike_resolution)

class GenericCSRWriterInstruction_t0(GenericCSRWriterInstruction, BaseInstruction_t0):
    def __init__(self, fuzzerstate, csr_id: int, rd: int, rs1: int, producer_id: int, val_to_write_spike: int, val_to_write_cpu: int):
        super().__init__(fuzzerstate, csr_id, rd, rs1, producer_id, val_to_write_spike, val_to_write_cpu)
        self.rd = rd
        self.rs1 = rs1
        self.csr_instr = CSRRegInstruction_t0(fuzzerstate,"csrrw", rd, rs1, csr_id)
        assert self.paddr == self.csr_instr.paddr

    def execute(self, taint_en: bool = TAINT_EN, is_spike_resolution: bool = True):
        self.csr_instr.execute(taint_en,is_spike_resolution)


class PrivilegeDescentInstruction_t0(PrivilegeDescentInstruction, BaseInstruction_t0):
    def execute(self, taint_en, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF):
        if is_spike_resolution:
            return
        if self.is_mret:
            self.execute_mret()
        else:
            self.execute_sret()

    def execute_mret(self):
        mstatus = self.fuzzerstate.csrfile.regs[CSR_IDS.MSTATUS].get_val()
        mstatus_t0 = self.fuzzerstate.csrfile.regs[CSR_IDS.MSTATUS].get_val_t0()
        assert mstatus_t0 == 0

        if not self.fuzzerstate.is_design_64bit:
            mstatus |= self.fuzzerstate.csrfile.regs[CSR_IDS.MSTATUSH] << 32

        mpp = PrivilegeStateEnum((mstatus>>MPP_BIT)&0x3) # MPP has two bits
        assert self.priv_level_after_op == mpp, f"{self.get_str()}: Returning into wrong privelege: mpp is {mpp.name}, should be {self.priv_level_after_op.name}, mstatus is {hex(mstatus)}"
        mpie = (mstatus>>MPIE_BIT)&1

        mstatus &= ~(0x3<<MPP_BIT) # set MPP bits to 0
        mstatus = ((~(1<<MIE_BIT))&mstatus) | (mpie<<MIE_BIT)# set MIE bit to mpie
        mstatus |= (1<<MPIE_BIT)# set MPIE bit to 1
        # print(f"{self.get_str()} MRET mstatus: {hex(mstatus_cpy)} -> {hex(mstatus)}")
        self.fuzzerstate.csrfile.regs[CSR_IDS.MSTATUS].set_val(mstatus)

        self.fuzzerstate.curr_pc = self.fuzzerstate.csrfile.regs[CSR_IDS.MEPC].get_val()
        self.fuzzerstate.advance_minstret()

    def execute_sret(self):
        sstatus = self.fuzzerstate.csrfile.regs[CSR_IDS.SSTATUS].get_val()
        sstatus_t0 = self.fuzzerstate.csrfile.regs[CSR_IDS.SSTATUS].get_val_t0()
        assert sstatus_t0 == 0

        spp = PrivilegeStateEnum((sstatus>>SPP_BIT)&1)
        assert self.priv_level_after_op == spp,  f"{self.get_str()}: Returning into wrong privelege: spp is {spp.name}, should be {self.priv_level_after_op.name}: sstatus is {hex(sstatus)}"
        spie = (sstatus>>SPIE_BIT)&1
        
        sstatus &= ~(1<<SPP_BIT) # set SPP bit to 0
        sstatus = ((~(1<<SIE_BIT))&sstatus) | (spie<<SIE_BIT)# set SIE bit to SPIE
        sstatus |= (1<<SPIE_BIT)# set SPIE bit to 1
        self.fuzzerstate.csrfile.regs[CSR_IDS.SSTATUS].set_val(sstatus)

        self.fuzzerstate.curr_pc = self.fuzzerstate.csrfile.regs[CSR_IDS.SEPC].get_val()
        self.fuzzerstate.advance_minstret()




class SimpleIllegalInstruction_t0(SimpleIllegalInstruction, BaseInstruction_t0):
    def execute(self, taint_en, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF):
        if is_spike_resolution:
            return
        self.assert_addr()
        medeleg = self.fuzzerstate.csrfile.regs[CSR_IDS.MEDELEG].get_val()
        mstatus = self.fuzzerstate.csrfile.regs[CSR_IDS.MSTATUS].get_val()
        # assert self.fuzzerstate.privilegestate.medeleg_val == medeleg , f"MEDELEG in CSRFile not consistent with fuzzerstate.privelegestate: {hex(self.val)}, {hex(self.fuzzerstate.privilegestate.medeleg_val)}. {self.fuzzerstate.instr_objs_seq[-1][-1].get_str()}"
        if (medeleg>>ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION)&1:
            if self.priv_level != PrivilegeStateEnum.MACHINE: # User and supervisor can delegate to supervisor.
                assert self.priv_level_after_op == PrivilegeStateEnum.SUPERVISOR
                self.fuzzerstate.csrfile.regs[CSR_IDS.SCAUSE].set_val(ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION)
                if USE_MMU:
                    # print(f"{self.get_str()} setting SEPC to {hex(self.vaddr)}")
                    self.fuzzerstate.csrfile.regs[CSR_IDS.SEPC].set_val(self.vaddr)
                else:
                    self.fuzzerstate.csrfile.regs[CSR_IDS.SEPC].set_val(self.paddr)
                sie = (mstatus>>SIE_BIT)&1

                mstatus &= ~(1<<SPP_BIT)
                mstatus |= (self.priv_level&1 << SPP_BIT) # set spp to current priv, TODO make sure priveleges work in final sim too

                mstatus &= ~(1<<SPIE_BIT) # set spie to sie
                mstatus |= (sie<<SPIE_BIT)
                mstatus &= ~(1<<SIE_BIT) # clear sie bit

                self.fuzzerstate.csrfile.regs[CSR_IDS.MSTATUS].set_val(mstatus)
                target_pc = self.fuzzerstate.csrfile.regs[CSR_IDS.STVEC].get_val()
            else: # Cant delegate to supervisor if in machine mode.
                assert self.priv_level_after_op == PrivilegeStateEnum.MACHINE
                self.fuzzerstate.csrfile.regs[CSR_IDS.MCAUSE].set_val(ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION)
                if USE_MMU:
                    self.fuzzerstate.csrfile.regs[CSR_IDS.MEPC].set_val(self.vaddr)
                else:
                    self.fuzzerstate.csrfile.regs[CSR_IDS.MEPC].set_val(self.paddr)
                sie = (mstatus>>SIE_BIT)&1

                mstatus &= ~(1<<SPP_BIT)
                mstatus |= (self.priv_level&1 << SPP_BIT) # set spp to current priv, TODO make sure priveleges work in final sim too

                mstatus &= ~(1<<SPIE_BIT) # set spie to sie
                mstatus |= (sie<<SPIE_BIT)
                mstatus &= ~(1<<SIE_BIT) # clear sie bit

                self.fuzzerstate.csrfile.regs[CSR_IDS.MSTATUS].set_val(mstatus)
                target_pc = self.fuzzerstate.csrfile.regs[CSR_IDS.MTVEC].get_val()
        else:
            assert self.priv_level_after_op == PrivilegeStateEnum.MACHINE
            if USE_MMU:
                self.fuzzerstate.csrfile.regs[CSR_IDS.MEPC].set_val(self.vaddr)
            else:
                self.fuzzerstate.csrfile.regs[CSR_IDS.MEPC].set_val(self.paddr)
            self.fuzzerstate.csrfile.regs[CSR_IDS.MCAUSE].set_val(ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION)
            target_pc = self.fuzzerstate.csrfile.regs[CSR_IDS.MTVEC].get_val()
            # self.fuzzerstate.privilegestate.privstate =  PrivilegeStateEnum.MACHINE

        # assert self.priv_level_after_op == self.fuzzerstate.privilegestate.privstate, f"{self.get_str()}: Did not enter expected privelege: expected {self.priv_level_after_op.name}, entered {self.fuzzerstate.privilegestate.privstate.name} (delegated: {(medeleg>>ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION)&1})"
        
        self.fuzzerstate.curr_pc = target_pc


class SimpleExceptionEncapsulator_t0(SimpleExceptionEncapsulator, BaseInstruction_t0):
    def execute(self, taint_en, is_spike_resolution: bool = True):
        if is_spike_resolution:
            return
        self.assert_addr()
        medeleg = self.fuzzerstate.csrfile.regs[CSR_IDS.MEDELEG].get_val()
        mstatus = self.fuzzerstate.csrfile.regs[CSR_IDS.MSTATUS].get_val()
        if (medeleg>>self.exception_op_type)&1: # If its delegated
            if self.priv_level != PrivilegeStateEnum.MACHINE:
                assert self.priv_level_after_op ==  PrivilegeStateEnum.SUPERVISOR, f"{self.get_str()}: medeleg {hex(medeleg)}"
                assert not self.is_mtvec, f"{self.get_str()}: medeleg {hex(medeleg)}"
                self.fuzzerstate.csrfile.regs[CSR_IDS.SCAUSE].set_val(self.exception_op_type)
                if USE_MMU:
                    # print(f"{self.get_str()} setting SEPC to {hex(self.vaddr)}")
                    self.fuzzerstate.csrfile.regs[CSR_IDS.SEPC].set_val(self.vaddr)
                else:
                    self.fuzzerstate.csrfile.regs[CSR_IDS.SEPC].set_val(self.paddr)

                sie = (mstatus>>SIE_BIT)&1

                mstatus &= ~(1<<SPP_BIT)
                # print(f"Priv at time of trap {self.fuzzerstate.privilegestate.privstate.name}")
                mstatus |= (self.priv_level&1 << SPP_BIT) # set spp to current priv, TODO make sure priveleges work in final sim too

                mstatus &= ~(1<<SPIE_BIT) # set spie to sie
                mstatus |= (sie<<SPIE_BIT)
                mstatus &= ~(1<<SIE_BIT) # clear sie bit

                self.fuzzerstate.csrfile.regs[CSR_IDS.MSTATUS].set_val(mstatus)
                target_pc = self.fuzzerstate.csrfile.regs[CSR_IDS.STVEC].get_val()
            else: # Cant delegate so supervisor if in machine mode.
                assert self.priv_level_after_op ==  PrivilegeStateEnum.MACHINE
                assert self.is_mtvec, f"{self.get_str()}"
                self.fuzzerstate.csrfile.regs[CSR_IDS.MCAUSE].set_val(self.exception_op_type)
                if USE_MMU:
                    self.fuzzerstate.csrfile.regs[CSR_IDS.MEPC].set_val(self.vaddr)
                else:
                    self.fuzzerstate.csrfile.regs[CSR_IDS.MEPC].set_val(self.paddr)
                sie = (mstatus>>SIE_BIT)&1

                mstatus &= ~(1<<SPP_BIT)
                # print(f"Priv at time of trap {self.fuzzerstate.privilegestate.privstate.name}")
                mstatus |= (self.priv_level&1 << SPP_BIT) # set spp to current priv, TODO make sure priveleges work in final sim too

                mstatus &= ~(1<<SPIE_BIT) # set spie to sie
                mstatus |= (sie<<SPIE_BIT)
                mstatus &= ~(1<<SIE_BIT) # clear sie bit

                self.fuzzerstate.csrfile.regs[CSR_IDS.MSTATUS].set_val(mstatus)
                target_pc = self.fuzzerstate.csrfile.regs[CSR_IDS.MTVEC].get_val()

            # print(f"{self.get_str()} delegated to supervisor, sepc set to {hex(self.addr)}, {'scause' if self.instr.instr_str != 'ebreak' else 'mcause' } set to {hex(self.exception_op_type)}, mepc is {hex(self.fuzzerstate.csrfile.regs[CSR_IDS.MEPC].get_val())}")
        else:
            assert self.priv_level_after_op ==  PrivilegeStateEnum.MACHINE
            assert self.is_mtvec, f"{self.get_str()}"
            if USE_MMU:
                self.fuzzerstate.csrfile.regs[CSR_IDS.MEPC].set_val(self.vaddr)
            else:
                self.fuzzerstate.csrfile.regs[CSR_IDS.MEPC].set_val(self.paddr)
            self.fuzzerstate.csrfile.regs[CSR_IDS.MCAUSE].set_val(self.exception_op_type)
            target_pc = self.fuzzerstate.csrfile.regs[CSR_IDS.MTVEC].get_val()
            # self.fuzzerstate.privilegestate.privstate =  PrivilegeStateEnum.MACHINE
            # print(f"{self.get_str()} setting mepc to {hex(self.addr)}, mcause to {hex(self.exception_op_type)}")
            # print(f"Going to {hex(target_pc)}")
        # assert self.priv_level_after_op == self.fuzzerstate.privilegestate.privstate, f"{self.get_str()}: Did not enter expected privelege: expected {self.priv_level_after_op.name}, entered {self.fuzzerstate.privilegestate.privstate.name} (delegated: {(medeleg>>self.exception_op_type)&1})"
        self.fuzzerstate.curr_pc = target_pc

        # print(f"{self.get_str()}: mstatus: {hex(mstatus_cpy)} -> {hex(mstatus)}, medeleg: {hex(medeleg)}")

class MisalignedMemInstruction_t0(MisalignedMemInstruction, BaseInstruction_t0):
    def execute(self, taint_en, is_spike_resolution: bool = True):
        if is_spike_resolution:
            return

        self.assert_addr()
        medeleg = self.fuzzerstate.csrfile.regs[CSR_IDS.MEDELEG].get_val()
        mstatus = self.fuzzerstate.csrfile.regs[CSR_IDS.MSTATUS].get_val()
        if (medeleg>>self.exceptioncause_val)&1:
            if self.priv_level != PrivilegeStateEnum.MACHINE:
                assert self.priv_level_after_op ==  PrivilegeStateEnum.SUPERVISOR, f"{self.get_str()}: medeleg {hex(medeleg)}"
                assert not self.is_mtvec, f"{self.get_str()}"
                self.fuzzerstate.csrfile.regs[CSR_IDS.SCAUSE].set_val(self.exceptioncause_val)
                if USE_MMU:
                    # print(f"{self.get_str()} setting SEPC to {hex(self.vaddr)}")
                    self.fuzzerstate.csrfile.regs[CSR_IDS.SEPC].set_val(self.vaddr)
                else:
                    self.fuzzerstate.csrfile.regs[CSR_IDS.SEPC].set_val(self.paddr)
                sie = (mstatus>>SIE_BIT)&1

                mstatus &= ~(1<<SPP_BIT)
                # print(f"Priv at time of trap {self.fuzzerstate.privilegestate.privstate.name}")
                mstatus |= (self.priv_level&1 << SPP_BIT) # set spp to current priv, TODO make sure priveleges work in final sim too

                mstatus &= ~(1<<SPIE_BIT) # set spie to sie
                mstatus |= (sie<<SPIE_BIT)
                mstatus &= ~(1<<SIE_BIT) # clear sie bit

                self.fuzzerstate.csrfile.regs[CSR_IDS.MSTATUS].set_val(mstatus)
                target_pc = self.fuzzerstate.csrfile.regs[CSR_IDS.STVEC].get_val()
                # self.fuzzerstate.privilegestate.privstate =  PrivilegeStateEnum.SUPERVISOR
            else: # Cant delegate so supervisor if in machine mode.
                assert self.priv_level_after_op ==  PrivilegeStateEnum.MACHINE, f"{self.get_str()}: medeleg {hex(medeleg)}"
                assert self.is_mtvec, f"{self.get_str()}"
                self.fuzzerstate.csrfile.regs[CSR_IDS.MCAUSE].set_val(self.exceptioncause_val)
                if USE_MMU:
                    self.fuzzerstate.csrfile.regs[CSR_IDS.MEPC].set_val(self.vaddr)
                else:
                    self.fuzzerstate.csrfile.regs[CSR_IDS.MEPC].set_val(self.paddr)
                sie = (mstatus>>SIE_BIT)&1

                mstatus &= ~(1<<SPP_BIT)
                # print(f"Priv at time of trap {self.fuzzerstate.privilegestate.privstate.name}")
                mstatus |= (self.priv_level&1 << SPP_BIT) # set spp to current priv, TODO make sure priveleges work in final sim too

                mstatus &= ~(1<<SPIE_BIT) # set spie to sie
                mstatus |= (sie<<SPIE_BIT)
                mstatus &= ~(1<<SIE_BIT) # clear sie bit

                self.fuzzerstate.csrfile.regs[CSR_IDS.MSTATUS].set_val(mstatus)
                target_pc = self.fuzzerstate.csrfile.regs[CSR_IDS.MTVEC].get_val()
                # self.fuzzerstate.privilegestate.privstate =  PrivilegeStateEnum.MACHINE

            # print(f"{self.get_str()} delegated to supervisor, sepc set to {hex(self.addr)}, {'scause' if self.instr.instr_str != 'ebreak' else 'mcause' } set to {hex(self.exception_op_type)}, mepc is {hex(self.fuzzerstate.csrfile.regs[CSR_IDS.MEPC].get_val())}")
        else:
            assert self.priv_level_after_op ==  PrivilegeStateEnum.MACHINE, f"{self.get_str()}: medeleg {hex(medeleg)}"
            assert self.is_mtvec, f"{self.get_str()}"
            if USE_MMU:
                self.fuzzerstate.csrfile.regs[CSR_IDS.MEPC].set_val(self.vaddr)
            else:
                self.fuzzerstate.csrfile.regs[CSR_IDS.MEPC].set_val(self.paddr)
            self.fuzzerstate.csrfile.regs[CSR_IDS.MCAUSE].set_val(self.exceptioncause_val)
            target_pc = self.fuzzerstate.csrfile.regs[CSR_IDS.MTVEC].get_val()
            # self.fuzzerstate.privilegestate.privstate =  PrivilegeStateEnum.MACHINE
            # print(f"{self.get_str()} setting mepc to {hex(self.addr)}, mcause to {hex(self.exception_op_type)}")
            # print(f"Going to {hex(target_pc)}")
        # assert self.priv_level_after_op == self.fuzzerstate.privilegestate.privstate, f"{self.get_str()}: Did not enter expected privelege: expected {self.priv_level_after_op.name}, entered {self.fuzzerstate.privilegestate.privstate.name} (delegated: {(medeleg>>self.exception_op_type)&1})"
        self.fuzzerstate.curr_pc = target_pc

        # print(f"{self.get_str()}: mstatus: {hex(mstatus_cpy)} -> {hex(mstatus)}, medeleg: {hex(medeleg)}")


class RawDataWord_t0(RawDataWord):
    def __init__(self, fuzzerstate, wordval: int, wordval_t0: int = 0, signed: bool = False):
        super().__init__(fuzzerstate, wordval, signed)
        if DO_ASSERT:
            if signed:
                assert wordval_t0 >= -(1 << 31)
                assert wordval_t0 < (1 << 32), f"signed wordval: {wordval}, 1 << 32: {1 << 32}"
            else:
                assert wordval_t0 >= 0
                assert wordval_t0 < (1 << 32), f"unsigned wordval: {hex(wordval)}, 1 << 32: {hex(1 << 32)}"
        self.wordval_t0 = wordval_t0
        if signed:
            if wordval_t0 < 0:
                self.wordval_t0 = wordval_t0 + (1 << 32)

    def gen_bytecode_int_t0(self, is_spike_resolution: bool):
        return self.wordval_t0
    
    def get_str(self, is_spike_resolution: bool = True):
        return f"{hex(self.paddr)}: {hex(self.wordval)}, {hex(self.wordval_t0)} (RAW DATA)"
    
    def execute(self, taint_en, is_spike_resolution: bool = True):
        return

    def write(self, is_spike_resolution: bool = False):
        if DO_ASSERT:
            assert self.paddr >= SPIKE_STARTADDR
            assert self.paddr < SPIKE_STARTADDR + self.fuzzerstate.memsize
        super().write(is_spike_resolution)
        self.write_t0(is_spike_resolution)

    def write_t0(self, is_spike_resolution: bool = False):
        if DO_ASSERT:
            assert self.paddr >= SPIKE_STARTADDR
            assert self.paddr < SPIKE_STARTADDR + self.fuzzerstate.memsize
        self.fuzzerstate.memview.write_t0(self.paddr, self.gen_bytecode_int_t0(is_spike_resolution), 4)

