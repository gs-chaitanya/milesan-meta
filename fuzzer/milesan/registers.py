from abc import ABC
import json

from milesan.util import IntRegIndivState
from rv.csrids import CSR_IDS, CSR_TYPES, CSRTypeEnum
from rv.csrids import SSTATUS_MASK, MSTATUS_MASK, MSTATUS_START_VAL, SSTATUS_START_VAL
from params.runparams import PRINT_CHECK_REGS_T0, CHECK_REGS_T0_PRECISE, PRINT_CHECK_REGS_T0_MISMATCH_OK, DO_ASSERT, IGNORE_SPIKE_OFFSET_IN_REG_CHECK
from params.fuzzparams import ALLOW_CSR_TAINT
ABI_INAMES = ["zero","ra","sp","gp","tp","t0","t1","t2","s0/fp","s1","a0","a1","a2","a3","a4","a5","a6","a7"]
ABI_INAMES += [f"s{i}" for i in range(2,12)] + [f"t{i}" for i in range(3,7)]
MAX_32b = 0xFFFFFFFF
MAX_64b = 0xFFFFFFFFFFFFFFFF
MAX_20b = 0xFFFFF
MAX_12b = 0xFFF

class __Register(ABC):
    def __init__(self,id: int = None, is_design_64bit: bool = False, val: int = 0, val_t0: int = 0, pickable: bool = False):
        self.id = id
        self.is_design_64bit = is_design_64bit
        self.mask = MAX_64b if is_design_64bit else MAX_32b
        self.n_bits = 64 if is_design_64bit else 32
        self.val = val&self.mask
        self.val_t0 = val_t0&self.mask
        self.pickable = pickable

    def set_val(self, val):
        if(self.id != 0):
            self.val = val&self.mask
        # print(f"Setting {ABI_INAMES[self.id]} to {hex(self.val)}")

    def set_val_t0(self, val_t0):
        if(self.id != 0):
            self.val_t0 = val_t0&self.mask

    def get_val(self):
        return self.val

    def get_val_t0(self):
        return self.val_t0

    def reset(self):
        self.val = 0
        self.val_t0 = 0

# TODO: extend this to allow field masks if necessary.
def _get_writeable_csr_value(value: int, csr_mask: int, csr_type: CSRTypeEnum):
    if csr_type == CSRTypeEnum.WLRL:
        return value&csr_mask # we only write the bits that can be written legally
    elif csr_type == CSRTypeEnum.WARL:
        return value&csr_mask # we only write the bits that can be written legally
    elif csr_type == CSRTypeEnum.WPRI:
        raise NotImplementedError("WPRI not implemented yet.")
    else:
        raise TypeError

class CSR(__Register):
    def __init__(self, csrfile, id: CSR_IDS, csr_mask, csr_type: CSRTypeEnum, val: int = 0, val_t0: int = 0):
        super().__init__(id, True, val, val_t0) # CSRs are always 64bit
        if DO_ASSERT:
            assert csr_type == CSRTypeEnum.WLRL or id == CSR_IDS.MEDELEG and csr_type == CSRTypeEnum.WARL, f"Only medeleg supported for other type than WLRL."
            assert csr_mask is not None, f"Got None as csr mask for {id.name}. Check if medeleg was profiled."
        self.csrfile = csrfile
        self.abi_name = id.name
        self.val = val
        self.val_t0 = val_t0
        self.csr_mask = csr_mask
        self.csr_type = csr_type
        self.unreliable = False # Used for e.g. SEPC/SCAUSE, when the order of exception handling is not strictly determined by the spec and thus the value is ambiguous until overwritten.

    def set_val(self, val):
        self.val = self.mask&_get_writeable_csr_value(val,self.csr_mask,self.csr_type)
        # if self.id == CSR_IDS.MCAUSE:
        #     print(f"Setting {self.abi_name} to {hex(self.val)} ({hex(val)})")

    def set_val_t0(self, val_t0):
        from common.exceptions import TaintedCSRException

        if not ALLOW_CSR_TAINT and val_t0:
            raise TaintedCSRException(self.id, self.abi_name)
        self.val_t0 = val_t0&self.mask

    def get_val(self):
        return self.val

    def get_val_t0(self):
        from common.exceptions import TaintedCSRException

        if not ALLOW_CSR_TAINT and self.val_t0:
            raise TaintedCSRException(self.id, self.abi_name)
        return self.val_t0

    def reset(self):
        self.set_val(0)
        self.set_val_t0(0)

# SSTATUS is a subset from MSTATUS so we need special classes for them.
class SStatus_CSR(CSR):
    def __init__(self, csrfile, val: int = 0, val_t0: int = 0):
        super().__init__(csrfile,CSR_IDS.SSTATUS,csrfile.csr_masks[CSR_IDS.SSTATUS],CSR_TYPES[CSR_IDS.MSTATUS], val, val_t0)
    
    def set_val(self, val):
        super().set_val(val)
        assert self.val&~(SSTATUS_START_VAL | SSTATUS_MASK) == 0 
        mstatus = self.csrfile.regs[CSR_IDS.MSTATUS].get_val()
        mstatus &= ~(SSTATUS_MASK & MAX_64b) # clear the bits
        mstatus |= (SSTATUS_MASK & self.val)
        self.csrfile.regs[CSR_IDS.MSTATUS].val = mstatus  # dont use setter here

class MStatus_CSR(CSR):
    def __init__(self, csrfile, val: int = 0, val_t0: int = 0):
        super().__init__(csrfile,CSR_IDS.MSTATUS,csrfile.csr_masks[CSR_IDS.MSTATUS],CSR_TYPES[CSR_IDS.MSTATUS], val, val_t0)

    def set_val(self, val):
        super().set_val(val)
        assert self.val&~(MSTATUS_START_VAL | MSTATUS_MASK) == 0 
        sstatus = self.csrfile.regs[CSR_IDS.SSTATUS].get_val()
        sstatus &= ~(SSTATUS_MASK & MAX_64b) # clear the bits
        sstatus |= (SSTATUS_MASK & self.val)
        self.csrfile.regs[CSR_IDS.SSTATUS].val = sstatus # dont use setter here

class Medeleg_CSR(CSR):
    def __init__(self, csrfile, val: int = 0, val_t0: int = 0):
        super().__init__(csrfile,CSR_IDS.MEDELEG,csrfile.csr_masks[CSR_IDS.MEDELEG],CSR_TYPES[CSR_IDS.MEDELEG], val, val_t0)
    

class CheckableRegister(__Register):
    def __init__(self, id: int, abi_name: str,is_design_64bit: bool, val: int = 0, val_t0: int = 0, pickable: bool = False):
        super().__init__(id, is_design_64bit, val, val_t0, pickable)
        self.abi_name = abi_name
    
    def check(self, cmp_val):
        cmp_val &= self.mask
        mismatch = self.val != cmp_val
            
        if not mismatch:
            return False
        else:
            return self.abi_name,self.val,cmp_val

    def check_t0(self, cmp_val, precise = CHECK_REGS_T0_PRECISE):
        cmp_val &= self.mask
        mismatch = self.val_t0 != cmp_val
        if not precise:
            cover = ~self.val_t0&cmp_val == 0 # overapproximates, check if spike taint is covered by milesan sim taint
            if cover:
                if mismatch and PRINT_CHECK_REGS_T0_MISMATCH_OK:
                    print(f"\tTaint mismatch OK: {hex(self.val_t0)} covers {hex(cmp_val)}.")
                return False

        if not mismatch:
            return False
        else:
            return self.abi_name,self.val_t0,cmp_val

    def print_and_compare(self,rtl_val,rtl_val_t0):
        if self.is_design_64bit:
            if rtl_val == self.val:
                val_str =  "0x{:016x}".format(self.val)
            else:
                val_str = "0x{:016x} != 0x{:016x}".format(self.val,rtl_val)

            if rtl_val_t0 == self.val_t0:
                val_t0_str = "0x{:016x}".format(self.val_t0)
            elif rtl_val_t0&~self.val_t0 == 0:
                val_t0_str = "0x{:016x} >= 0x{:016x}".format(self.val_t0,rtl_val_t0)
            else:
                val_t0_str = "0x{:016x} != 0x{:016x}".format(self.val_t0,rtl_val_t0)

        else:
            if rtl_val == self.val:
                val_str =  "0x{:08x}".format(self.val)
            else:
                val_str = "0x{:08x} != 0x{:08x}".format(self.val,rtl_val)

            if rtl_val_t0 == self.val_t0:
                val_t0_str = "0x{:08x}".format(self.val_t0)
            elif rtl_val_t0&~self.val_t0 == 0:
                val_t0_str = "0x{:08x} >= 0x{:08x}".format(self.val_t0,rtl_val_t0)
            else:
                val_t0_str = "0x{:08x} != 0x{:08x}".format(self.val_t0,rtl_val_t0)
            
        row = [self.abi_name,val_str,val_t0_str]
        print("{: >30} {: >30} {: >30}".format(*row))

    def print(self):
        row = [self.abi_name,hex(self.val),hex(self.val_t0), self.fsm_state.name, "True" if self.pickable else "False"]
        print("{: >20} {: >20} {: >20} {: >20} {: >20}".format(*row))

class IntRegister(CheckableRegister):
    def __init__(self, id: int, is_design_64bit: bool, val: int = 0, val_t0: int = 0, pickable: bool = False):
        super().__init__(id, ABI_INAMES[id], is_design_64bit, val, val_t0, pickable)
        self.fsm_state = IntRegIndivState.FREE

    def set_fsm_sate(self,new_state: IntRegIndivState = None):
        self.fsm_state = new_state

    def reset(self):
        super().reset()
        self.fsm_state = IntRegIndivState.FREE

   


