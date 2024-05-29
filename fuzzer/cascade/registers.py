from abc import ABC

from cascade.util import IntRegIndivState
import enum
from rv.csrids import CSR_IDS, CSRTypeEnum
from params.runparams import PRINT_CHECK_REGS_T0, CHECK_REGS_T0_PRECISE, PRINT_CHECK_REGS_T0_MISMATCH_OK, DO_ASSERT
from params.fuzzparams import ALLOW_CSR_TAINT
ABI_INAMES = ["zero","ra","sp","gp","tp","t0","t1","t2","s0/fp","s1","a0","a1","a2","a3","a4","a5","a6","a7"]
ABI_INAMES += [f"s{i}" for i in range(2,12)] + [f"t{i}" for i in range(3,7)]
MAX_32b = 0xFFFFFFFF
MAX_64b = 0xFFFFFFFFFFFFFFFF
MAX_20b = 0xFFFFF

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

def _get_writeable_csr_value(value: int, csr_mask: int, csr_type: CSRTypeEnum):
    if csr_type == CSRTypeEnum.WLRL:
        return value # mask is ignored, any value can be written or read
    elif csr_type == CSRTypeEnum.WARL:
        return value&csr_mask # we only write the bits that can be written legally
    elif csr_type == CSRTypeEnum.WPRI:
        raise NotImplementedError("WPRI not implemented yet.")
    else:
        raise TypeError

class CSR(__Register):
    def __init__(self, id: CSR_IDS, csr_mask, csr_type: CSRTypeEnum, val: int = 0, val_t0: int = 0):
        super().__init__(id, True, val, val_t0) # CSRs are always 64bit
        if DO_ASSERT:
            assert csr_type == CSRTypeEnum.WLRL or id == CSR_IDS.MEDELEG and csr_type == CSRTypeEnum.WARL, f"Only medeleg supported for other type than WLRL."
            assert csr_mask is not None, f"Got None as csr mask for {id.name}. Check if medeleg was profiled."
        self.abi_name = id.name
        self.val = val
        self.val_t0 = val_t0
        self.csr_mask = csr_mask
        self.csr_type = csr_type

    def set_val(self, val):
        self.val = self.mask&_get_writeable_csr_value(val,self.csr_mask,self.csr_type)

    def set_val_t0(self, val_t0):
        if not ALLOW_CSR_TAINT:
            assert val_t0 == 0, "Taint propagation through CSRs is disabled!"
        self.val_t0 = val_t0&self.mask

    def get_val(self):
        return self.val

    def get_val_t0(self):
        if not ALLOW_CSR_TAINT:
            assert self.val_t0 == 0, "Taint propagation through CSRs is disabled!"
        return self.val_t0

    def reset(self):
        self.val = 0
        self.val_t0 = 0






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
            cover = ~self.val_t0&cmp_val == 0 # overapproximates, check if spike taint is covered by cascade sim taint
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

   


