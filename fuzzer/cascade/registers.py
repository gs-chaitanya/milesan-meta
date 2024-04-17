from abc import ABC

from cascade.util import IntRegIndivState
from rv.csrids import CSR_IDS
from rv.asmutil import twos_complement,to_unsigned
from params.runparams import PRINT_CHECK_REGS_T0, CHECK_REGS_T0_PRECISE, PRINT_CHECK_REGS_T0_MISMATCH_OK

ABI_INAMES = ["zero","ra","sp","gp","tp","t0","t1","t2","s0/fp","s1","a0","a1","a2","a3","a4","a5","a6","a7"]
ABI_INAMES += [f"s{i}" for i in range(2,12)] + [f"t{i}" for i in range(3,7)]
MAX_32b = 0xFFFFFFFF
MAX_64b = 0xFFFFFFFFFFFFFFFF
MAX_20b = 0xFFFFF

class __RegState(ABC): # Abstract base class cannot be instantiated.
    def __init__(self,id):
        self.id = id

    def print(self):
        pass

class __64RegState(__RegState):
    def __init__(self,id: int = None, val: int = 0, val_t0: int = 0):
        self.id = id
        self.val = val
        self.val_t0 = val_t0
        self.n_bits = 64

class CSR64(__64RegState):
    def __init__(self, id: CSR_IDS = None, val: int = 0, val_t0: int = 0):
        super().__init__(id, val, val_t0)
        self.abi_name = id.name
        assert self.val_t0 == 0

    def set_val(self, val):
        self.val = val&MAX_64b

    def set_val_t0(self, val_t0):
        assert val_t0 == 0

    def get_val(self):
        return self.val

    def get_val_t0(self):
        assert self.val_t0 == 0
        return self.val_t0

    def reset(self):
        self.val = 0
        self.val_t0 = 0


class __32RegState(__RegState):
    def __init__(self,id: int = None, val: int = 0, val_t0: int = 0, pickable: bool = False):
        self.id = id
        self.val = val&MAX_32b
        self.val_t0 = val_t0&MAX_32b
        self.n_bits = 32
        self.pickable = pickable

    def set_val(self, val):
        if(self.id != 0):
            self.val = val&MAX_32b

    def set_val_t0(self, val_t0):
        if(self.id != 0):
            self.val_t0 = val_t0&MAX_32b

    def get_val(self):
        return self.val

    def get_val_t0(self):
        return self.val_t0

    def reset(self):
        self.val = 0
        self.val_t0 = 0

class CSR32(__32RegState):
    def __init__(self, id: CSR_IDS = None, val: int = 0, val_t0: int = 0):
        super().__init__(id, val, val_t0)
        self.abi_name = id.name

    def set_val(self, val):
        self.val = val&MAX_32b

    def set_val_t0(self, val_t0):
        self.val_t0 = val_t0&MAX_32b

    def get_val(self):
        return self.val

    def get_val_t0(self):
        return self.val_t0

    def reset(self):
        self.val = 0
        self.val_t0 = 0



class Int32RegState(__32RegState):
    def __init__(self, id: int = None, val: int = 0, val_t0: int = 0, pickable: bool = False):
        super().__init__(id, val, val_t0, pickable)
        self.fsm_state = IntRegIndivState.FREE
        self.abi_name = ABI_INAMES[self.id]

    def set_fsm_sate(self,new_state: IntRegIndivState = None):
        self.fsm_state = new_state
    
    def check(self, cmp_val):
        cmp_val_uint32 = cmp_val&MAX_32b
        mismatch = self.val != cmp_val_uint32

        if not mismatch:
            return False
        else:
            return ABI_INAMES[self.id],self.val,cmp_val_uint32

    def check_t0(self, cmp_val, precise = CHECK_REGS_T0_PRECISE):
        cmp_val_uint32 = cmp_val&MAX_32b
        mismatch = self.val_t0 != cmp_val_uint32
        if not precise:
            cover = ~self.val_t0&cmp_val_uint32 == 0 # overapproximates, check if spike taint is covered by cascade sim taint
            if cover:
                if mismatch and PRINT_CHECK_REGS_T0_MISMATCH_OK:
                    print(f"\tTaint mismatch OK: {hex(self.val_t0)} covers {hex(cmp_val_uint32)}.")
                return False

        if not mismatch:
            return False
        else:
            return ABI_INAMES[self.id],self.val_t0,cmp_val_uint32

    def reset(self):
        super().reset()
        self.fsm_state = IntRegIndivState.FREE

    def print(self):
        row = [ABI_INAMES[self.id],hex(self.val),hex(self.val_t0), self.fsm_state.name, "True" if self.pickable else "False"]
        print("{: >20} {: >20} {: >20} {: >20} {: >20}".format(*row))

    def print_and_compare(self,rtl_val,rtl_val_t0):
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
        
        row = [ABI_INAMES[self.id],val_str,val_t0_str]
        print("{: >30} {: >30} {: >30}".format(*row))



