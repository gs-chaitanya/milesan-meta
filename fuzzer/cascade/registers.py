from cascade.util import IntRegIndivState
from rv.asmutil import twos_complement,to_unsigned
# import ctypes
from abc import ABC
ABI_INAMES = ["zero","ra","sp","gp","tp","t0","t1","t2","s0/fp","s1","a0","a1","a2","a3","a4","a5","a6","a7"]
ABI_INAMES += [f"s{i}" for i in range(2,12)] + [f"t{i}" for i in range(3,7)]
ABI_CSRNAMES = []
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
        self.val_bk = val_t0
        self.val_t0 = val_t0
        self.n_bits = 64


class __32RegState(__RegState):
    def __init__(self,id: int = None, val: int = 0, val_t0: int = 0):
        self.id = id
        self.val = val&MAX_32b
        self.val_bk = val&MAX_32b
        self.val_t0 = val_t0&MAX_32b
        self.val_t0_bk = val_t0&MAX_32b
        self.n_bits = 32

    def print(self):
        row = [ABI_INAMES[self.id],hex(self.val),hex(self.val_t0), self.fsm_state.name]
        print("{: >20} {: >20} {: >20} {: >20}".format(*row))

    def set_val(self, val):
        if(self.id != 0):
            self.val_bk = self.val
            self.val = val&MAX_32b

    def set_val_t0(self, val_t0):
        if(self.id != 0):
            self.val_t0_bk = self.val_t0
            self.val_t0 = val_t0&MAX_32b

    def get_val(self):
        return self.val

    def get_val_bk(self):
        return self.val_bk

    def get_val_t0(self):
        return self.val_t0

    def get_val_t0_bk(self):
        return self.val_t0_bk


class Int32RegState(__32RegState):
    def __init__(self, id: int = None, val: int = 0, val_t0: int = 0):
        super().__init__(id, val, val_t0)
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

    def check_t0(self, cmp_val, precise = False):
        cmp_val_uint32 = cmp_val&MAX_32b
        mismatch = self.val_t0 != cmp_val_uint32
        if not precise:
            cover = ~self.val_t0&cmp_val_uint32 == 0 # overapproximates, check if spike taint is covered by cascade sim taint
            if cover:
                if mismatch:
                    print(f"\tTaint mismatch OK: {hex(self.val_t0)} covers spike {hex(cmp_val_uint32)}.")
                return False

        if not mismatch:
            return False
        else:
            return ABI_INAMES[self.id],self.val_t0,cmp_val_uint32


