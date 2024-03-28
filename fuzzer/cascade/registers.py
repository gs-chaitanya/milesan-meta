from cascade.util import IntRegIndivState
import ctypes
from abc import ABC
ABI_INAMES = ["zero","ra","sp","gp","tp","t0","t1","t2","s0/fp","s1","a0","a1","a2","a3","a4","a5","a6","a7"]
ABI_INAMES += [f"s{i}" for i in range(2,12)] + [f"t{i}" for i in range(3,7)]
MAX_32b = 0xFFFFFFFF
MAX_64b = 0xFFFFFFFFFFFFFFFF

class __RegState(ABC): # Abstract base class cannot be instantiated.
    def __init__(self,id):
        self.id = id

    def print(self):
        pass


class __64RegState(__RegState):
    def __init__(self,id: int = None, val: ctypes.c_uint64 = ctypes.c_uint64(0), val_t0: ctypes.c_uint64 = ctypes.c_uint64(0)):
        self.id = id
        self.val = val
        self.val_bk = val_t0
        self.val_t0 = val_t0


class __32RegState(__RegState):
    def __init__(self,id: int = None, val: ctypes.c_uint32 = ctypes.c_uint32(0), val_t0: ctypes.c_uint32 = ctypes.c_uint32(0)):
        self.id = id
        self.val = val
        self.val_bk = val
        self.val_t0 = val_t0
        self.val_t0_bk = val_t0

    def print(self):
        print(f"{ABI_INAMES[self.id]}: {hex(self.val.value)}")

    def set_val(self, val):
        if(self.id != 0):
            self.val_bk = self.val
            self.val = ctypes.c_uint32(val)

    def set_val_t0(self, val_t0):
        if(self.id != 0):
            self.val_t0_bk = self.val_t0
            self.val_t0 = ctypes.c_uint32(val_t0)


    def get_val(self):
        return self.val.value

    def get_val_bk(self):
        return self.val_bk.value

    def get_val_t0(self):
        return self.val.value

    def get_val_t0_bk(self):
        return self.val_t0_bk.value


class Int32RegState(__32RegState):
    def __init__(self, id: int = None, val: ctypes.c_uint32 = ctypes.c_uint32(0), val_t0: ctypes.c_uint32 = ctypes.c_uint32(0)):
        super().__init__(id, val, val_t0)
        self.fsm_state = IntRegIndivState.FREE
        self.abi_name = ABI_INAMES[self.id]

    
    def set_fsm_sate(self,new_state: IntRegIndivState = None):
        self.fsm_state = new_state
    
    def check(self, cmp_val, pc):
        cmp_val_uint32 = ctypes.c_uint32(cmp_val)
        mismatch = self.val.value != cmp_val_uint32.value # check the value that 

        # print(f"{hex(pc)}: Value {'mismatch' if  mismatch else 'match'} for {self.abi_name}: {hex(self.val.value)}" + f" != {hex(cmp_val_uint32.value)}" if mismatch else "")
        # assert not mismatch, f"{hex(pc)}: Value mismatch for {self.abi_name}: {hex(self.val.value)} != {hex(cmp_val_uint32.value)}"
        if not mismatch:
            return False
        else:
            return pc,ABI_INAMES[self.id],self.val.value,cmp_val_uint32.value

    def check_t0(self, cmp_val, pc):
        cmp_val_uint32 = ctypes.c_uint32(cmp_val)
        mismatch = self.val_t0.value != cmp_val_uint32.value # check the value that 

        # print(f"{hex(pc)}: Value {'mismatch' if  mismatch else 'match'} for {self.abi_name}: {hex(self.val.value)}" + f" != {hex(cmp_val_uint32.value)}" if mismatch else "")
        # assert not mismatch, f"{hex(pc)}: Value mismatch for {self.abi_name}: {hex(self.val.value)} != {hex(cmp_val_uint32.value)}"
        if not mismatch:
            return False
        else:
            return pc,ABI_INAMES[self.id],self.val_t0.value,cmp_val_uint32.value


