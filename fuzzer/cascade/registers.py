from cascade.util import IntRegIndivState
import ctypes
from abc import ABC

class __RegState(ABC): # Abstract base class cannot be instantiated.
    def __init__(self,id):
        self.id = id

    def print(self):
        pass


class __64RegState(__RegState):
    def __init__(self,id: int = None, val: ctypes.c_uint64 = ctypes.c_uint64(0), val_t0: ctypes.c_uint64 = ctypes.c_uint64(0)):
        self.id = id
        self.val = val
        self.val_t0 = val_t0


class __32RegState(__RegState):
    def __init__(self,id: int = None, val: ctypes.c_uint32 = ctypes.c_uint32(0), val_t0: ctypes.c_uint32 = ctypes.c_uint32(0)):
        self.id = id
        self.val = val
        self.val_t0 = val_t0

    def print(self):
        print(f"i{self.id}: {hex(self.val.value)}")

    def set_val(self, val: int):
        self.val = ctypes.c_uint32(val)

class Int32RegState(__32RegState):
    def __init__(self, id: int = None, val: ctypes.c_uint32 = ctypes.c_uint32(0), val_t0: ctypes.c_uint32 = ctypes.c_uint32(0)):
        super().__init__(id, val, val_t0)
        self.fsm_state = IntRegIndivState.FREE
    
    def set_fsm_sate(self,new_state: IntRegIndivState = None):
        self.fsm_state = new_state



