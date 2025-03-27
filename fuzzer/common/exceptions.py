import enum
from params.runparams import COLLECT_EXCEPTION_STATS
import json
import os
from milesan.csrfile import CSR_IDS
from milesan.registers import ABI_INAMES
class FailTypeEnum(enum.IntEnum):
    SPIKE_TIMEOUT = enum.auto()
    RTL_TIMEOUT = enum.auto()
    VALUE_MISMATCH = enum.auto()
    TAINT_MISMATCH = enum.auto()
    NO_FAILURE = enum.auto()

class FuzzerStateException(Exception):
    def __init__(self, *args: object, fuzzerstate, fail_type: FailTypeEnum, timestamp) -> None:
        super().__init__(*args)
        self.fuzzerstate = fuzzerstate
        self.fail_type = fail_type
        self.timestamp = timestamp
        if COLLECT_EXCEPTION_STATS:
            with open(os.path.join(fuzzerstate.tmp_dir, "exception.json"), "w") as f:
                json.dump({
                    "id": fuzzerstate.instance_to_str(),
                    "dut": fuzzerstate.design_name,
                    "t_total":timestamp,
                    "fail_type": self.fail_type.name,
                    "seed":fuzzerstate.randseed
                }, f)

class MismatchError(ValueError):
    def __init__(self, *args: object, fail_type: FailTypeEnum) -> None:
        super().__init__(*args)
        self.fail_type = fail_type



class TaintedRegisterException(Exception):
    def __init__(self,fuzzerstate, reg_id:int, instr) -> None:
        super().__init__(f"{instr.get_str()} has tainted register {ABI_INAMES[reg_id]}")
        self.fuzzerstate = fuzzerstate
        self.reg_id = reg_id # The register that got tainted
        self.instr = instr # The instruction that triggered the exception

class TaintedDDELIException(TaintedRegisterException):
    def __init__(self, fuzzerstate, reg_id: int, instr) -> None:
        super().__init__(fuzzerstate, reg_id, instr)

class TaintedMemAddrException(TaintedRegisterException):
    def __init__(self, fuzzerstate, reg_id: int, instr) -> None:
        super().__init__(fuzzerstate, reg_id, instr)

class TaintedMemLoadException(TaintedMemAddrException):
    def __init__(self, fuzzerstate, reg_id: int, instr) -> None:
        super().__init__(fuzzerstate, reg_id, instr)

class TaintedMemStoreException(TaintedMemAddrException):
    def __init__(self, fuzzerstate, reg_id: int, instr) -> None:
        super().__init__(fuzzerstate, reg_id, instr)

class TaintedCFOperandException(TaintedRegisterException):
    def __init__(self, fuzzerstate, reg_id: int, instr) -> None:
        super().__init__(fuzzerstate, reg_id, instr)

class TaintedBranchException(TaintedCFOperandException):
    def __init__(self, fuzzerstate, reg_id: int, instr) -> None:
        super().__init__(fuzzerstate, reg_id, instr)
        
class TaintedJalrException(TaintedCFOperandException):
    def __init__(self, fuzzerstate, reg_id: int, instr) -> None:
        super().__init__(fuzzerstate, reg_id, instr)

class TaintedCSRException(Exception):
    def __init__(self, csr_id, csr_abi_name) -> None:
        super().__init__(f"CSR {csr_abi_name} is tainted.")
        self.csr_id = csr_id
        self.csr_abi_name = csr_abi_name

class MemException(Exception):
    def __init__(self, fuzzerstate, addr: int, n_bytes: int, e: AssertionError) -> None:
        super().__init__(f"Invalid memory request at {hex(addr)} for {n_bytes} bytes: {e}")
        self.fuzzerstate = fuzzerstate
        self.addr = addr
        self.n_bytes = n_bytes
        self.e = e

class MemReadException(MemException):
    def __init__(self, fuzzerstate, addr: int, n_bytes: int, e: AssertionError) -> None:
        super().__init__(fuzzerstate=fuzzerstate, addr=addr, n_bytes=n_bytes, e=e)

class MemWriteException(MemException):
    def __init__(self, fuzzerstate, addr: int, n_bytes: int, e: AssertionError) -> None:
        super().__init__(fuzzerstate=fuzzerstate, addr=addr, n_bytes=n_bytes,e=e)

class InvalidProgramException(Exception):
    def __init__(self, fuzzerstate, msg) -> None:
        super().__init__(f"Invalid program: {msg}")
        self.fuzzerstate = fuzzerstate
        self.msg = msg
