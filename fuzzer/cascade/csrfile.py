from cascade.registers import CSR, MAX_64b
from common.spike import SPIKE_MEDELEG_MASK
from rv.csrids import CSR_IDS, CSR_TYPES, CSRTypeEnum
class CSRFile():
    fuzzerstate = None
    regs = None
    csr_masks = None
    def __init__(self, fuzzerstate):
        from common.profiledesign import PROFILED_MEDELEG_MASK
        if PROFILED_MEDELEG_MASK is None:
            return # When we generate the fuzzerstate to profile the medeleg, we just return
        self.fuzzerstate = fuzzerstate
        self.csr_masks = {i:MAX_64b for i in CSR_IDS if CSR_TYPES[i] == CSRTypeEnum.WLRL}
        self.csr_masks[CSR_IDS.MEDELEG] =  PROFILED_MEDELEG_MASK & SPIKE_MEDELEG_MASK
        self.regs = {id:CSR(id,self.csr_masks[id], CSR_TYPES[id]) for id in CSR_IDS}

    def reset(self):
        for _, reg in self.regs.items():
            reg.reset()


