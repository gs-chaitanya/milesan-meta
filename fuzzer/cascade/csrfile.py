from cascade.registers import CSR, MStatus_CSR, SStatus_CSR, Medeleg_CSR, MAX_64b
from rv.csrids import CSR_IDS, CSR_TYPES, CSRTypeEnum, MSCAUSE_MASK
class CSRFile():
    fuzzerstate = None
    regs = None
    csr_masks = None
    def __init__(self, fuzzerstate):
        from common.profiledesign import PROFILED_MEDELEG_MASK
        if PROFILED_MEDELEG_MASK is None:
            return # When we generate the fuzzerstate to profile the medeleg, we just return
        self.fuzzerstate = fuzzerstate
        self.csr_masks = {i:MAX_64b for i in CSR_IDS}
        self.csr_masks[CSR_IDS.MEDELEG] =  PROFILED_MEDELEG_MASK # WARL
        self.csr_masks[CSR_IDS.MCAUSE] =  MSCAUSE_MASK # WLRL
        self.csr_masks[CSR_IDS.SCAUSE] =  MSCAUSE_MASK # WLRL
        self.regs = {id:CSR(self,id,self.csr_masks[id], CSR_TYPES[id]) for id in CSR_IDS}
        self.regs[CSR_IDS.MSTATUS] = MStatus_CSR(self)
        self.regs[CSR_IDS.SSTATUS] = SStatus_CSR(self)
        self.regs[CSR_IDS.MSTATUS].set_val(0xa00000000)
        self.regs[CSR_IDS.SSTATUS].set_val(0x200000000)
        self.regs[CSR_IDS.MEDELEG] = Medeleg_CSR(self)


    def reset(self):
        for _, reg in self.regs.items():
            reg.reset()
        self.regs[CSR_IDS.MSTATUS].set_val(0xa00000000)
        self.regs[CSR_IDS.SSTATUS].set_val(0x200000000)



