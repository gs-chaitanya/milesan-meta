from cascade.registers import CSR32
from rv.csrids import CSR_IDS
class CSRFile():
    fuzzerstate = None
    regs = None
    def __init__(self):
        self.regs = {id:CSR32(id) for id in CSR_IDS}

    def reset(self):
        for _, reg in self.regs.items():
            reg.reset()

