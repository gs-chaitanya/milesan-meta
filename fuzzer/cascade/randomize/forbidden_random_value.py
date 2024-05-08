from rv.rv32i import RV32I_OPCODE_JAL, RV32I_OPCODE_JALR, RV32I_C_OPCODE_JAL, RV32I_C_OPCODE_JALR, RV32I_C_OPCODE_J, RV32I_OPCODE_MASK, RV32I_C_OPCODE_MASK

def is_forbidden_random_value(value, n_bytes):
    for offset in range(n_bytes):
        ivalue = (value&(0xFFFFFFFF<<(offset*8)))>>(offset*8)
        if not (ivalue^RV32I_OPCODE_JAL)&RV32I_OPCODE_MASK: # they match on the masked bits
            return True
        elif not (ivalue^RV32I_OPCODE_JALR)&RV32I_OPCODE_MASK:
            return True
        for i in range(2): # need to check upper and lower 16 bits for compressed instructions
            cvalue = (ivalue&(0xFFFF<<i*16))>>i*16
            if not (cvalue^RV32I_C_OPCODE_JAL)&RV32I_C_OPCODE_MASK:
                return True
            if not (cvalue^RV32I_C_OPCODE_JALR)&RV32I_C_OPCODE_MASK:
                return True
            if not (cvalue^RV32I_C_OPCODE_J)&RV32I_C_OPCODE_MASK:
                return True
        return False