import rv.rvprotoinstrs as rvprotoinstrs

#opcode: inst[15:13] inst[1:0]
RV64IC_OPCODE_MISC_ALU =    (0b100, 0b01) #same as rv32
RV64IC_OPCODE_ADDIW =       (0b001, 0b01)
RV64IC_OPCODE_LDSP =        (0b011, 0b10)
RV64IC_OPCODE_LD =          (0b011, 0b00)
RV64IC_OPCODE_SDSP =        (0b111, 0b10)
RV64IC_OPCODE_SD =          (0b111, 0b00)

def rv64ic_addw(rd : int, rs2 : int):
    rdprime = rd - 8
    rs2prime = rs2 - 8
    funct6 = (RV64IC_OPCODE_MISC_ALU[0] << 3) | 0b111
    return rvprotoinstrs.instruc_catype(RV64IC_OPCODE_MISC_ALU[1], rs2prime, 0b01, rdprime, funct6)
def rv64ic_subw(rd : int, rs2 : int):
    rdprime = rd - 8
    rs2prime = rs2 - 8
    funct6 = (RV64IC_OPCODE_MISC_ALU[0] << 3) | 0b111
    return rvprotoinstrs.instruc_catype(RV64IC_OPCODE_MISC_ALU[1], rs2prime, 0b00, rdprime, funct6)
def rv64ic_addiw(rd : int, imm : int):
    return rvprotoinstrs.instruc_citype(RV64IC_OPCODE_ADDIW[1], rd, RV64IC_OPCODE_ADDIW[0], imm)
def rv64ic_ldsp(rd : int, imm : int):
    bit_5 = (imm >> 5) & 0b1
    bit_4_to_3 = (imm >> 3) & 0b11
    bit_8_to_6 = (imm >> 6) & 0b111
    imm = (bit_5 << 5) | (bit_4_to_3 << 3) | bit_8_to_6
    return rvprotoinstrs.instruc_citype(RV64IC_OPCODE_LDSP[1], rd, RV64IC_OPCODE_LDSP[0], imm)
def rv64ic_ld(rd : int, rs1 : int, imm : int):
    rdprime = rd - 8
    rs1prime = rs1 - 8
    bit_5_to_3 = (imm >> 3) & 0b111
    bit_7_to_6 = (imm >> 6) & 0b11
    imm = (bit_5_to_3 << 2) | bit_7_to_6
    return rvprotoinstrs.instruc_cltype(RV64IC_OPCODE_LD[1], rdprime, rs1prime, RV64IC_OPCODE_LD[0], imm)
def rv64ic_sdsp(rs2 : int, imm : int):
    bit_5_to_3 = (imm >> 2) & 0b111
    bit_8_to_6 = (imm >> 6) & 0b111
    imm = (bit_5_to_3 << 3) | bit_8_to_6
    return rvprotoinstrs.instruc_csstype(RV64IC_OPCODE_SDSP[1], rs2, RV64IC_OPCODE_SDSP[0], imm)
def rv64ic_sd(rs1 : int, rs2 : int, imm : int):
    rs1prime = rs1 - 8
    rs2prime = rs2 - 8
    bit_5_to_3 = (imm >> 3) & 0b111
    bit_7_to_6 = (imm >> 6) & 0b11
    imm = (bit_5_to_3 << 2) | bit_7_to_6
    return rvprotoinstrs.instruc_cstype(RV64IC_OPCODE_SD[1], rs1prime, rs2prime, RV64IC_OPCODE_SD[0], imm)

