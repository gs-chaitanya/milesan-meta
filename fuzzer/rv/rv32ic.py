import rv.rvprotoinstrs as rvprotoinstrs

#opcode: inst[15:13] inst[1:0]
RV32IC_OPCODE_MV_ADD =          (0b100, 0b10)
RV32IC_OPCODE_MISC_ALU =        (0b100, 0b01)
RV32IC_OPCODE_LUI_ADDI16SP =    (0b011, 0b01)
RV32IC_OPCODE_ADDI4SPN =        (0b000, 0b00)
RV32IC_OPCODE_ADDI =            (0b000, 0b01)
RV32IC_OPCODE_LI =              (0b010, 0b01)
RV32IC_OPCODE_SLLI =            (0b000, 0b10)
RV32IC_OPCODE_BEQZ =            (0b110, 0b01)
RV32IC_OPCODE_BNEZ =            (0b111, 0b01)
RV32IC_OPCODE_J =               (0b101, 0b01)
RV32IC_OPCODE_JAL =             (0b001, 0b01)
RV32IC_OPCODE_JALR_JR =         (0b100, 0b10)
RV32IC_OPCODE_LWSP =            (0b010, 0b10)
RV32IC_OPCODE_LW =              (0b010, 0b00)
RV32IC_OPCODE_SWSP =            (0b110, 0b10)
RV32IC_OPCODE_SW =              (0b110, 0b00)

#refactor so that funct3, is part of a tuple defined above
def rv32ic_mv(rd : int, rs2 : int):
    funct4 = (RV32IC_OPCODE_MV_ADD[0] << 1) | 0b0
    return rvprotoinstrs.instruc_crtype(RV32IC_OPCODE_MV_ADD[1], rs2, rd, funct4)
def rv32ic_add(rd : int, rs2 : int):
    funct4 = (RV32IC_OPCODE_MV_ADD[0] << 1) | 0b1
    return rvprotoinstrs.instruc_crtype(RV32IC_OPCODE_MV_ADD[1], rs2, rd, funct4)
def rv32ic_and(rd : int, rs2 : int):
    rdprime = rd - 8
    rs2prime = rs2 - 8
    funct6 = (RV32IC_OPCODE_MISC_ALU[0] << 3) | 0b011
    return rvprotoinstrs.instruc_catype(RV32IC_OPCODE_MISC_ALU[1], rs2prime, 0b11, rdprime, funct6)
def rv32ic_or(rd : int, rs2 : int):
    rdprime = rd - 8
    rs2prime = rs2 - 8
    funct6 = (RV32IC_OPCODE_MISC_ALU[0] << 3) | 0b011
    return rvprotoinstrs.instruc_catype(RV32IC_OPCODE_MISC_ALU[1], rs2prime, 0b10, rdprime, funct6)
def rv32ic_xor(rd : int, rs2 : int):
    rdprime = rd - 8
    rs2prime = rs2 - 8
    funct6 = (RV32IC_OPCODE_MISC_ALU[0] << 3) | 0b011
    return rvprotoinstrs.instruc_catype(RV32IC_OPCODE_MISC_ALU[1], rs2prime, 0b01, rdprime, funct6)
def rv32ic_sub(rd : int, rs2 : int):
    rdprime = rd - 8
    rs2prime = rs2 - 8
    funct6 = (RV32IC_OPCODE_MISC_ALU[0] << 3) | 0b011
    return rvprotoinstrs.instruc_catype(RV32IC_OPCODE_MISC_ALU[1], rs2prime, 0b00, rdprime, funct6)
def rv32ic_lui(rd: int, imm: int):
    return rvprotoinstrs.instruc_citype(RV32IC_OPCODE_LUI_ADDI16SP[1], rd, RV32IC_OPCODE_LUI_ADDI16SP[0], imm)
def rv32ic_addi16sp(rd : int, imm : int):
    bit_9 = (imm >> 9) & 0b1
    bit_4 = (imm >> 4) & 0b1
    bit_6 = (imm >> 6) & 0b1
    bits_8_to_7 = (imm >> 7) & 0b11
    bit_5 = (imm >> 5) & 0b1
    imm_o = (bit_9 << 5) | (bit_4 << 4) | (bit_6 << 3) | (bits_8_to_7 << 1) | bit_5
    return rvprotoinstrs.instruc_citype(RV32IC_OPCODE_LUI_ADDI16SP[1], rd, RV32IC_OPCODE_LUI_ADDI16SP[0], imm_o)
def rv32ic_addi4spn(rd : int, imm : int):
    rdprime = rd - 8
    bits_5_to_4 = (imm >> 4) & 0b11 
    bits_9_to_6 = (imm >> 6) & 0b1111 
    bit_2 = (imm >> 2) & 0b1 
    bit_3 = (imm >> 3) & 0b1 
    imm = (bits_5_to_4 << 6) | (bits_9_to_6 << 2) | (bit_2 << 1) | bit_3
    return rvprotoinstrs.instruc_ciwtype(RV32IC_OPCODE_ADDI4SPN[1], rdprime, RV32IC_OPCODE_ADDI4SPN[0], imm)
def rv32ic_addi(rd : int, imm : int):
    return rvprotoinstrs.instruc_citype(RV32IC_OPCODE_ADDI[1], rd, RV32IC_OPCODE_ADDI[0], imm)
def rv32ic_li(rd : int, imm : int):
    return rvprotoinstrs.instruc_citype(RV32IC_OPCODE_LI[1], rd, RV32IC_OPCODE_LI[0], imm)
def rv32ic_slli(rd : int, imm : int):
    return rvprotoinstrs.instruc_citype(RV32IC_OPCODE_SLLI[1], rd, RV32IC_OPCODE_SLLI[0], imm)
def rv32ic_andi(rs1 : int, imm : int):
    rs1prime = rs1 - 8
    bit_5 = (imm >> 5) & 0b1
    imm = (bit_5 << 7) | (0b10 << 5) | (imm & 0b11111) 
    return rvprotoinstrs.instruc_cbtype(RV32IC_OPCODE_MISC_ALU[1], rs1prime, RV32IC_OPCODE_MISC_ALU[0], imm)
def rv32ic_srli(rs1 : int, imm : int):
    rs1prime = rs1 - 8
    bit_5 = (imm >> 5) & 0b1
    imm = (bit_5 << 7) | (0b00 << 5) | (imm & 0b11111) 
    return rvprotoinstrs.instruc_cbtype(RV32IC_OPCODE_MISC_ALU[1], rs1prime, RV32IC_OPCODE_MISC_ALU[0], imm)
def rv32ic_srai(rs1 : int, imm : int):
    rs1prime = rs1 - 8
    bit_5 = (imm >> 5) & 0b1
    imm = (bit_5 << 7) | (0b01 << 5) | (imm & 0b11111) 
    return rvprotoinstrs.instruc_cbtype(RV32IC_OPCODE_MISC_ALU[1], rs1prime, RV32IC_OPCODE_MISC_ALU[0], imm)
def rv32ic_beqz(rs1 : int, imm : int):
    rs1prime = rs1 - 8
    bit_8 = (imm >> 8) & 0b1
    bit_4_to_3 = (imm >> 3) & 0b11
    bit_7_to_6 = (imm >> 6) & 0b11
    bit_2_to_1 = (imm >> 1) & 0b11
    bit_5 = (imm >> 5) & 0b1
    imm = (bit_8 << 7) | (bit_4_to_3 << 5) | (bit_7_to_6 << 3) | (bit_2_to_1 << 1) | bit_5
    return rvprotoinstrs.instruc_cbtype(RV32IC_OPCODE_BEQZ[1], rs1prime, RV32IC_OPCODE_BEQZ[0], imm)
def rv32ic_bnez(rs1 : int, imm : int):
    rs1prime = rs1 - 8
    bit_8 = (imm >> 8) & 0b1
    bit_4_to_3 = (imm >> 3) & 0b11
    bit_7_to_6 = (imm >> 6) & 0b11
    bit_2_to_1 = (imm >> 1) & 0b11
    bit_5 = (imm >> 5) & 0b1
    imm = (bit_8 << 7) | (bit_4_to_3 << 5) | (bit_7_to_6 << 3) | (bit_2_to_1 << 1) | bit_5
    return rvprotoinstrs.instruc_cbtype(RV32IC_OPCODE_BNEZ[1], rs1prime, RV32IC_OPCODE_BNEZ[0], imm)
def rv32ic_jal(imm : int):
    bit_11 = (imm >> 11) & 0b1
    bit_4 = (imm >> 4) & 0b1
    bit_9_to_8 = (imm >> 8) & 0b11
    bit_10 = (imm >> 10) & 0b1
    bit_6 = (imm >> 6) & 0b1
    bit_7 = (imm >> 7) & 0b1
    bit_3_to_1 = (imm >> 1) & 0b111
    bit_5 = (imm >> 5) & 0b1
    imm = (bit_11 << 10) | (bit_4 << 9) | (bit_9_to_8 << 7) | (bit_10 << 6) | (bit_6 << 5) | (bit_7 << 4) | (bit_3_to_1 << 1) | bit_5
    return rvprotoinstrs.instruc_cjtype(RV32IC_OPCODE_JAL[1], RV32IC_OPCODE_JAL[0], imm)
def rv32ic_j(imm : int):
    bit_11 = (imm >> 11) & 0b1
    bit_4 = (imm >> 4) & 0b1
    bit_9_to_8 = (imm >> 8) & 0b11
    bit_10 = (imm >> 10) & 0b1
    bit_6 = (imm >> 6) & 0b1
    bit_7 = (imm >> 7) & 0b1
    bit_3_to_1 = (imm >> 1) & 0b111
    bit_5 = (imm >> 5) & 0b1
    imm = (bit_11 << 10) | (bit_4 << 9) | (bit_9_to_8 << 7) | (bit_10 << 6) | (bit_6 << 5) | (bit_7 << 4) | (bit_3_to_1 << 1) | bit_5
    return rvprotoinstrs.instruc_cjtype(RV32IC_OPCODE_J[1], RV32IC_OPCODE_J[0], imm)
def rv32ic_jr(rs1 : int):
    funct4 = (RV32IC_OPCODE_JALR_JR[0] << 1) | 0b0
    return rvprotoinstrs.instruc_crtype(RV32IC_OPCODE_JALR_JR[1], 0b0, rs1, funct4)
def rv32ic_jalr(rs1 : int):
    funct4 = (RV32IC_OPCODE_JALR_JR[0] << 1) | 0b1
    return rvprotoinstrs.instruc_crtype(RV32IC_OPCODE_JALR_JR[1], 0b0, rs1, funct4)
def rv32ic_ebreak():
    funct4 = (RV32IC_OPCODE_MISC_ALU[0] << 1) | 0b1
    return rvprotoinstrs.instruc_crtype(RV32IC_OPCODE_MISC_ALU[1], 0b0, 0b0, funct4)
def rv32ic_lwsp(rd : int, imm : int):
    bit_5 = (imm >> 5) & 0b1
    bit_4_to_2 = (imm >> 2) & 0b111
    bit_7_to_6 = (imm >> 6) & 0b11
    imm = (bit_5 << 5) | (bit_4_to_2 << 2) | bit_7_to_6
    return rvprotoinstrs.instruc_citype(RV32IC_OPCODE_LWSP[1], rd, RV32IC_OPCODE_LWSP[0], imm)
def rv32ic_lw(rd : int, rs1 : int, imm : int):
    rdprime = rd - 8
    rs1prime = rs1 - 8
    bit_5_to_3 = (imm >> 3) & 0b111
    bit_2 = (imm >> 2) & 0b1
    bit_6 = (imm >> 6) & 0b1
    imm = (bit_5_to_3 << 2) | (bit_2 << 1) | bit_6
    return rvprotoinstrs.instruc_cltype(RV32IC_OPCODE_LW[1], rdprime, rs1prime, RV32IC_OPCODE_LW[0], imm)
def rv32ic_swsp(rs2 : int, imm : int):
    bit_5_to_2 = (imm >> 2) & 0b1111
    bit_7_to_6 = (imm >> 6) & 0b11
    imm = (bit_5_to_2 << 2) | bit_7_to_6
    return rvprotoinstrs.instruc_csstype(RV32IC_OPCODE_SWSP[1], rs2, RV32IC_OPCODE_SWSP[0], imm)
def rv32ic_sw(rs1 : int, rs2 : int, imm : int):
    rs1prime = rs1 - 8
    rs2prime = rs2 - 8
    bit_5_to_3 = (imm >> 3) & 0b111
    bit_2 = (imm >> 2) & 0b1
    bit_6 = (imm >> 6) & 0b1
    imm = (bit_5_to_3 << 2) | (bit_2 << 1) | bit_6
    return rvprotoinstrs.instruc_cstype(RV32IC_OPCODE_SW[1], rs1prime, rs2prime, RV32IC_OPCODE_SW[0], imm)