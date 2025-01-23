# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

from milesan.util import ISAInstrClass
from analyzeelfs.dependencies import INTREG_ABINAMES, FPREG_ABINAMES

##
# Useful constant lists
##

IS_COMPRESSABLE_CLASS = [
    ISAInstrClass.MEM,
    ISAInstrClass.MEM64,
    ISAInstrClass.MEM64,
    ISAInstrClass.MEMFPU,
    ISAInstrClass.MEMFPUD,
    ISAInstrClass.JAL,
    ISAInstrClass.JALR,
    ISAInstrClass.BRANCH,
    ISAInstrClass.ALU,
    ISAInstrClass.ALU64,
]

IS_COMPRESSABLE = [
    "lw",
    "sw",
    "ld",
    "sd",
    "flw",
    "fsw",
    "fld",
    "fsd",
    "jal",
    "jalr",
    "beq",
    "bne",
    "addi",
    "add",
    "and",
    "or",
    "xor",
    "sub",
    "lui",
    "slli",
    "srli",
    "srai",
    "andi",
    "addw",
    "subw",
    "addiw"
]

COMPRESSED_INST_EQUIV = {
        #MEM
        "lw": ["c.lwsp", "c.lw"],
        "sw": ["c.swsp", "c.sw"],
        # MEM64
        "ld": ["c.ldsp", "c.ld"],
        "sd": ["c.sdsp", "c.sd"],
        # MEMFPU
        "flw": ["c.flwsp", "c.flw"],
        "fsw": ["c.fswsp", "c.fsw"],
        # MEMFPUD
        "fld": ["c.fldsp", "c.fld"],
        "fsd": ["c.fsdsp", "c.fsd"],
        # JAL
        "jal": ["c.j", "c.jal"],
        # JALR
        "jalr": ["c.jr", "c.jalr"],
        # BRANCH
        "beq": "c.beqz",
        "bne": "c.bnez",
        # ALU
        "addi": ["c.addi", "c.li", "c.addi16sp", "c.addi4spn"],
        "add": ["c.mv", "c.add"],
        "and": "c.and",
        "or": "c.or",
        "xor": "c.xor",
        "sub": "c.sub",
        "lui": "c.lui",
        "slli": "c.slli",
        "srli": "c.srli",
        "srai": "c.srai",
        "andi": "c.andi",
        # ALU64
        "addw": "c.addw",
        "subw": "c.subw",
        "addiw": "c.addiw",
        # Rest
        "ebreak": "c.ebreak"

        ##ADD NOP
}

##
#subclasses for gen_producer_id_to_tgtaddr()
##
MEMC = [
    "c.lwsp", 
    "c.lw",
    "c.swsp",
    "c.sw"
]
MEM64C = [
    "c.ld",
    "c.ldsp",
    "c.sd",
    "c.sdsp"
]
MEMFPUC = [
    "c.flwsp", 
    "c.flw",
    "c.fswsp", 
    "c.fsw"
]
MEMFPUDC = [
    "c.fldsp",
    "c.fld",
    "c.fsdsp",
    "c.fsd"
]
JALRC = [
    "c.jr",
    "c.jalr"
]
JALC = [
    "c.j", 
    "c.jal"
]
BRANCHC = [
    "c.beqz",
    "c.bnez"
]



# The so called most used register, labelled as r' in the manual
INTREG_ABINAMES_CMP = [ 's0', 's1', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5' ]

FPREG_ABINAMES_CMP = [ 'fs0', 'fs1', 'fa0', 'fa1', 'fa2', 'fa3', 'fa4', 'fa5' ]

##
# Utility functions
##

# Note, only c.jal, c.flwsp, c.fswsp, c.fsw, c.flw are only for RV32 only if compressed, the other are coherent with the non-compressed ISA.
# Maybe add the checks later for sanity

#note imm := immediate, nz := non zero, u := unsigned, shamt := shift ammount (can be 0)

def reg_id_to_str(rd_id = -1, rs1_id = -1, rs2_id = -1, reg_type = "int"): #FIXME, ditch this and use the intervals from the array
    rd_str, rs1_str, rs2_str = 0, 0, 0
    regs = INTREG_ABINAMES
    if reg_type == "float": regs = FPREG_ABINAMES

    if (rd_id != -1):
        rd_str = regs[rd_id]
    if (rs1_id != -1):
        rs1_str = regs[rs1_id]
    if (rs2_id != -1):
        rs2_str = regs[rs2_id]

    return rd_str, rs1_str, rs2_str


#regs are in dependency.py id is index, we can use ranges, regname_to_reg_id()
def handle_R12D(rd, rs1, rs2, instr_str):
    rd, rs1, rs2 = reg_id_to_str(rd_id=rd, rs1_id=rs1, rs2_id=rs2)
    assert rd != 0 and rs1 != 0 and rs2 != 0

    match instr_str:
        case "add":
            if rd == rs1 and rs2 != "zero":
                return ("c.add", True)
            elif rs1 == "zero" and rs2 != "zero":
                return ("c.mv", True)
            else :
                return ("", False)

        #we do not differenciate rv32/rv64, since the selection already happend
        case "and" | "or" | "xor" | "sub" | "addw" | "subw":
            if rd in INTREG_ABINAMES_CMP and rs1 == rd and rs2 in INTREG_ABINAMES_CMP:
                c_inst_str = COMPRESSED_INST_EQUIV[instr_str]
                return (c_inst_str, True)
            else:
                return ("", False)
            
    assert False #should never be reached #we should never reach this point

def handle_ImRd(rd, imm, instr_str):
    rd, _, _ = reg_id_to_str(rd_id=rd)
    assert rd != 0

    match instr_str:
        case "lui":
            if rd != "zero" and rd != "sp" and imm!=0 and imm in range(-(1<<6), (1<<6)): # nzimm[17:12]
                return ("c.lui", True)
            else:
                return ("", False)

    assert False, f"{instr_str}" #should never be reached

def handle_RegImm(rd, rs1, imm, instr_str, is_rv64):
    rd, rs1, _ = reg_id_to_str(rd_id=rd, rs1_id=rs1)
    assert rd != 0 and rs1 != 0

    match instr_str:
        case "addi":
            if rd == "sp" and rd == rs1 and imm%(1<<4) == 0 and imm != 0 and imm in range(-(1<<9), (1<<9)): #nzimm[9:4]
                return ("c.addi16sp", True)
            elif rd in INTREG_ABINAMES_CMP and rs1 == "sp" and imm%(1<<2)==0 and imm!=0 and imm in range(0, (1<<10)): #nzuimm[9:2]
                return ("c.addi4spn", True)
            elif rd != 0 and rd == rs1 and imm!=0 and imm in range(-(1<<5), (1<<5)): #nzimm[5:0]
                return ("c.addi", True)
            elif rd != "zero" and rs1 == "zero" and  imm in range(-(1<<5), (1<<5)): #imm[5:0]
                return ("c.li", True)
            else:
                return ("", False)
            
        case "slli":
            if rd == rs1 and imm != 0 and imm in range(0, (1<<6)): # shamt[5:0] #0 is used to encode 64 only for RV128, which is not tested
                if is_rv64 :
                    return ("c.slli", True)
                elif (not is_rv64) and imm in range(0, (1<<5)): #shamt[5] must be 0 for RV32C
                    return ("c.slli", True)
            return ("", False)

        case "srli" | "srai":
            if rd in INTREG_ABINAMES_CMP and rd == rs1 and imm != 0 and imm in range(0, (1<<6)): # shamt[5:0] #0 is used to encode 64 only for RV128, which is not tested
                if is_rv64 :
                    c_inst_str = COMPRESSED_INST_EQUIV[instr_str]
                    return (c_inst_str, True)
                elif (not is_rv64) and imm in range(0, (1<<5)): #shamt[5] must be 0 for RV32C
                    c_inst_str = COMPRESSED_INST_EQUIV[instr_str]
                    return (c_inst_str, True)
            return ("", False)
        
        case "addiw":
            if rd != "zero" and rd == rs1 and imm in range(-(1<<5), (1<<5)): # imm[5:0]
                return ("c.addiw", True)
            else:
                return ("", False)

        case "andi":
            if rd == rs1 and rd in INTREG_ABINAMES_CMP and imm in range(-(1<<5), (1<<5)): # imm[5:0]
                return ("c.andi", True)
            else:
                return ("", False)
    assert False #should never be reached

def handle_Branch(rs1, rs2, imm, instr_str):
    _, rs1, rs2 = reg_id_to_str(rs1_id=rs1, rs2_id=rs2)
    assert rs1 != 0 and rs2 != 0

    match instr_str:
        case "beq" | "bne":
            if rs2 == "zero" and rs1 in INTREG_ABINAMES_CMP and imm%(1<<1) == 0 and imm in range(-(1<<8), (1<<8)): # imm[8:1]
                c_inst_str = COMPRESSED_INST_EQUIV[instr_str]
                return (c_inst_str, True)
            else:
                return ("", False)
    assert False #should never be reached

#jal is even worse, as it always takes the branch, the descision must only be taken if we know the destination
def handle_JAL(rd, imm, instr_str, is_rv64):
    rd, _, _ = reg_id_to_str(rd_id=rd)
    assert rd != 0

    match instr_str:
        case "jal":
            if rd == "zero" and imm%(1<<1) == 0 and imm in range(-(1<<11), (1<<11)): # imm[11:1]
                return ("c.j", True)
            elif rd == "ra" and imm%(1<<1) == 0 and imm in range(-(1<<11), (1<<11)) and (not is_rv64): #jal is rv32c only, imm[11:1]
                return ("c.jal", True)
            else:
                return ("", False)
    assert False #should never be reached

def handle_JALR(rd, rs1, imm, instr_str):
    rd, rs1, _ = reg_id_to_str(rd_id=rd, rs1_id=rs1)
    assert rd != 0 and rs1 != 0

    match instr_str:
        case "jalr":
            if rd == "zero" and rs1 != "zero" and imm == 0:
                return ("c.jr", True)
            elif rd == "ra" and rs1 != "zero" and imm == 0:
                return ("c.jalr", True)
            else:
                return ("", False)
    assert False #should never be reached

#these must also be handled when we know the immediate value
def handle_IntLoad(rd, rs1, imm, instr_str):
    rd, rs1, _ = reg_id_to_str(rd_id=rd, rs1_id=rs1)
    assert rd != 0 and rs1 != 0

    match instr_str:
        case "lw":
            if rs1 == "sp" and imm % (1<<2) == 0 and rd != "zero" and imm in range(0, (1<<8)): #uimm[7:2]
                return ("c.lwsp", True)
            elif rd in INTREG_ABINAMES_CMP and rs1 in INTREG_ABINAMES_CMP and imm % (1<<2) == 0 and imm in range(0, (1<<7)): #uimm[6:2]
                return ("c.lw", True)
            else:
                return ("", False)

        case "ld":
            if rs1 == "sp" and imm % (1<<3) == 0 and rd != "zero" and imm in range(0, (1<<9)): # uimm[8:3]
                return ("c.ldsp", True)
            elif rd in INTREG_ABINAMES_CMP and rs1 in INTREG_ABINAMES_CMP and imm % (1<<3) == 0 and imm in range(0, (1<<8)): #uimm[7:3]
                return ("c.ld", True)
            else:
                return ("", False)

    assert False #should never be reached

def handle_IntStore(rs1, rs2, imm, instr_str):
    _, rs1, rs2 = reg_id_to_str(rs1_id=rs1, rs2_id=rs2)
    assert rs1 != 0 and rs2 != 0 and rs2 != 0

    match instr_str:
        case "sw":
            if rs1 == "sp" and imm % (1<<2) == 0 and imm in range(0, (1<<8)): #uimm[7:2]
                return ("c.swsp", True)
            elif rs1 in INTREG_ABINAMES_CMP and rs2 in INTREG_ABINAMES_CMP and imm % (1<<2) == 0 and imm in range(0, (1<<7)): #uimm[6:2]
                return ("c.sw", True)
            else:
                return ("", False) 

        case "sd":
            if rs1 == "sp" and imm % (1<<3) == 0 and imm in range(0, (1<<9)): # uimm[8:3]
                return ("c.sdsp", True)
            elif rs1 in INTREG_ABINAMES_CMP and rs2 in INTREG_ABINAMES_CMP and imm % (1<<3) == 0 and imm in range(0, (1<<8)): #uimm[7:3]
                return ("c.sd", True)
            else:
                return ("", False)
    assert False #should never be reached

def handle_FloatLoad(frd, rs1, imm, instr_str, is_rv64):
    rd, _, _ = reg_id_to_str(rd_id=frd, reg_type="float")
    _, rs1, _ = reg_id_to_str(rs1_id=rs1)
    assert rd != 0 and rs1 != 0

    match instr_str:
        case "flw":
            if is_rv64: 
                return ("", False)
            elif rs1 == "sp" and imm % (1<<2) == 0 and imm in range(0, (1<<8)): #RV32FC only, uimm[7:2]
                return ("c.flwsp", True)
            elif rd in FPREG_ABINAMES_CMP and rs1 in INTREG_ABINAMES_CMP and imm % (1<<2) == 0 and imm in range(0, (1<<7)): #uimm[6:2]
                return ("c.flw", True) #RV32FC only
            else:
                return ("", False) 

        case "fld":
            if rs1 == "sp" and imm % (1<<3) == 0 and imm in range(0, (1<<9)): # uimm[8:3]
                return ("c.fldsp", True)
            elif rd in FPREG_ABINAMES_CMP and rs1 in INTREG_ABINAMES_CMP and imm % (1<<3) == 0 and imm in range(0, (1<<8)): #uimm[7:3]
                return ("c.fld", True)
            else:
                return ("", False)
    assert False #should never be reached

def handle_FloatStore(rs1, frs2, imm, instr_str, is_rv64):
    _, rs1, _ = reg_id_to_str(rs1_id=rs1)
    _, _, rs2 = reg_id_to_str(rs2_id=frs2, reg_type="float")
    assert rs1 != 0 and rs2 != 0

    match instr_str:
        case "fsw":
            if is_rv64: 
                return ("", False) 
            elif rs1 == "sp" and imm % (1<<2) == 0 and imm in range(0, (1<<8)): #RV32FC only, uimm[7:2]
                return ("c.fswsp", True)
            elif rs1 in INTREG_ABINAMES_CMP and rs2 in FPREG_ABINAMES_CMP and imm % (1<<2) == 0 and imm in range(0, (1<<7)): #uimm[6:2]
                return ("c.fsw", True) #RV32FC only
            else:
                return ("", False) 

        case "fsd":
            if rs1 == "sp" and imm % (1<<3) == 0 and imm in range(0, (1<<9)): # uimm[8:3]
                return ("c.fsdsp", True)
            elif rs1 in INTREG_ABINAMES_CMP and rs2 in FPREG_ABINAMES_CMP and imm % (1<<3) == 0 and imm in range(0, (1<<8)): #uimm[7:3]
                return ("c.fsd", True)
            else:
                return ("", False)
    assert False #should never be reached

#Not sure what to do with this
def handle_Ebreak():
    return ("c.ebreak", True)

###
# ADD NOP !!
###