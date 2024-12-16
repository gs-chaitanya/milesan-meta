from milesan.util import CFInstructionClass
import enum

# If true only EITHER rd, rs1 etc are tainted, if false several bytecode fields can be tainted.
CFINSTRCLASS_TAINT_ONLY_ONE = True 

# If CFINSTRCLASS_TAINT_ONLY_ONE is true, the probabilities must sum up to 1. Otherwise each probability individually determines the likelyhoold that the resp. bits get tainted.
CFINSTRCLASS_TAINT_PROBS = { 
    CFInstructionClass.REGIMM: {"rd": 0,"rs1": 0, "imm": 1},
    CFInstructionClass.IMMRD: {"rd": 0,"imm": 1},
    CFInstructionClass.R12D: {"rd": 1,"rs1": 0, "rs2":0},
    CFInstructionClass.F2I: {"rd": 0.4,"frs1": 0.4, "rm":0.2},
    CFInstructionClass.I2F: {"frd": 0.4,"rs1": 0.4, "rm":0.2},
    CFInstructionClass.F4: {"frd": 0.2,"frs1": 0.2,"frs2":0.2,"frs3":0.2,"rm":0.2},
    CFInstructionClass.F3: {"frd": 0.2,"frs1": 0.3,"frs2":0.3, "rm":0.2},
    CFInstructionClass.F3NORM: {"frd": 0.2,"frs1": 0.4,"frs2":0.4},
    CFInstructionClass.F2: {"frd": 0.5,"frs1": 0.5},
    CFInstructionClass.FIRD2: {"rd": 0.2,"frs1": 0.4,"frs2":0.4},
    CFInstructionClass.FIRD1: {"rd": 0.3,"frs1": 0.7},
    CFInstructionClass.FIRS1: {"frd": 0.3,"rs1": 0.7},
    CFInstructionClass.INTLOAD: {"rd": 1},
    CFInstructionClass.INTSTORE: {"rs": 1},
    CFInstructionClass.FLOATLOAD: {"frd": 1},
    CFInstructionClass.FLOATSTORE: {"frs": 1}
}

# Max number of instructions to be injected within a basic block.
MAX_N_INJECT_PER_BB = 1

# Probability that instruction is chosen for injection. if more than MAX_N_INJECT_PER_BB are chosen within a block, only the first MAX_N_INJECT_PER_BB are used.
# This can be used to skip some instruction types from being used for injection.
CFINSTRCLASS_INJECT_PROBS = {
    CFInstructionClass.NONE: 0,
    CFInstructionClass.REGIMM: 0,
    CFInstructionClass.IMMRD: 1,
    CFInstructionClass.R12D: 0,
    CFInstructionClass.F2I: 0,
    CFInstructionClass.I2F: 0,
    CFInstructionClass.F4: 0,
    CFInstructionClass.F3: 0,
    CFInstructionClass.F3NORM: 0,
    CFInstructionClass.F2: 0,
    CFInstructionClass.FIRD2: 0,
    CFInstructionClass.FIRD1: 0,
    CFInstructionClass.FIRS1: 0,
    CFInstructionClass.BRANCH: 0,
    CFInstructionClass.JAL: 0,
    CFInstructionClass.JALR: 0,
    CFInstructionClass.SPECIAL: 0,
    CFInstructionClass.ECALL: 0,
    CFInstructionClass.INTLOAD: 0,
    CFInstructionClass.INTSTORE: 0,
    CFInstructionClass.FLOATLOAD: 0,
    CFInstructionClass.FLOATSTORE: 0,
    CFInstructionClass.CSR: 0
}


class IntegerRegisterClass(enum.IntEnum):
    zero = 0
    ra = 1
    sp = 2
    gp = 3
    tp = 4
    t0 = 5
    t1 = 6
    t2 = 7
    s0 = 8 # also fp
    s1 = 9
    a0 = 10
    a1 = 11
    a2 = 12
    a3 = 13
    a4 = 14
    a5 = 15
    a6 = 16
    a7 = 17
    s2 = 18
    s3 = 19
    s4 = 20
    s5 = 21
    s6 = 22
    s7 = 23
    s8 = 24
    s9 = 25
    s10 = 26
    s11 = 27
    t3 = 28
    t4 = 29
    t5 = 30
    t6 = 31


 # use this to mask out any destination regs from being tainted in the bytecode
RD_INT_TAINT_PROBS_MASK = {
    IntegerRegisterClass.zero : 0,
    IntegerRegisterClass.ra: 1,
    IntegerRegisterClass.sp : 1, #0
    IntegerRegisterClass.gp: 1, #0
    IntegerRegisterClass.tp: 1, #0
    IntegerRegisterClass.t0 : 1,
    IntegerRegisterClass.t1: 1,
    IntegerRegisterClass.t2: 1,
    IntegerRegisterClass.s0: 1, #0
    IntegerRegisterClass.s1: 1,
    IntegerRegisterClass.a0: 1,
    IntegerRegisterClass.a1: 1,
    IntegerRegisterClass.a2: 1,
    IntegerRegisterClass.a3: 1,
    IntegerRegisterClass.a4: 1,
    IntegerRegisterClass.a5: 1,
    IntegerRegisterClass.a6: 1,
    IntegerRegisterClass.a7: 1,
    IntegerRegisterClass.s2: 1,
    IntegerRegisterClass.s3: 1,
    IntegerRegisterClass.s4: 1,
    IntegerRegisterClass.s5: 1,
    IntegerRegisterClass.s6: 1,
    IntegerRegisterClass.s7: 1,
    IntegerRegisterClass.s8: 1,
    IntegerRegisterClass.s9: 1,
    IntegerRegisterClass.s10: 1,
    IntegerRegisterClass.s11: 1,
    IntegerRegisterClass.t3: 1,
    IntegerRegisterClass.t4: 1,
    IntegerRegisterClass.t5: 1,
    IntegerRegisterClass.t6: 1
}

 # use this to mask out any destination regs from being tainted in the bytecode
RS_INT_TAINT_PROBS_MASK = {
    IntegerRegisterClass.zero : 1,
    IntegerRegisterClass.ra: 1,
    IntegerRegisterClass.sp : 1,#0
    IntegerRegisterClass.gp: 1,#0
    IntegerRegisterClass.tp: 1,#0
    IntegerRegisterClass.t0 : 1,
    IntegerRegisterClass.t1: 1,
    IntegerRegisterClass.t2: 1,
    IntegerRegisterClass.s0: 1, #0
    IntegerRegisterClass.s1: 1,
    IntegerRegisterClass.a0: 1,
    IntegerRegisterClass.a1: 1,
    IntegerRegisterClass.a2: 1,
    IntegerRegisterClass.a3: 1,
    IntegerRegisterClass.a4: 1,
    IntegerRegisterClass.a5: 1,
    IntegerRegisterClass.a6: 1,
    IntegerRegisterClass.a7: 1,
    IntegerRegisterClass.s2: 1,
    IntegerRegisterClass.s3: 1,
    IntegerRegisterClass.s4: 1,
    IntegerRegisterClass.s5: 1,
    IntegerRegisterClass.s6: 1,
    IntegerRegisterClass.s7: 1,
    IntegerRegisterClass.s8: 1,
    IntegerRegisterClass.s9: 1,
    IntegerRegisterClass.s10: 1,
    IntegerRegisterClass.s11: 1,
    IntegerRegisterClass.t3: 1,
    IntegerRegisterClass.t4: 1,
    IntegerRegisterClass.t5: 1,
    IntegerRegisterClass.t6: 1
}


class FloatRegisterClass(enum.IntEnum):
    ft0 = 0
    ft1 = 1
    tf2 = 2
    tf3 = 3
    ft4 = 4
    ft5 = 5
    ft6 = 6
    ft7 = 7
    fs0 = 8
    fs1 = 9
    fa0 = 10
    fa1 = 11
    fa2 = 12
    fa3 = 13
    fa4 = 14
    fa5 = 15
    fa6 = 16
    fa7 = 17
    fs2 = 18
    fs3 = 19
    fs4 = 20
    fs5 = 21
    fs6 = 22
    fs7 = 23
    fs8 = 24
    fs9 = 25
    fs10 = 26
    fs11 = 27
    ft8 = 28
    ft9 = 29
    ft10 = 30
    ft11 = 31

RD_FLOAT_TAINT_PROBS_MASK = {
    FloatRegisterClass.ft0: 1,
    FloatRegisterClass.ft1: 1,
    FloatRegisterClass.tf2: 1,
    FloatRegisterClass.tf3: 1,
    FloatRegisterClass.ft4: 1,
    FloatRegisterClass.ft5: 1,
    FloatRegisterClass.ft6: 1,
    FloatRegisterClass.ft7: 1,
    FloatRegisterClass.fs0: 1,
    FloatRegisterClass.fs1: 1,
    FloatRegisterClass.fa0: 1,
    FloatRegisterClass.fa1: 1,
    FloatRegisterClass.fa2: 1,
    FloatRegisterClass.fa3: 1,
    FloatRegisterClass.fa4: 1,
    FloatRegisterClass.fa5: 1,
    FloatRegisterClass.fa6: 1,
    FloatRegisterClass.fa7: 1,
    FloatRegisterClass.fs2: 1,
    FloatRegisterClass.fs3: 1,
    FloatRegisterClass.fs4: 1,
    FloatRegisterClass.fs5: 1,
    FloatRegisterClass.fs6: 1,
    FloatRegisterClass.fs7: 1,
    FloatRegisterClass.fs8: 1,
    FloatRegisterClass.fs9: 1,
    FloatRegisterClass.fs10: 1,
    FloatRegisterClass.fs11: 1,
    FloatRegisterClass.ft8: 1,
    FloatRegisterClass.ft9: 1,
    FloatRegisterClass.ft10: 1,
    FloatRegisterClass.ft11: 1
}


RS_FLOAT_TAINT_PROBS_MASK = {
    FloatRegisterClass.ft0: 1,
    FloatRegisterClass.ft1: 1,
    FloatRegisterClass.tf2: 1,
    FloatRegisterClass.tf3: 1,
    FloatRegisterClass.ft4: 1,
    FloatRegisterClass.ft5: 1,
    FloatRegisterClass.ft6: 1,
    FloatRegisterClass.ft7: 1,
    FloatRegisterClass.fs0: 1,
    FloatRegisterClass.fs1: 1,
    FloatRegisterClass.fa0: 1,
    FloatRegisterClass.fa1: 1,
    FloatRegisterClass.fa2: 1,
    FloatRegisterClass.fa3: 1,
    FloatRegisterClass.fa4: 1,
    FloatRegisterClass.fa5: 1,
    FloatRegisterClass.fa6: 1,
    FloatRegisterClass.fa7: 1,
    FloatRegisterClass.fs2: 1,
    FloatRegisterClass.fs3: 1,
    FloatRegisterClass.fs4: 1,
    FloatRegisterClass.fs5: 1,
    FloatRegisterClass.fs6: 1,
    FloatRegisterClass.fs7: 1,
    FloatRegisterClass.fs8: 1,
    FloatRegisterClass.fs9: 1,
    FloatRegisterClass.fs10: 1,
    FloatRegisterClass.fs11: 1,
    FloatRegisterClass.ft8: 1,
    FloatRegisterClass.ft9: 1,
    FloatRegisterClass.ft10: 1,
    FloatRegisterClass.ft11: 1
}

# SHAMT_INSTRUCTIONS = {
#     "srl",
#     "sra",
#     "sll",
#     "sllw",
#     "srlw",
#     "sraw"
# }


OPCODE_FIELD_MASKS = {
    "rd": 0x1F,
    "rs": 0x1F,
    "immi": 0xFFF,
    "shamt": 0x1F,
    "immu": 0xFFFFF,
    "immj": 0xFFFFF,
    "rm": 0x7
}

DONT_TAINT_REGS = [
    # IntegerRegisterClass.zero
    # IntegerRegisterClass.sp, # stack pointer r2
    # IntegerRegisterClass.gp, #global pointer r3
    # IntegerRegisterClass.tp, # thread pointer r4
    # IntegerRegisterClass.s0, # frame pointer r8
    # IntegerRegisterClass.s1 # , saved register r9
]

OPCODE_FIELD_BITS = {
    "rd": 7,
    "rs1": 15,
    "rs2": 20,
    "rs3": 27,
    "immi": 20,
    "immu": 12,
    "immj": 12,
    "rm": 12
}





