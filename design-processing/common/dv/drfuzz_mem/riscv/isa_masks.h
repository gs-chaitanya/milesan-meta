#pragma once
#define N_BYTES_PER_INST 4 // no compressed for now
#define OPCODE_BIT 0
#define OPCODE_MASK 0x3F

#define RD_BIT 7
#define RD_MASK 0x1F

#define FUNCT3_BIT 12
#define FUNCT3_MASK 0x7

#define FUNCT7_BIT 25
#define FUNCT7_MASK 0x7F

#define FUNCT5_BIT 27
#define FUNCT5_MASK 0x1F

#define FMT_BIT 25
#define FMT_MASK 0x3

#define RM_BIT 12
#define RM_MASK 0x7

#define RS1_BIT 15
#define RS1_MASK 0x1F

#define RS2_BIT 20
#define RS2_MASK 0x1F

#define RS3_BIT 27
#define RS3_MASK 0x1F

#define IMMI_BIT 20
#define IMMI_MASK 0xFFF

#define IMMS11to5_BIT 25
#define IMMS11to5_MASK 0x7F
#define IMMS4to0BIT 7
#define IMMS4to0MASK 0x1F

#define IMMB12and10to5_BIT 25
#define IMMB12andto5_MASK 0x7F
#define IMMB11and4to0BIT 7
#define IMMB11and4to0MASK 0x1F

#define IMMU_BIT 12
#define IMMU_MASK  0xFFFFF

#define IMMJ_BIT 12
#define IMMJ_MASK 0xFFFFF
