#ifndef MACROS
#define MACROS
#include "def_tb.h"
#include <sys/stat.h>
#include <sys/types.h>


#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define PERMISSIONS S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH

// standard vals, Q_DIR and COV_DIR can be overwritten by environment vars
#define DUMP_DIR "/milesan-data/cov_dump_mem_stdout"
#define DUT_DIR DUMP_DIR "/" DUT
#define INST_DIR DUT_DIR "/" INST
#define SEED_DIR INST_DIR "/seed" STR(SEED)
#define COV_DIR SEED_DIR "/cov/"
#define REG_MISMATCH_DIR SEED_DIR "/reg_mismatch/"
#define TIMEOUT_DIR SEED_DIR "/timeout/"
#define Q_DIR SEED_DIR "/queue/"
#define EXPECTED_REGVALS SEED_DIR "/expected_regvals/0.regs.json"
#define MUT_INST_PATH SEED_DIR "/mut_instructions/0.inst.json"
#define REGDUMP_PATH SEED_DIR "/regdump.json"
#define REGSTREAM_PATH SEED_DIR "/regstream.json"
#define DEFAULT_ID 0

// #define EN_COV_QUANTIZATION
#ifndef T_DELTA_COV_DUMP
#define T_DELTA_COV_DUMP 1
#endif

// convert #bits to #32-bit-words for verilator 
#define b32(n) ((n + 31 ) / 32)
#define MAX_b32_VAL ((1l << 32) - 1)
#define b8(n) ((n + 7 ) / 8)
#define MAX_b8_VAL ((1l << 8) - 1)

#define N_COV_POINTS_b32 b32(N_COV_POINTS)
#define N_TAINT_OUTPUTS_b32 b32(N_TAINT_OUTPUTS)
#define N_ASSERTS_b32 b32(N_ASSERTS)

// compute traling bits for masks
#define N_COV_TRAIL_BITS N_COV_POINTS%32
#define N_TAINT_OUTPUT_TRAIL_BITS N_TAINT_OUTPUTS%32
#define N_ASSERTS_TRAIL_BITS N_ASSERTS%32

// compute masks for last uint32 in arrays
#define trail_mask(x) ~(((int)(1l<<31))>>(31-x)) // shift 1 to MSB, arithmetic (so cast to signed int) shift right, invert
#define COV_MASK trail_mask(N_COV_TRAIL_BITS)
#define TAINT_OUPUT_MASK trail_mask(N_TAINT_OUTPUT_TRAIL_BITS)
#define ASSERTS_MASK trail_mask(N_ASSERTS_TRAIL_BITS)
#define FULLMASK_b32 0xFFFFFFFFULL

// bus widths
#define DATA_WIDTH_BYTES (1<<DATA_WIDTH_BYTES_LOG2)
#define ADDR_WIDTH_BYTES (1<<ADDR_WIDTH_BYTES_LOG2)

#ifndef SEED
#define SEED 73
#endif // SEED

#ifndef MUX_UNTAINT_TH
#define MUX_UNTAINT_TH 0
#endif
#ifndef RELOCATE_UP
#define RELOCATE_UP 0x8000000
#endif

#endif // MACROS
