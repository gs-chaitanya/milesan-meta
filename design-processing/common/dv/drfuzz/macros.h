#ifndef MACROS
#define MACROS
#include "def_tb.h"
#include <sys/stat.h>
#include <sys/types.h>

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define PERMISSIONS S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH

#define DUMP_DIR "/mnt/milesan-meta/design-processing/common/python_scripts/analysis/cov_dumps"
#define DUT_DIR DUMP_DIR "/" DUT
#define INST_DIR DUT_DIR "/" INST
#define SEED_DIR INST_DIR "/seed" STR(SEED)
#define Q_DIR SEED_DIR "/queue/"
#define COV_DIR SEED_DIR "/cov/"

// convert #bits to #32-bit-words for verilator 
#define b32(n) ((n + 31 ) / 32)
#define MAX_b32_VAL ((1l << 32) - 1)
#define b8(n) ((n + 7 ) / 8)
#define MAX_b8_VAL ((1l << 8) - 1)

#define N_FUZZ_INPUTS_b32 b32(N_FUZZ_INPUTS)
#define N_TAINT_INPUTS_b32 b32(N_TAINT_INPUTS)
#define N_COV_POINTS_b32 b32(N_COV_POINTS)
#define N_TAINT_OUTPUTS_b32 b32(N_TAINT_OUTPUTS)
#define N_ASSERTS_b32 b32(N_ASSERTS)

// compute traling bits for masks
#define N_FUZZ_TRAIL_BITS N_FUZZ_INPUTS%32
#define N_TAINT_INPUT_TRAIL_BITS N_TAINT_INPUTS%32
#define N_COV_TRAIL_BITS N_COV_POINTS%32
#define N_TAINT_OUTPUT_TRAIL_BITS N_TAINT_OUTPUTS%32
#define N_ASSERTS_TRAIL_BITS N_ASSERTS%32

// compute masks for last uint32 in arrays
#define trail_mask(x) ~(((int)(1l<<31))>>(31-x)) // shift 1 to MSB, arithmetic (so cast to signed int) shift right, invert
#define FUZZ_INPUT_MASK trail_mask(N_FUZZ_TRAIL_BITS)
#define TAINT_INPUT_MASK trail_mask(N_TAINT_INPUT_TRAIL_BITS)
#define COV_MASK trail_mask(N_COV_TRAIL_BITS)
#define TAINT_OUPUT_MASK trail_mask(N_TAINT_OUTPUT_TRAIL_BITS)
#define ASSERTS_MASK trail_mask(N_ASSERTS_TRAIL_BITS)

// max #tainted bits for brute force taint mutator
#define MAX_CANDIDATE_WEIGHT 25

#endif // MACROS
