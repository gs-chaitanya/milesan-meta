#------------------------------------------------------------------------------
# SpectreV4 minimal example.
#------------------------------------------------------------------------------
#include "memcfg.h"

.text
    li a1, REGDUMP_ADDR
    # Store all registers to the address in a1
    sd x0, 0(a1)
    fence
    sd ra, 0(a1)
    fence
    sd sp, 0(a1)
    fence
    sd gp, 0(a1)
    fence
    sd tp, 0(a1)
    fence
    sd t0, 0(a1)
    fence
    sd t1, 0(a1)
    fence
    sd t2, 0(a1)
    fence
    sd s0, 0(a1)
    fence
    sd s1, 0(a1)
    fence
    sd a0, 0(a1)
    fence
    sd a1, 0(a1)
    fence
    sd a2, 0(a1)
    fence
    sd a3, 0(a1)
    fence
    sd a4, 0(a1)
    fence
    sd a5, 0(a1)
    fence
    sd a6, 0(a1)
    fence
    sd a7, 0(a1)
    fence
    sd s2, 0(a1)
    fence
    sd s3, 0(a1)
    fence
    sd s4, 0(a1)
    fence
    sd s5, 0(a1)
    fence
    sd s6, 0(a1)
    fence
    sd s7, 0(a1)
    fence
    sd s8, 0(a1)
    fence
    sd s9, 0(a1)
    fence
    sd s10, 0(a1)
    fence
    sd s11, 0(a1)
    fence
    sd t3, 0(a1)
    fence
    sd t4, 0(a1)
    fence
    sd t5, 0(a1)
    fence
    sd t6, 0(a1)
    fence
    li a0, STOPSIG_ADDR
    fence
    sd a0, 0(a0)
    fence