#include "memcfg.h"

.text
    li a2, 0
    slli a0, a2, 0
    div a0, a0, a2
    li a1, REGDUMP_ADDR
    # Store all registers to the address in a1
    sd a0, 0(a1)
    fence
    li a0, STOPSIG_ADDR
    fence
    sd a0, 0(a0)
    fence