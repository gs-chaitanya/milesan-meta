#------------------------------------------------------------------------------
# SpectreV4 minimal example.
#------------------------------------------------------------------------------
#include "memcfg.h"

.text
    li a0, 123
    li a2, 123
    div a0, a2, a0
    li a1, REGDUMP_ADDR
    # Store all registers to the address in a1
    sd a0, 0(a1)
    fence
    li a0, STOPSIG_ADDR
    fence
    sd a0, 0(a0)
    fence