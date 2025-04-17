#include "memcfg.h"

.text
main:
    li s0, UDATA
    ld s1, 0(s0) # load from tainted address
    bnez s1, stop # taint PC
    mul a0, t0, a0 # random stuff
    div a0, t0,a0
    mul a0, t0, a0
    div a0, t0,a0
    mul a0, t0, a0
    div a0, t0,a0
    stop:
    li a1, REGDUMP_ADDR
    sd x0, 0(a1)
    fence
    li a0, STOPSIG_ADDR
    sd a0, 0(a0)
    fence
    j stop

.align 4
test:
    unimp

#include "data.h"
