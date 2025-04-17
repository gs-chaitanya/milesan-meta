#include "memcfg.h"

.text
main:
    // access to user mode page to show that it works
    li s0, UDATA
    ld s1, 0(s0)
    bnez s1, test
    li t1, 0x123
    mul a0, a0, t1
    div a0, a0, t1
    mul a0, a0, t1
    div a0, a0, t1
    mul a0, a0, t1
    div a0, a0, t1
    mul a0, a0, t1
    div a0, a0, t1


.align 4
test:
    unimp

#include "data.h"
