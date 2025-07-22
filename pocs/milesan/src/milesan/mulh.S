#include "memcfg.h"
#include "data.h"
.text
    li s0, REGDUMP_ADDR
    li a2, UDATA
    ld a1, 0(a2)
    ld a0, 8(a2)
    mulh ra, a1, a0

    # li a1, 0xff
    # rem t0, a1, a1
    # # beq a1, t0, END

    # div t1, a1, ra
    
    # fence
    # sd ra, 0(s0)
    # fence

    # sd t0, 0(s0)
    # fence
    
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lui t1, 0x0
    sd t1, 0(s0)
    fence

    END:
    li s0, STOPSIG_ADDR
    fence
    sd a0, 0(s0)
    fence