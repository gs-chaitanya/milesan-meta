#include "memcfg.h"

.text
main:
    // access to user mode page to show that it works
    li s0, UDATA
    ld s1, 0(s0)

    // access to supervisor mode page, which will raise a fault
    li s1, SDATA
    lb s1, 0(s1)
    // add offset to user base address
    mul s1, s0, s1
    // load from that address in order to
    // reveal secret value through side channel
    #ifndef DISABLE_DEP_LOAD
    ld s2, 0(s1)
    #endif

#include "data.h"
