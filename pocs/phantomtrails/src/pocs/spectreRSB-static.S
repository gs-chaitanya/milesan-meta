#include "memcfg.h"

.text
setup:
  li s2, UDATA
  lla s1, ret_target

taint_load:
  ld t0, 0(s2)
  #ifndef DISABLE_DEP_LOAD
  ld t0, 0(t0)
  #endif

attack:
  # mv s0, s2

  # Slow down jump with mul/div by a non-power-of-two.
  mv t1, s1
  li t2, 6
  mul t1, t1, t2
  div t1, t1, t2
  mul t1, t1, t2
  div t1, t1, t2
  mul t1, t1, t2
  div t1, t1, t2
  mul t1, t1, t2
  div t1, t1, t2

  # Change ret target.
  mv ra, t1
  # Mispredicted ret: empty predictor returns to 0.
  ret
  unimp

.align 8
ret_target:
  ld t0, 0x80(s0)
  unimp

#include "data.h"
