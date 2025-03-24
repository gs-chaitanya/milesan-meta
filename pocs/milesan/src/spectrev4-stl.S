#------------------------------------------------------------------------------
# SpectreV4 minimal example.
#------------------------------------------------------------------------------

.section ".data.init"
secret:
  .word 0xdeadbeef


.section ".text.init","ax",@progbits
	.globl _start
	.align 2

_start:
  li s0, 0x80004000
  addi s1, s0, 0x80
  ld zero, 0(s0)

  mv t2, s0
  # Slow down computation of store address.
  li t1, 6
  mul t2, t2, t1
  div t2, t2, t1
  mul t2, t2, t1
  div t2, t2, t1
  mul t2, t2, t1
  div t2, t2, t1
  
  mul t2, t2, t1
  div t2, t2, t1
  mul t2, t2, t1
  div t2, t2, t1
  mul t2, t2, t1
  div t2, t2, t1
  
  sd s0, 0(t2)

  # Load from s0, reodered before the store.
  ld t0, 0(s0)
  ld s0, 0(t0)

  mul t2, t2, t1
  div t2, t2, t1

  ld t0, 0(t0)

end:
  li a0, 0x60000010
  sd t0, 0(a0)
  fence
  li a0, 0x60000000
  sd a0, 0(a0)
