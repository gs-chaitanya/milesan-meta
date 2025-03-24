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
  li s1, 0x80004000

  # Mul s0 by 1.
  li t1, 1
  mul s0, s0, t1
  mul s0, s0, t1
  mul s0, s0, t1
  mul s0, s0, t1
  mul s0, s0, t1
  mul s0, s0, t1
  mul s0, s0, t1
  mul s0, s0, t1
  mul s0, s0, t1
  # Store new value in [s0].
  sd t1, 0(s0)

  # Load from s1, reodered before the store.
  ld t0, 0(s1)
  
  beq t0, t1, end
  ld t0, 0(t0)

end:
  li a0, 0x60000010
  sd t0, 0(a0)
  fence
  li a0, 0x60000000
  sd a0, 0(a0)

