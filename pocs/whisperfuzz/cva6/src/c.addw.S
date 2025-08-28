.section ".text.init","ax",@progbits
	.globl _start
	.align 2
_start:
li a0, 2047
li a1, 0
csrr t1, mcycle
c.addw a1, a0
csrr t2, mcycle
sub t1, t2, t1
li t0, 16
sd t1, 0(t0)
li t0, 0
sd t0, 0(t0)
