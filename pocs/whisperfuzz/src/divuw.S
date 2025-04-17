.section ".text.init","ax",@progbits
	.globl _start
	.align 2
_start:
li a3, 291
li a7, -1954
li s10, 201
li t6, 477
csrr t1, mcycle
divuw t5, a7,t6
rem t3, s10, a3
csrr t2, mcycle
sub t1, t2, t1
li t0, 0x60000010
sd t1, 0(t0)
li t0, 0x60000000
sd t0, 0(t0)
