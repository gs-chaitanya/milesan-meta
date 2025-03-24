.section ".text.init","ax",@progbits
	.globl _start
	.align 2
_start:
li a4, 0
li a7, 0
divuw t3, t3, a4
li a0, 16
sd zero, 0(a0)
li a0, 0
sd a0, 0(a0)
