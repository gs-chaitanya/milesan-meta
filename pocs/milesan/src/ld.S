.section ".text.init","ax",@progbits
	.globl _start
	.align 2
_start:
lui a0,0x80000
slli a0, a0, 32
srli a0, a0, 32
addi a0, a0, 0x100
ld zero, 0(a0)
li a0, 16
sd zero, 0(a0)
li a0, 0
sd a0, 0(a0)