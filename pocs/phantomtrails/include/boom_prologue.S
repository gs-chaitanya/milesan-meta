.section ".data.init"
secret:
  .word 0xdeadbeef

public:
  .word 0xffffffff

.section ".text.init","ax",@progbits
	.globl _start
	.align 2

_start: