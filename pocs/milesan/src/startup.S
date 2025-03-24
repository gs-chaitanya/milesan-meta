.section ".data.init"
secret:
  .word 0xdeadbeef

.section ".text.init","ax",@progbits
	.globl _start
	.align 2
    
_start:
    li sp, 0x80004000