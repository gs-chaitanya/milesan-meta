OUTPUT_ARCH( "riscv" )

SECTIONS
{
  . = 0x00000000;
  .text : { *(.text) }
  . = 0x00009000;
  .data : { *(.data) }
  _end = .;
}