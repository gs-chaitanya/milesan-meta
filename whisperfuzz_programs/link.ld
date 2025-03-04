OUTPUT_ARCH( "riscv" )
ENTRY(_start)

SECTIONS
{
  . = 0x80000000;
  .text.init : { *(.text.init) }
  . = ALIGN(0x1000);
  . = 0x80004000;
  .data.init : { *(.data.init) }
  . = ALIGN(0x1000);

}

