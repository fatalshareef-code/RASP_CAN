MEMORY { FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 4M  RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 4M }
ENTRY(Reset_Handler)
SECTIONS {
 .text : { KEEP(*(.vectors)) *(.text*) *(.rodata*) } > FLASH
 .ARM.exidx : { *(.ARM.exidx*) } > FLASH
 _etext = .;
 .data : AT(_etext) { _sdata = .; *(.data*) . = ALIGN(4); _edata = .; } > RAM
 .bss : { _sbss = .; *(.bss*) *(COMMON) . = ALIGN(4); _ebss = .; } > RAM
 _estack = ORIGIN(RAM) + LENGTH(RAM);
}
