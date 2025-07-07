/* Copyright (C) 2025 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)

PHDRS {
      ph_text PT_LOAD;
      ph_dyn  PT_DYNAMIC;
}

SECTIONS {
	 .text : {
	    PROVIDE_HIDDEN (__text_start = .);
	    *(.text .text.*)
	    PROVIDE_HIDDEN (__text_end = .);
	    *(.rodata .rodata.*)
	    *(.data .data.*)
	    PROVIDE_HIDDEN (__bss_start = .);
	    *(.bss .bss.*)
	    *(COMMON)
	    PROVIDE_HIDDEN (__bss_end = .);
	 } : ph_text

	.dynamic :  {
	    PROVIDE_HIDDEN (_DYNAMIC = .);
	    *(.dynamic)
	} : ph_text : ph_dyn
}
