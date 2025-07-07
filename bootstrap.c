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


#include "elfldr_elf.c"

#define SYS_munmap        73
#define SYS_mmap          477

#define PAGE_SIZE 0x4000
#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_SIZE - 1))

#define MAP_PRIVATE   0x0002
#define MAP_ANONYMOUS 0x1000
#define MAP_FAILED    ((void *)-1)

#define PROT_READ  1
#define PROT_WRITE 2
#define PROT_EXEC  4

#define ELF64_R_SYM(info)   ((info) >> 32)
#define ELF64_ST_BIND(info) ((info) >> 4)

#define PT_LOAD    1
#define PT_DYNAMIC 2

#define DT_NULL            0
#define DT_NEEDED          1
#define DT_PLTRELSZ        2
#define DT_STRTAB          5
#define DT_SYMTAB          6
#define DT_RELA            7
#define DT_RELASZ          8
#define DT_JMPREL          23
#define DT_INIT_ARRAY      25
#define DT_FINI_ARRAY      26
#define DT_INIT_ARRAYSZ    27
#define DT_FINI_ARRAYSZ    28
#define DT_PREINIT_ARRAY   32
#define DT_PREINIT_ARRAYSZ 33
#define DT_GNU_HASH         0x6ffffef5

#define R_X86_64_64       1
#define R_X86_64_GLOB_DAT 6
#define R_X86_64_JMP_SLOT 7
#define R_X86_64_RELATIVE 8

#define ET_DYN 3

#define STB_WEAK 2

#define SHT_RELA 4

#define PF_X (1 << 0)
#define PF_W (1 << 1)
#define PF_R (1 << 2)


typedef struct {
  unsigned char e_ident[16];
  unsigned short e_type;
  unsigned short e_machine;
  unsigned int e_version;
  unsigned long e_entry;
  unsigned long e_phoff;
  unsigned long e_shoff;
  unsigned int e_flags;
  unsigned short e_ehsize;
  unsigned short e_phentsize;
  unsigned short e_phnum;
  unsigned short e_shentsize;
  unsigned short e_shnum;
  unsigned short e_shstrndx;
} Elf64_Ehdr;


typedef struct {
  unsigned int p_type;
  unsigned int p_flags;
  unsigned long p_offset;
  unsigned long p_vaddr;
  unsigned long p_paddr;
  unsigned long p_filesz;
  unsigned long p_memsz;
  unsigned long p_align;
} Elf64_Phdr;


typedef struct {
  unsigned int sh_name;
  unsigned int sh_type;
  unsigned long sh_flags;
  unsigned long sh_addr;
  unsigned long sh_offset;
  unsigned long sh_size;
  unsigned int sh_link;
  unsigned int sh_info;
  unsigned long sh_addralign;
  unsigned long sh_entsize;
} Elf64_Shdr;


typedef struct {
  long d_tag;
  union {
    unsigned long d_val;
    unsigned long d_ptr;
  } d_un;
} Elf64_Dyn;


typedef struct {
  unsigned int   st_name;
  unsigned char  st_info;
  unsigned char  st_other;
  unsigned short st_shndx;
  unsigned long  st_value;
  unsigned long  st_size;
} Elf64_Sym;


typedef struct {
  unsigned long r_offset;
  unsigned long r_info;
  long          r_addend;
} Elf64_Rela;



static inline long
__syscall(long n, ...) {
  long a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0, a6 = 0;
  __builtin_va_list ap;
  unsigned long ret;
  char iserror;

  __builtin_va_start(ap, n);
  a1 = __builtin_va_arg(ap, long);
  a2 = __builtin_va_arg(ap, long);
  a3 = __builtin_va_arg(ap, long);
  a4 = __builtin_va_arg(ap, long);
  a5 = __builtin_va_arg(ap, long);
  a6 = __builtin_va_arg(ap, long);
  __builtin_va_end(ap);

  register long r10 __asm__("r10") = a4;
  register long r8  __asm__("r8")  = a5;
  register long r9  __asm__("r9")  = a6;

  __asm__ __volatile__(
		       "syscall"
		       : "=a"(ret), "=@ccc"(iserror), "+r"(r10), "+r"(r8), "+r"(r9)
		       : "a"(n), "D"(a1), "S"(a2), "d"(a3)
		       : "rcx", "r11", "memory");

  return iserror ? -ret : ret;
}


static inline void*
mmap(void* addr, unsigned long len, int prot, int flags, int fd, unsigned long offset) {
  return (void*)__syscall(SYS_mmap, addr, len, prot, flags, fd, offset);
}


static inline int
munmap(void* addr, unsigned long len) {
  return (int)__syscall(SYS_munmap, addr, len);
}


static void*
memcpy(unsigned char* dst, const unsigned char* src, unsigned long len) {
  for(unsigned long i=0; i<len; i++) {
    dst[i] = src[i];
  }
  return dst;
}


static void
elfldr_exec(unsigned char* elf) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr*)elf;
  Elf64_Phdr *phdr = (Elf64_Phdr*)(elf + ehdr->e_phoff);
  Elf64_Shdr *shdr = (Elf64_Shdr*)(elf + ehdr->e_shoff);
  unsigned long min_vaddr = -1;
  unsigned long max_vaddr = 0;
  unsigned long img_size = 0;
  unsigned char* img = 0;
  void (*entry)(void);

  // Compute size of virtual memory region.
  for(int i=0; i<ehdr->e_phnum; i++) {
    if(phdr[i].p_vaddr < min_vaddr) {
      min_vaddr = phdr[i].p_vaddr;
    }

    if(max_vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
      max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
    }
  }

  min_vaddr = TRUNC_PG(min_vaddr);
  max_vaddr = ROUND_PG(max_vaddr);
  img_size  = max_vaddr-min_vaddr;

  // Reserve an address space of sufficient size.
  if((img=mmap(0, img_size, PROT_READ | PROT_WRITE | PROT_EXEC,
	       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
    return;
  }

  // Parse program headers.
  for(int i=0; i<ehdr->e_phnum; i++) {
    switch(phdr[i].p_type) {
    case PT_LOAD:
      if(phdr[i].p_memsz && phdr[i].p_filesz) {
	memcpy(img + phdr[i].p_vaddr, elf + phdr[i].p_offset, phdr[i].p_filesz);
      }
      break;
    }
  }

  // Apply relcations.
  for(int i=0; i<ehdr->e_shnum; i++) {
    if(shdr[i].sh_type != SHT_RELA) {
      continue;
    }

    Elf64_Rela* rela = (Elf64_Rela*)(elf + shdr[i].sh_offset);
    for(int j=0; j<shdr[i].sh_size/sizeof(Elf64_Rela); j++) {
      if((rela[j].r_info & 0xffffffffl) == R_X86_64_RELATIVE) {
	void* loc = (img + rela[j].r_offset);
	void* val = (img + rela[j].r_addend);
	memcpy(loc, (unsigned char*)&val, sizeof(val));
      }
    }
  }
;
  // invoke the payload
  entry = (void*)(img + ehdr->e_entry);
  entry();

  munmap(img, img_size);

}

/**
 * Dependencies provided by the ELF linker.
 **/
extern unsigned char __bss_start[] __attribute__((weak));
extern unsigned char __bss_end[] __attribute__((weak));



/**
 * Entry-point invoked by the BIN loader.
 **/
void
_start(void) {
  // clear .bss section
  for(unsigned char* bss=__bss_start; bss<__bss_end; bss++) {
    *bss = 0;
  }

  elfldr_exec(elfldr_elf);
}
