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

#define MAP_PRIVATE 0x0002
#define MAP_ANONYMOUS 0x1000
#define MAP_FAILED ((void *)-1)

#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4

#define PAGE_SIZE 0x4000
#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_SIZE - 1))

#define PT_LOAD 1
#define R_X86_64_RELATIVE 8
#define SHT_RELA 4

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
  unsigned long r_offset;
  unsigned long r_info;
  long r_addend;
} Elf64_Rela;

extern unsigned char __bss_start[] __attribute__((weak));
extern unsigned char __bss_end[] __attribute__((weak));

static void *
memcpy(void *dest, const void *src, unsigned long n) {
  asm __volatile__("rep movsb" : "+D"(dest), "+S"(src), "+c"(n) : : "memory");
  return dest;
}

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
  register long r8 __asm__("r8") = a5;
  register long r9 __asm__("r9") = a6;

  __asm__ __volatile__("syscall"
                       : "=a"(ret), "=@ccc"(iserror), "+r"(r10), "+r"(r8),
                         "+r"(r9)
                       : "a"(n), "D"(a1), "S"(a2), "d"(a3)
                       : "rcx", "r11", "memory");

  return iserror ? -ret : ret;
}

static inline void *
mmap(void *addr, unsigned long len, int prot, int flags, int fd,
     unsigned long offset) {
  return (void *)__syscall(477, addr, len, prot, flags, fd, offset);
}

static inline int
munmap(void *addr, unsigned long len) {
  return (int)__syscall(73, addr, len);
}

static void
elfldr_exec(unsigned char *elf) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf;
  Elf64_Phdr *phdr = (Elf64_Phdr *)(elf + ehdr->e_phoff);
  Elf64_Shdr *shdr = (Elf64_Shdr *)(elf + ehdr->e_shoff);
  unsigned long min_vaddr = -1;
  unsigned long max_vaddr = 0;
  unsigned long img_size = 0;
  unsigned char *img = 0;
  void (*entry)(void);

  // Sanity check, we only support ELF files.
  if(ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E'
     || ehdr->e_ident[2] != 'L' || ehdr->e_ident[3] != 'F') {
    return;
  }

  // Compute size of virtual memory region.
  for(int i = 0; i < ehdr->e_phnum; i++) {
    if(phdr[i].p_vaddr < min_vaddr) {
      min_vaddr = phdr[i].p_vaddr;
    }

    if(max_vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
      max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
    }
  }

  min_vaddr = TRUNC_PG(min_vaddr);
  max_vaddr = ROUND_PG(max_vaddr);
  img_size = max_vaddr - min_vaddr;

  // Reserve an address space of sufficient size.
  if((img = mmap(0, img_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0))
     == MAP_FAILED) {
    return;
  }

  // Parse program headers.
  for(int i = 0; i < ehdr->e_phnum; i++) {
    switch(phdr[i].p_type) {
      case PT_LOAD:
        if(phdr[i].p_memsz && phdr[i].p_filesz) {
          memcpy(img + phdr[i].p_vaddr, elf + phdr[i].p_offset,
                 phdr[i].p_filesz);
        }
        break;
    }
  }

  // Apply relcations.
  for(int i = 0; i < ehdr->e_shnum; i++) {
    if(shdr[i].sh_type != SHT_RELA) {
      continue;
    }

    Elf64_Rela *rela = (Elf64_Rela *)(elf + shdr[i].sh_offset);
    for(int j = 0; j < shdr[i].sh_size / sizeof(Elf64_Rela); j++) {
      if((rela[j].r_info & 0xffffffffl) == R_X86_64_RELATIVE) {
        void *loc = (img + rela[j].r_offset);
        void *val = (img + rela[j].r_addend);
        memcpy(loc, &val, sizeof(val));
      }
    }
  }

  entry = (void *)(img + ehdr->e_entry);
  entry();

  munmap(img, img_size);
}

int
_start(void) {
  elfldr_exec(elfldr_elf);
  return 0;
}
