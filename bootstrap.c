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

#include <ctype.h>
#include <elf.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ps4/kernel.h>

#include "elfldr.h"
#include "log.h"
#include "notify.h"

#include "socksrv_elf.c"

static int
my_hex_to_int(char c) {
  if(c >= '0' && c <= '9')
    return c - '0';
  if(c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  if(c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  return -1;
}

static uintptr_t
pattern_scan(const uintptr_t base, const uintptr_t base_size,
             const char *pattern) {
  if(!base || !base_size || !pattern)
    return 0;

  const uint8_t *memory = (const uint8_t *)base;
  const int pattern_len = strlen(pattern);

  int byte_count = 0;
  for(int i = 0; i < pattern_len; i++) {
    if(!isspace(pattern[i])) {
      if(pattern[i] == '?') {
        byte_count++;
        if(i + 1 < pattern_len && pattern[i + 1] == '?')
          i++;
      } else if(my_hex_to_int(pattern[i]) >= 0) {
        if(i + 1 < pattern_len && my_hex_to_int(pattern[i + 1]) >= 0)
          i++;
        byte_count++;
      }
    }
  }

  if(byte_count == 0 || (uintptr_t)byte_count > base_size)
    return 0;

  for(uintptr_t mem_offset = 0; mem_offset <= base_size - byte_count;
      mem_offset++) {
    int pattern_pos = 0;
    int byte_pos = 0;
    int match = 1;

    while(pattern_pos < pattern_len && byte_pos < byte_count && match) {
      while(pattern_pos < pattern_len && isspace(pattern[pattern_pos])) {
        pattern_pos++;
      }

      if(pattern_pos >= pattern_len)
        break;

      if(pattern[pattern_pos] == '?') {
        pattern_pos++;
        if(pattern_pos < pattern_len && pattern[pattern_pos] == '?') {
          pattern_pos++;
        }
        byte_pos++;
      } else if(my_hex_to_int(pattern[pattern_pos]) >= 0) {
        int high = my_hex_to_int(pattern[pattern_pos]);
        int low = 0;

        pattern_pos++;
        if(pattern_pos < pattern_len
           && my_hex_to_int(pattern[pattern_pos]) >= 0) {
          low = my_hex_to_int(pattern[pattern_pos]);
          pattern_pos++;
        } else {
          low = high;
          high = 0;
        }

        uint8_t expected_byte = (uint8_t)((high << 4) | low);
        if(memory[mem_offset + byte_pos] != expected_byte) {
          match = 0;
        }
        byte_pos++;
      } else {
        pattern_pos++;
      }
    }

    if(match && byte_pos == byte_count) {
      return base + mem_offset;
    }
  }

  return 0;
}

uintptr_t
pattern_scan_offset(const uintptr_t base, const uintptr_t base_size,
                    const char *pattern, const size_t ret_offset) {
  const uintptr_t r = pattern_scan(base, base_size, pattern);
  return r ? r + ret_offset : 0;
}

static ssize_t
kernel_get_image_size(void) {
  size_t min_vaddr = -1;
  size_t max_vaddr = 0;
  Elf64_Ehdr ehdr;
  Elf64_Phdr phdr;

  // copy out ELF header from kernel
  if(kernel_copyout(KERNEL_ADDRESS_IMAGE_BASE, &ehdr, sizeof(ehdr))) {
    perror("kernel_copyout");
    return -1;
  }

  if(ehdr.e_ident[0] != 0x7f || ehdr.e_ident[1] != 'E'
     || ehdr.e_ident[2] != 'L' || ehdr.e_ident[3] != 'F') {
    puts("not an ELF file");
    return -1;
  }

  // Compute size of virtual memory region.
  for(int i = 0; i < ehdr.e_phnum; i++) {
    if(kernel_copyout(KERNEL_ADDRESS_IMAGE_BASE + ehdr.e_phoff
                          + i * sizeof(Elf64_Phdr),
                      &phdr, sizeof(phdr))) {
      perror("kernel_copyout");
      return -1;
    }

    if(phdr.p_vaddr < min_vaddr) {
      min_vaddr = phdr.p_vaddr;
    }

    if(max_vaddr < phdr.p_vaddr + phdr.p_memsz) {
      max_vaddr = phdr.p_vaddr + phdr.p_memsz;
    }
  }

  return sizeof(ehdr) + ehdr.e_phnum * sizeof(phdr) + max_vaddr - min_vaddr;
}

static uintptr_t
kernel_chunk_scan(const char *pattern, const size_t offset_to_pattern) {
  uint8_t buf[0x4000];
  ssize_t imgsize;
  size_t len;

  if((imgsize = kernel_get_image_size()) < 0) {
    return 0;
  }

  for(size_t i = 0; i < imgsize; i += sizeof(buf)) {
    len = imgsize - i;
    if(len > sizeof(buf)) {
      len = sizeof(buf);
    }

    const uintptr_t kern_chunk = KERNEL_ADDRESS_IMAGE_BASE + i;
    if(kernel_copyout(kern_chunk, buf, len)) {
      perror("kernel_copyout");
      return 0;
    }
    const uintptr_t pBuf = (uintptr_t)buf;
    uintptr_t res
        = pattern_scan_offset(pBuf, sizeof(buf), pattern, offset_to_pattern);
    if(res) {
      return kern_chunk + (res - pBuf);
    }
  }
  return 0;
}

static int
touch(const char *path) {
  FILE *s_FilePointer = fopen(path, "w");
  if(!s_FilePointer) {
    return 1;
  }
  fclose(s_FilePointer);
  return 0;
}

static int
file_exists(const char *path) {
  if(access(path, F_OK) == 0) {
    return 0;
  }
  return 1;
}

/**
 * Entry point to the payload.
 **/
int
main(void) {
  unsigned int fw = kernel_get_fw_version();
  char *enable_ptrace_patch1 = 0;
  size_t offset_to_nop = 0;
  uint8_t qaflags[16];

  switch(fw & 0xffff0000) {
    case 0x5050000:
    case 0x5500000:
    case 0x5550000:
    case 0x5560000:
    case 0x6000000:
    case 0x6200000:
    case 0x6500000:
    case 0x6510000:
    case 0x6700000:
    case 0x6710000:
    case 0x6720000:
      enable_ptrace_patch1 = "48 b8 36 10 00 00 7e 02 00 00 ? ? ? ? ? ? ? ? ? "
                             "? ? ? ? 0f 84 ? ? ? ?";
      offset_to_nop = 23;
      break;
    case 0x7000000:
    case 0x7020000:
    case 0x7500000:
    case 0x7510000:
    case 0x7550000:
    case 0x8000000:
    case 0x8010000:
    case 0x8030000:
    case 0x8500000:
    case 0x8520000:
    case 0x9000000:
    case 0x9030000:
    case 0x9040000:
    case 0x9500000:
    case 0x9510000:
    case 0x9600000:
    case 0x10000000:
    case 0x10010000:
    case 0x10500000:
    case 0x10700000:
    case 0x10710000:
    case 0x11000000:
    case 0x11020000:
    case 0x11500000:
    case 0x11520000:
    case 0x12000000:
    case 0x12020000:
    case 0x12500000:
    case 0x12520000:
      enable_ptrace_patch1 = "48 b8 36 10 00 00 7e 02 00 00 4c 0f a3 e0 0f 83 "
                             "? ? ? ? 85 db 0f 84 ? ? ? ?";
      offset_to_nop = 22;
      break;

    default:
      LOG_PRINTF("Unsupported firmware (0x%x)\n", fw);
      notify("Unsupported firmware (0x%x)\n", fw);
      return -1;
  }

  notify("Bootstrapping elfldr.elf...");
  LOG_PUTS("Bootstrapping elfldr.elf...");

  signal(SIGCHLD, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);

  if(kernel_get_qaflags(qaflags)) {
    LOG_PERROR("kernel_get_qaflags");
    return -1;
  }

  qaflags[1] |= 3;
  if(kernel_set_qaflags(qaflags)) {
    LOG_PERROR("kernel_set_qaflags");
    return -1;
  }

  static const char ptrace_patch_check[] = "/user/temp/elfldr.pt.check";
  const int file_check_r = file_exists(ptrace_patch_check);
  if(file_check_r) {
    const uintptr_t kbase = KERNEL_ADDRESS_IMAGE_BASE;
    const size_t ksize = kernel_get_image_size();
    const uintptr_t patternRes
        = kernel_chunk_scan(enable_ptrace_patch1, offset_to_nop);
    if(patternRes) {
      static const uint8_t nop6x[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
      LOG_PRINTF("kbase : 0x%lx ksize %lu bytes\n"
                 "pattern found 0x%lx offset 0x%lx\n",
                 kbase, ksize, patternRes, patternRes - kbase);
      // apply patch
      if((kernel_copyin(nop6x, patternRes, sizeof(nop6x)))) {
        notify("failed to write ptrace patch!");
        return -1;
      }
      touch(ptrace_patch_check);
      notify("ptrace patched for elfldr");
    }
  } else if(file_check_r == 0) {
    LOG_PUTS("ptrace already patched");
  }
  return elfldr_spawn("elfldr.elf", -1, socksrv_elf);
}
