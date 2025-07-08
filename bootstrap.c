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

#include <signal.h>
#include <stdint.h>

#include <ps4/kernel.h>

#include "elfldr.h"
#include "log.h"
#include "notify.h"

#include "socksrv_elf.c"


/**
 * Entry point to the payload.
 **/
int main() {
  unsigned int fw = kernel_get_fw_version();
  unsigned int enable_ptrace_patch1 = 0;
  uint8_t qaflags[16];

  switch(fw & 0xffff0000) {
  case 0x5050000:
    enable_ptrace_patch1 = 0x030D9C3;
    break;

  case 0x6720000:
    enable_ptrace_patch1 = 0x0010F892;
    break;

  case 0x7000000:
  case 0x7020000:
    enable_ptrace_patch1 = 0x000448ED;
    break;

  case 0x7500000:
  case 0x7510000:
  case 0x7550000:
    enable_ptrace_patch1 = 0x00361D0D;
    break;

  case 0x8000000:
  case 0x8010000:
  case 0x8030000:
    enable_ptrace_patch1 = 0x0017416D;
    break;

  case 0x8500000:
  case 0x8520000:
    enable_ptrace_patch1 = 0x0013254D;
    break;

  case 0x9000000:
    enable_ptrace_patch1 = 0x0041F4FD;
    break;

  case 0x9030000:
  case 0x9040000:
    enable_ptrace_patch1 = 0x0041D46D;
    break;

  case 0x9500000:
  case 0x9510000:
    enable_ptrace_patch1 = 0x0047A01D;
    break;

  case 0x9600000:
    enable_ptrace_patch1 = 0x0047A01D;
    break;

  case 0x10000000:
  case 0x10010000:
    enable_ptrace_patch1 = 0x0044E63D;
    break;

  case 0x10500000:
  case 0x10700000:
  case 0x10710000:
    enable_ptrace_patch1 = 0x00424E9D;
    break;

  case 0x11000000:
    enable_ptrace_patch1 = 0x0038429D;
    break;

  case 0x11020000:
    enable_ptrace_patch1 = 0x003842BD;
    break;

  case 0x11500000:
  case 0x11520000:
    enable_ptrace_patch1 = 0x0036675D;
    break;

  case 0x12000000:
  case 0x12020000:
    enable_ptrace_patch1 = 0x0036699d;
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


  // ptrace (allow req < 0x2b)
  kernel_patch(KERNEL_ADDRESS_IMAGE_BASE + enable_ptrace_patch1,
	       "\x0f\x84\x19\x02\x00\x00\x4c\x8b",
	       "\x90\x90\x90\x90\x90\x90\x4c\x8b", 8);

  return elfldr_spawn("elfldr.elf", -1, socksrv_elf);
}

