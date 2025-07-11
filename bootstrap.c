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
#include <stdlib.h>
#include <string.h>

#include <ps4/kernel.h>

#include "elfldr.h"
#include "log.h"
#include "notify.h"

#include "socksrv_elf.c"

/**
 * Entry point to the payload.
 **/
int
main(void) {
  unsigned int fw = kernel_get_fw_version();
  intptr_t ptrace_patch = 0; // (req < 0x2b)
  uint8_t qaflags[16];

  LOG_PUTS("Bootstrapping elfldr.elf...");

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
      if((ptrace_patch
          = kernel_find_pattern(KERNEL_ADDRESS_IMAGE_BASE, KERNEL_IMAGE_SIZE,
                                "48b8361000007e020000?????????????????????????"
                                "?0f84190200004c8b"))) {
        ptrace_patch += 23;
      }
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
      if((ptrace_patch
          = kernel_find_pattern(KERNEL_ADDRESS_IMAGE_BASE, KERNEL_IMAGE_SIZE,
                                "48b8361000007e020000????????????????????????"
                                "0f84190200004c8b"))) {
        ptrace_patch += 22;
      }
      break;

    default:
      notify("Unsupported firmware (0x%x)\n", fw);
      return -1;
  }

  if(kernel_get_qaflags(qaflags)) {
    LOG_PERROR("kernel_get_qaflags");
    return -1;
  }

  qaflags[1] |= 3;
  if(kernel_set_qaflags(qaflags)) {
    LOG_PERROR("kernel_set_qaflags");
    return -1;
  }

  if(ptrace_patch) {
    LOG_PRINTF("pathing kernel at 0x%lx (ptrace)\n", ptrace_patch);
    kernel_patch(ptrace_patch, "\x0f\x84\x19\x02\x00\x00",
                 "\x90\x90\x90\x90\x90\x90", 6);
  }

  signal(SIGCHLD, SIG_IGN);
  return elfldr_spawn("elfldr.elf", -1, socksrv_elf);
}
