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
  uint8_t qaflags[16];

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

  // ptrace (FW 9.00, allow req < 0x2b)
  kernel_patch(KERNEL_ADDRESS_IMAGE_BASE + 0x41f4fd,
	       "\x0f\x84\x19\x02\x00\x00\x4c\x8b",
	       "\x90\x90\x90\x90\x90\x90\x4c\x8b", 8);

  return elfldr_spawn("elfldr.elf", -1, socksrv_elf);
}

