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

#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include <ps4/kernel.h>

#include "pt.h"


int
pt_attach(pid_t pid) {
  if(ptrace(PT_ATTACH, pid, 0, 0) == -1) {
    return -1;
  }

  if(waitpid(pid, 0, 0) == -1) {
    return -1;
  }

  return 0;
}


int
pt_detach(pid_t pid, int sig) {
  if(ptrace(PT_DETACH, pid, 0, sig) == -1) {
    return -1;
  }

  return 0;
}

int
pt_step(pid_t pid) {
  if(ptrace(PT_STEP, pid, (caddr_t)1, 0)) {
    return -1;
  }

  if(waitpid(pid, 0, 0) < 0) {
    return -1;
  }

  return 0;
}


int
pt_continue(pid_t pid, int sig) {
  if(ptrace(PT_CONTINUE, pid, (caddr_t)1, sig) == -1) {
    return -1;
  }

  return 0;
}


int
pt_getregs(pid_t pid, struct reg *r) {
  return ptrace(PT_GETREGS, pid, (caddr_t)r, 0);
}


int
pt_setregs(pid_t pid, const struct reg *r) {
  return ptrace(PT_SETREGS, pid, (caddr_t)r, 0);
}


int
pt_copyin(pid_t pid, const void* buf, intptr_t addr, size_t len) {
  struct ptrace_io_desc iod = {
    .piod_op = PIOD_WRITE_D,
    .piod_offs = (void*)addr,
    .piod_addr = (void*)buf,
    .piod_len = len};
  return ptrace(PT_IO, pid, (caddr_t)&iod, 0);
}


int
pt_copyout(pid_t pid, intptr_t addr, void* buf, size_t len) {
  struct ptrace_io_desc iod = {
    .piod_op = PIOD_READ_D,
    .piod_offs = (void*)addr,
    .piod_addr = buf,
    .piod_len = len};
  return ptrace(PT_IO, pid, (caddr_t)&iod, 0);
}


long
pt_syscall(pid_t pid, int sysno, ...) {
  uint16_t sysc_instr = 0x050f;
  struct reg sysc_reg;
  uint16_t bak_instr;
  struct reg bak_reg;
  va_list ap;

  if(pt_getregs(pid, &bak_reg)) {
    return -1;
  }

  if(pt_copyout(pid, bak_reg.r_rip, &bak_instr, sizeof(bak_instr))) {
    return -1;
  }

  memcpy(&sysc_reg, &bak_reg, sizeof(sysc_reg));
  sysc_reg.r_rax = sysno;

  va_start(ap, sysno);
  sysc_reg.r_rdi = va_arg(ap, uint64_t);
  sysc_reg.r_rsi = va_arg(ap, uint64_t);
  sysc_reg.r_rdx = va_arg(ap, uint64_t);
  sysc_reg.r_r10 = va_arg(ap, uint64_t);
  sysc_reg.r_r8  = va_arg(ap, uint64_t);
  sysc_reg.r_r9  = va_arg(ap, uint64_t);
  va_end(ap);

  if(pt_setregs(pid, &sysc_reg)) {
    return -1;
  }
  
  if(pt_copyin(pid, &sysc_instr, sysc_reg.r_rip, sizeof(sysc_instr))) {
    return -1;
  }

  if(pt_step(pid)) {
    return -1;
  }
  if(pt_getregs(pid, &sysc_reg)) {
    return -1;
  }

  if(pt_setregs(pid, &bak_reg)) {
    return -1;
  }
  if(pt_copyin(pid, &bak_instr, bak_reg.r_rip, sizeof(bak_instr))) {
    return -1;
  }

  return sysc_reg.r_rax;
}


intptr_t
pt_mmap(pid_t pid, intptr_t addr, size_t len, int prot, int flags,
	int fd, off_t off) {
  return pt_syscall(pid, SYS_mmap, addr, len, prot, flags, fd, off);
}


int
pt_mprotect(pid_t pid, intptr_t addr, size_t len, int prot) {
  return pt_syscall(pid, SYS_mprotect, addr, len, prot);
}


int
pt_msync(pid_t pid, intptr_t addr, size_t len, int flags) {
  return pt_syscall(pid, SYS_msync, addr, len, flags);
}


int
pt_munmap(pid_t pid, intptr_t addr, size_t len) {
  return pt_syscall(pid, SYS_munmap, addr, len);
}


int
pt_close(pid_t pid, int fd) {
  return (int)pt_syscall(pid, SYS_close, fd);
}


int
pt_dup2(pid_t pid, int oldfd, int newfd) {
  return (int)pt_syscall(pid, SYS_dup2, oldfd, newfd);
}


int
pt_rdup(pid_t pid, pid_t other_pid, int fd) {
  return (int)pt_syscall(pid, 0x25b, other_pid, fd);
}
