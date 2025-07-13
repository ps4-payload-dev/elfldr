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

#include <elf.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <ps4/klog.h>

#include "log.h"
#include "selfldr.h"

static int
rdup(pid_t pid, int fd) {
  int err;

  if((err = syscall(0x25b, pid, fd)) < 0) {
    errno = -err;
    return -1;
  }

  return err;
}

/**
 *
 **/
int
selfldr_sanity_check(uint8_t *self, size_t self_size) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)self;

  if(self_size < sizeof(Elf64_Ehdr)) {
    return -1;
  }

  if(ehdr->e_ident[0] != 0x4f || ehdr->e_ident[1] != 0x15
     || ehdr->e_ident[2] != 0x3d || ehdr->e_ident[3] != 0x1d) {
    return -1;
  }

  return 0;
}

typedef struct self_spawn_args {
  int stdio;
  uint8_t *self;
  size_t self_size;
} self_spawn_args_t;

/**
 *
 **/
static int
selfldr_rfork_entry(void *ctx) {
  self_spawn_args_t *args = (self_spawn_args_t *)ctx;
  char path[PATH_MAX];
  char *const argv[] = { path, 0 };
  pid_t ppid = getppid();
  int fd;

  if(syscall(0x23b, 0)) {
    LOG_PERROR("sys_budget_set");
    return 0;
  }

  sprintf(path, "/user/temp/patload_%d.self", getpid());

  if(rdup(ppid, args->stdio) < 0) {
    LOG_PERROR("rdup");
    return 0;
  }
  if(rdup(ppid, args->stdio) < 0) {
    LOG_PERROR("rdup");
    return 0;
  }
  if(rdup(ppid, args->stdio) < 0) {
    LOG_PERROR("rdup");
    return 0;
  }

  if((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755)) < 0) {
    LOG_PERROR("open");
    return 0;
  }

  if(write(fd, args->self, args->self_size) != args->self_size) {
    LOG_PERROR("write");
    return 0;
  }

  close(fd);

  execve(path, argv, 0);

  LOG_PERROR("execve");
  return 0;
}

pid_t
selfldr_spawn(int stdio, uint8_t *self, size_t self_size) {
  self_spawn_args_t args = { stdio, self, self_size };
  struct kevent evt;
  void *stack;
  pid_t pid;
  int kq;

  if((kq = kqueue()) < 0) {
    LOG_PERROR("kqueue");
    return -1;
  }

  if(!(stack = malloc(PAGE_SIZE))) {
    LOG_PERROR("malloc");
    close(kq);
    return -1;
  }

  if((pid = rfork_thread(RFPROC | RFCFDG | RFMEM, stack + PAGE_SIZE - 8,
                         selfldr_rfork_entry, &args))
     < 0) {
    LOG_PERROR("rfork_thread");
    free(stack);
    close(kq);
    return -1;
  }

  EV_SET(&evt, pid, EVFILT_PROC, EV_ADD, NOTE_EXEC | NOTE_EXIT, 0, 0);
  if(kevent(kq, &evt, 1, &evt, 1, 0) < 0) {
    LOG_PERROR("kevent");
    free(stack);
    close(kq);
    return -1;
  }

  free(stack);
  close(kq);

  return pid;
}
