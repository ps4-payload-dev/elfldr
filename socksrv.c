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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include <sys/socket.h>

#include <ps4/kernel.h>

#include "elfldr.h"
#include "log.h"


/**
 * Read an ELF file from the given file descriptor.
 **/
static size_t
readsock(int fd, uint8_t** elf) {
  uint8_t buf[0x4000];
  uint8_t* data = 0;
  uint8_t* bak = 0;
  off_t offset = 0;
  ssize_t len;

  while((len=read(fd, buf, sizeof(buf))) > 0) {
    bak = data;
    if(!(data=realloc(data, offset+len+1))) {
      LOG_PERROR("realloc");
      if(bak) {
        free(bak);
      }
      return 0;
    }

    memcpy(data + offset, buf, len);
    offset += len;
  }

  if(len < 0) {
    LOG_PERROR("read");
    free(data);
    return 0;
  }

  if(offset) {
    data[offset] = 0;
    *elf = data;
  }

  return offset;
}


/**
 * Process connections in induvidual threads.
 **/
static void
on_connection(int fd) {
  int optval = 1;
  uint8_t* elf;
  size_t len;

  if(setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &optval, sizeof(optval)) < 0) {
    return;
  }

  if(!(len=readsock(fd, &elf))) {
    return;
  }

  if(elfldr_sanity_check(elf, len)) {
    write(fd, "Malformed ELF file\n\r\0", 34);
  } else {
    elfldr_spawn("payload.elf", fd, elf);
  }

  free(elf);
}


/**
 * Serve an ELF loader via a TCP socket on the given port.
 **/
static int
serve_elfldr(uint16_t port) {
  struct sockaddr_in srvaddr;
  struct sockaddr_in cliaddr;
  socklen_t socklen;
  int connfd;
  int srvfd;

  if((srvfd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    LOG_PERROR("socket");
    return -1;
  }

  if(setsockopt(srvfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
    LOG_PERROR("setsockopt");
    return -1;
  }

  memset(&srvaddr, 0, sizeof(srvaddr));
  srvaddr.sin_family = AF_INET;
  srvaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  srvaddr.sin_port = htons(port);

  if(bind(srvfd, (struct sockaddr*)&srvaddr, sizeof(srvaddr)) != 0) {
    LOG_PERROR("bind");
    return -1;
  }

  if(listen(srvfd, 5) != 0) {
    LOG_PERROR("listen");
    return -1;
  }

  while(1) {
    socklen = sizeof(cliaddr);
    if((connfd=accept(srvfd, (struct sockaddr*)&cliaddr, &socklen)) < 0) {
      LOG_PERROR("accept");
      break;
    }

    on_connection(connfd);
    close(connfd);
  }

  return close(srvfd);
}


/**
 * Entry point to the payload.
 **/
int main() {
  uint8_t qaflags[16];
  int port = 9021;

  signal(SIGCHLD, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);

  if(kernel_get_qaflags(qaflags)) {
    perror("kernel_get_qaflags");
    return -1;
  }

  qaflags[1] |= 3;
  if(kernel_set_qaflags(qaflags)) {
    perror("kernel_set_qaflags");
    return -1;
  }

  // ptrace (FW 9.00, allow req < 0x2b)
  kernel_patch(KERNEL_ADDRESS_IMAGE_BASE + 0x41f4fd,
	       "\x0f\x84\x19\x02\x00\x00\x4c\x8b",
	       "\x90\x90\x90\x90\x90\x90\x4c\x8b", 8);

  return serve_elfldr(port);
}


