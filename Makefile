#   Copyright (C) 2025 John Törnblom
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not see
# <http://www.gnu.org/licenses/>.

PS4_HOST ?= ps4
PS4_PORT ?= 9020

ifdef PS4_PAYLOAD_SDK
    include $(PS4_PAYLOAD_SDK)/toolchain/orbis.mk
else
    $(error PS4_PAYLOAD_SDK is undefined)
endif

ELF  := elfldr.elf
BIN  := elfldr.bin

CFLAGS := -fPIC -Wall -Werror -g

all: $(ELF) $(BIN)

$(ELF): socksrv.c elfldr.c pt.c
	$(CC) $(CFLAGS) $^ -o $@

elfldr_elf.c: elfldr.elf
	xxd -i $^ > $@

bootstrap.o: bootstrap.c elfldr_elf.c
	$(CC) $(CFLAGS) -c -target x86_64-none-elf -ffreestanding -fno-builtin -nostdlib $< -o $@

bootstrap.elf: bootstrap.o
	ld.lld -T elf_x86_64-binldr.x -pie $^ -o $@

$(BIN): bootstrap.elf
	llvm-objcopy -O binary --only-section=.text $< $@

clean:
	-rm -f *.o *.elf *.bin elfldr_elf.c

test: $(ELF)
	$(PS4_DEPLOY) -h $(PS4_HOST) -p $(PS4_PORT) $^

