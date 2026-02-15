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

CFLAGS := -fPIC -Wall -Werror -g -mstackrealign

SRCS := $(wildcard *.c)
SRCS += $(wildcard *.h)

all: $(ELF) $(BIN)

socksrv.elf: socksrv.c elfldr.c pt.c uri.c selfldr.c notify.c
	$(CC) $(CFLAGS) -lSceSsl2 -lSceHttp2 $^ -o $@

bootstrap-elf.c: socksrv_elf.c

socksrv_elf.c: socksrv.elf
	xxd -i $^ > $@

elfldr_elf.c: $(ELF)
	xxd -i $^ > $@

$(ELF): bootstrap-elf.c elfldr.c pt.c notify.c
	$(CC) $(CFLAGS) $^ -o $@

bootstrap-bin.o: elfldr_elf.c

$(BIN): bootstrap-bin.o
	$(LD) -T bin_x86_64.x -o $@ $<
	$(OBJCOPY) -O binary --only-section=.text $@

clean:
	-rm -f *.o *.elf *.bin socksrv_elf.c elfldr_elf.c

test: $(ELF)
	$(PS4_DEPLOY) -h $(PS4_HOST) -p $(PS4_PORT) $^

format: $(SRCS)
	clang-format -i $^
