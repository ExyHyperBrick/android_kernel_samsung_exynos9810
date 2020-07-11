# SPDX-License-Identifier: GPL-2.0-only
OUTPUT ?= $(CURDIR)/
HOSTCC ?= cc
HOSTCFLAGS ?= -O2 -g

srctree := $(abspath ../../..)
BINARY := $(OUTPUT)resolve_btfids
BTF_SRC := $(srctree)/tools/lib/bpf/btf.c
INCLUDES := -I$(srctree)/tools/include \
	-I$(srctree)/tools/include/uapi \
	-I$(srctree)/tools/lib/bpf

all: $(BINARY)

$(BINARY): main.c $(BTF_SRC) $(srctree)/tools/lib/bpf/btf.h
	@mkdir -p $(OUTPUT)
	$(HOSTCC) $(HOSTCFLAGS) -DBTF_NO_LIBELF -std=gnu99 \
		-Wall -Wextra $(INCLUDES) -o $@ main.c $(BTF_SRC)

clean:
	$(RM) $(BINARY)

.PHONY: all clean
