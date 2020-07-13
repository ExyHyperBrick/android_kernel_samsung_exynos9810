# SPDX-License-Identifier: GPL-2.0-only
OUTPUT ?= $(CURDIR)/
HOSTCC ?= cc
HOSTCFLAGS ?= -O2 -g

BINARY := $(OUTPUT)resolve_btfids

all: $(BINARY)

$(BINARY): main.c
	@mkdir -p $(OUTPUT)
	$(HOSTCC) $(HOSTCFLAGS) -std=gnu99 -Wall -Wextra -o $@ $<

clean:
	$(RM) $(BINARY)

.PHONY: all clean
