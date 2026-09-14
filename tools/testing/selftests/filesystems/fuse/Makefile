# SPDX-License-Identifier: GPL-2.0
CFLAGS += -O2 -g -Wall -Wextra
KHDR_INCLUDES ?= -I../../../../../usr/include
CPPFLAGS += $(KHDR_INCLUDES)

TEST_PROGS_EXTENDED := backing-casefold
TEST_FILES := README

all: $(TEST_PROGS_EXTENDED)

include ../../lib.mk

clean:
	$(RM) $(TEST_PROGS_EXTENDED)
