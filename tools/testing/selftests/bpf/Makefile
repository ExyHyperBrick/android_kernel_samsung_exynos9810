LIBDIR := ../../../lib
BPFDIR := $(LIBDIR)/bpf

CFLAGS += -Wall -O2 -I../../../include/uapi -I$(LIBDIR)
LDLIBS += -lcap

test_objs = test_verifier test_maps test_lru_map

test_objs = test_verifier test_maps test_lru_map test_lpm_map

TEST_PROGS := $(test_objs) test_kmod.sh
TEST_FILES := $(test_objs)

all: $(test_objs)

include ../lib.mk

BPFOBJ := $(OUTPUT)/bpf.o

$(TEST_GEN_PROGS): $(BPFOBJ)

.PHONY: force

# force a rebuild of BPFOBJ when its dependencies are updated
force:

$(BPFOBJ): force
	$(MAKE) -C $(BPFDIR) OUTPUT=$(OUTPUT)/

clean:
	$(RM) $(test_objs)
