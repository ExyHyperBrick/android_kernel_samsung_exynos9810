# Makefile for vm selftests

ifndef OUTPUT
  OUTPUT := $(shell pwd)
endif

CFLAGS = -Wall -I ../../../../usr/include $(EXTRA_CFLAGS)
BINARIES = compaction_test
BINARIES += hugepage-mmap
BINARIES += hugepage-shm
BINARIES += map_hugetlb
BINARIES += mlock2-tests
BINARIES += on-fault-limit
BINARIES += thuge-gen
BINARIES += transhuge-stress
BINARIES += userfaultfd
BINARIES += uffd-art
BINARIES += userfaultfd_hugetlb
BINARIES += userfaultfd_shmem
BINARIES += mlock-random-test
BINARIES += process_madvise
BINARIES += process_mrelease

all: $(BINARIES)
%: %.c
	$(CC) $(CFLAGS) -o $@ $^ -lrt
process_mrelease: process_mrelease.c
	$(CC) $(CFLAGS) -O2 -o $@ $< -pthread
uffd-art: uffd-art.c ../../../../usr/include/linux/kernel.h
	$(CC) $(CFLAGS) -O2 -o $@ $< -lpthread

userfaultfd: userfaultfd.c ../../../../usr/include/linux/kernel.h
	$(CC) $(CFLAGS) -O2 -o $@ $< -lpthread

userfaultfd_hugetlb: userfaultfd.c ../../../../usr/include/linux/kernel.h
	$(CC) $(CFLAGS) -DHUGETLB_TEST -O2 -o $@ $< -lpthread

userfaultfd_shmem: userfaultfd.c ../../../../usr/include/linux/kernel.h
	$(CC) $(CFLAGS) -DSHMEM_TEST -O2 -o $@ $< -lpthread

mlock-random-test: mlock-random-test.c
	$(CC) $(CFLAGS) -o $@ $< -lcap

../../../../usr/include/linux/kernel.h:
	make -C ../../../.. headers_install

TEST_PROGS := run_vmtests process_mrelease
TEST_FILES := $(BINARIES)

include ../lib.mk

clean:
	$(RM) $(BINARIES)
