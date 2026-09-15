CFLAGS += -O2 -Wall -Wextra
TEST_PROGS := binder_freezer

all: $(TEST_PROGS)

binder_freezer: binder_freezer.c ../../../../include/uapi/linux/android/binder.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	$(RM) $(TEST_PROGS)

include ../lib.mk
