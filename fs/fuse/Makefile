#
# Makefile for the FUSE filesystem.
#

obj-$(CONFIG_FUSE_FS) += fuse.o
obj-$(CONFIG_CUSE) += cuse.o

fuse-y := dev.o dir.o file.o inode.o control.o xattr.o acl.o
fuse-$(CONFIG_FUSE_BPF) += backing.o
