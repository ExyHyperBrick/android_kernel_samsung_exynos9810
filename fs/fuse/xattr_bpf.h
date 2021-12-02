/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _FS_FUSE_XATTR_BPF_H
#define _FS_FUSE_XATTR_BPF_H

#include <linux/limits.h>
#include <linux/xattr.h>

struct fuse_bpf_getxattr_io {
	struct fuse_getxattr_in in;
	struct fuse_getxattr_out out;
	char name[XATTR_NAME_MAX + 1];
	char original_name[XATTR_NAME_MAX + 1];
	void *value;
	size_t requested_size;
	ssize_t actual_ret;
	bool executed;
};

struct fuse_bpf_listxattr_io {
	struct fuse_getxattr_in in;
	struct fuse_getxattr_out out;
	void *list;
	size_t requested_size;
	ssize_t actual_ret;
	bool executed;
};

int fuse_bpf_getxattr_initialize(struct fuse_bpf_args *args,
				 struct fuse_bpf_getxattr_io *io,
				 struct dentry *entry, const char *name,
				 void *value, size_t size);
int fuse_bpf_getxattr_backing(struct fuse_bpf_args *args,
			      struct dentry *entry, const char *name,
			      void *value, size_t size);
void *fuse_bpf_getxattr_finalize(struct fuse_bpf_args *args,
				 struct dentry *entry, const char *name,
				 void *value, size_t size);

int fuse_bpf_listxattr_initialize(struct fuse_bpf_args *args,
				  struct fuse_bpf_listxattr_io *io,
				  struct dentry *entry, char *list,
				  size_t size);
int fuse_bpf_listxattr_backing(struct fuse_bpf_args *args,
			       struct dentry *entry, char *list,
			       size_t size);
void *fuse_bpf_listxattr_finalize(struct fuse_bpf_args *args,
				  struct dentry *entry, char *list,
				  size_t size);

struct fuse_bpf_setxattr_io {
	struct fuse_setxattr_in in;
	char name[XATTR_NAME_MAX + 1];
	void *value;
};

struct fuse_bpf_removexattr_io {
	char name[XATTR_NAME_MAX + 1];
};

int fuse_bpf_setxattr(struct dentry *entry, const char *name,
		      const void *value, size_t size, int flags);
int fuse_bpf_removexattr(struct dentry *entry, const char *name);

#endif
