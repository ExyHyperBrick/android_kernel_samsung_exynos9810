// SPDX-License-Identifier: GPL-2.0
/*
 * FUSE-BPF read-only extended attribute routing
 * Copyright (c) 2021 Google LLC
 */

#include "fuse_i.h"
#include "xattr_bpf.h"

#include <linux/errno.h>
#include <linux/string.h>
#include <linux/xattr.h>

static void *fuse_bpf_xattr_end(void *value, size_t size)
{
	unsigned long start = (unsigned long)value;
	unsigned long end;

	if (!value)
		return NULL;
	end = start + size;
	return end < start ? NULL : (void *)end;
}

static int fuse_bpf_xattr_path(struct inode *inode, struct dentry *entry,
			       struct path *path)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct inode *backing_inode;

	*path = (struct path) { };
	if (!entry || d_inode(entry) != inode)
		return -ESTALE;
	if (!get_fuse_backing_path(entry, path))
		return -EBADF;

	backing_inode = d_inode(path->dentry);
	if (!fi->backing_inode || !fi->backing_mnt || !backing_inode ||
	    backing_inode != fi->backing_inode ||
	    path->mnt != fi->backing_mnt ||
	    ((inode->i_mode ^ backing_inode->i_mode) & S_IFMT)) {
		fuse_put_backing_path(path);
		return -ESTALE;
	}
	return 0;
}

static int fuse_bpf_xattr_name(const char *name, size_t *length)
{
	size_t len;

	if (!name)
		return -EINVAL;
	len = strnlen(name, XATTR_NAME_MAX + 1);
	if (!len || len > XATTR_NAME_MAX)
		return -ERANGE;
	*length = len;
	return 0;
}

static int fuse_bpf_verify_xattr_list(const char *list, size_t size)
{
	size_t remaining = size;

	while (remaining) {
		size_t len = strnlen(list, remaining);

		if (!len || len == remaining)
			return -EIO;
		list += len + 1;
		remaining -= len + 1;
	}
	return 0;
}

int fuse_bpf_getxattr_initialize(struct fuse_bpf_args *args,
				 struct fuse_bpf_getxattr_io *io,
				 struct dentry *entry, const char *name,
				 void *value, size_t size)
{
	struct inode *inode = d_inode(entry);
	size_t name_len;
	int ret;

	ret = fuse_bpf_xattr_name(name, &name_len);
	if (ret)
		return ret;
	if (size > XATTR_SIZE_MAX || (size && !value))
		return -E2BIG;

	memset(io, 0, sizeof(*io));
	memcpy(io->name, name, name_len + 1);
	memcpy(io->original_name, name, name_len + 1);
	io->in.size = size;
	io->value = value;
	io->requested_size = size;
	io->actual_ret = -EINPROGRESS;

	*args = (struct fuse_bpf_args) {
		.nodeid = get_node_id(inode),
		.opcode = FUSE_GETXATTR,
		.in_numargs = 2,
		.out_numargs = 1,
		.flags = size ? FUSE_BPF_OUT_ARGVAR : 0,
		.in_args[0] = (struct fuse_bpf_in_arg) {
			.size = sizeof(io->in),
			.value = &io->in,
		},
		.in_args[1] = (struct fuse_bpf_in_arg) {
			.size = name_len + 1,
			.value = io->name,
		},
		.out_args[0] = (struct fuse_bpf_arg) {
			.size = size ? size : sizeof(io->out),
			.value = size ? value : &io->out,
		},
	};
	return 0;
}

static int fuse_bpf_getxattr_validate(struct fuse_bpf_args *args,
				      struct fuse_bpf_getxattr_io *io,
				      struct inode *inode)
{
	size_t name_len = strlen(io->original_name);
	u32 expected_in;

	if (args->opcode == FUSE_GETXATTR)
		expected_in = 2;
	else if (args->opcode == (FUSE_GETXATTR | FUSE_POSTFILTER))
		expected_in = 3;
	else
		return -EIO;
	if (args->nodeid != get_node_id(inode) ||
	    args->flags != (io->requested_size ?
			    FUSE_BPF_OUT_ARGVAR : 0) ||
	    args->in_numargs != expected_in ||
	    args->out_numargs != 1 ||
	    !args->in_args[0].value || !args->in_args[1].value ||
	    !args->out_args[0].value ||
	    args->in_args[0].size != sizeof(io->in) ||
	    args->in_args[0].value != &io->in ||
	    args->in_args[1].size != name_len + 1 ||
	    args->in_args[1].value != io->name ||
	    memcmp(io->name, io->original_name, name_len + 1) ||
	    io->in.padding || io->in.size != io->requested_size)
		return -EIO;
	if (io->requested_size) {
		if (args->out_args[0].value != io->value ||
		    args->out_args[0].size > io->requested_size)
			return -EIO;
	} else if (args->out_args[0].value != &io->out ||
		   args->out_args[0].size != sizeof(io->out)) {
		return -EIO;
	}
	if (expected_in == 3 &&
	    (!args->in_args[2].value ||
	     args->in_args[2].value != args->out_args[0].value ||
	     args->in_args[2].size != args->out_args[0].size))
		return -EIO;
	return 0;
}

int fuse_bpf_getxattr_backing(struct fuse_bpf_args *args,
			      struct dentry *entry, const char *name,
			      void *value, size_t size)
{
	struct inode *inode = d_inode(entry);
	struct fuse_getxattr_in *in;
	struct fuse_bpf_getxattr_io *io;
	struct path path;
	ssize_t ret;
	int error;

	if (!args->in_args[0].value)
		return -EINVAL;
	in = (struct fuse_getxattr_in *)args->in_args[0].value;
	io = container_of(in, struct fuse_bpf_getxattr_io, in);
	error = fuse_bpf_getxattr_validate(args, io, inode);
	if (error)
		return error;
	error = fuse_bpf_xattr_path(inode, entry, &path);
	if (error)
		return error;

	ret = vfs_getxattr(path.dentry, io->original_name,
			   io->value, io->requested_size);
	fuse_put_backing_path(&path);
	if (ret < 0)
		return ret;
	if ((size_t)ret > (io->requested_size ?
			   io->requested_size : XATTR_SIZE_MAX))
		return -EIO;

	io->executed = true;
	io->actual_ret = ret;
	if (io->requested_size) {
		args->out_args[0].size = ret;
		args->out_args[0].end_offset =
			fuse_bpf_xattr_end(io->value, ret);
		if (!args->out_args[0].end_offset && io->value)
			return -EOVERFLOW;
	} else {
		io->out.size = ret;
	}
	(void)name;
	(void)value;
	(void)size;
	return 0;
}

void *fuse_bpf_getxattr_finalize(struct fuse_bpf_args *args,
				 struct dentry *entry, const char *name,
				 void *value, size_t size)
{
	struct inode *inode = d_inode(entry);
	struct fuse_getxattr_in *in;
	struct fuse_bpf_getxattr_io *io;
	ssize_t ret;
	int error = (s32)args->error_in;

	if (error)
		return ERR_PTR(error < 0 ? error : -EIO);
	if (!args->in_numargs || !args->in_args[0].value)
		return ERR_PTR(-EIO);
	in = (struct fuse_getxattr_in *)args->in_args[0].value;
	io = container_of(in, struct fuse_bpf_getxattr_io, in);
	if (fuse_bpf_getxattr_validate(args, io, inode) || !io->executed ||
	    io->actual_ret < 0)
		return ERR_PTR(-EIO);

	if (io->requested_size) {
		ret = args->out_args[0].size;
		if (ret > io->actual_ret)
			return ERR_PTR(-EIO);
	} else {
		if (io->out.padding || io->out.size > io->actual_ret)
			return ERR_PTR(-EIO);
		ret = io->out.size;
	}
	(void)name;
	(void)value;
	(void)size;
	return ERR_PTR(ret);
}

int fuse_bpf_listxattr_initialize(struct fuse_bpf_args *args,
				  struct fuse_bpf_listxattr_io *io,
				  struct dentry *entry, char *list,
				  size_t size)
{
	struct inode *inode = d_inode(entry);

	if (size > XATTR_LIST_MAX || (size && !list))
		return -E2BIG;

	memset(io, 0, sizeof(*io));
	io->in.size = size;
	io->list = list;
	io->requested_size = size;
	io->actual_ret = -EINPROGRESS;
	*args = (struct fuse_bpf_args) {
		.nodeid = get_node_id(inode),
		.opcode = FUSE_LISTXATTR,
		.in_numargs = 1,
		.out_numargs = 1,
		.flags = size ? FUSE_BPF_OUT_ARGVAR : 0,
		.in_args[0] = (struct fuse_bpf_in_arg) {
			.size = sizeof(io->in),
			.value = &io->in,
		},
		.out_args[0] = (struct fuse_bpf_arg) {
			.size = size ? size : sizeof(io->out),
			.value = size ? (void *)list : &io->out,
		},
	};
	return 0;
}

static int fuse_bpf_listxattr_validate(struct fuse_bpf_args *args,
				       struct fuse_bpf_listxattr_io *io,
				       struct inode *inode)
{
	u32 expected_in;

	if (args->opcode == FUSE_LISTXATTR)
		expected_in = 1;
	else if (args->opcode == (FUSE_LISTXATTR | FUSE_POSTFILTER))
		expected_in = 2;
	else
		return -EIO;
	if (args->nodeid != get_node_id(inode) ||
	    args->flags != (io->requested_size ?
			    FUSE_BPF_OUT_ARGVAR : 0) ||
	    args->in_numargs != expected_in ||
	    args->out_numargs != 1 ||
	    !args->in_args[0].value || !args->out_args[0].value ||
	    args->in_args[0].size != sizeof(io->in) ||
	    args->in_args[0].value != &io->in ||
	    io->in.padding || io->in.size != io->requested_size)
		return -EIO;
	if (io->requested_size) {
		if (args->out_args[0].value != io->list ||
		    args->out_args[0].size > io->requested_size)
			return -EIO;
	} else if (args->out_args[0].value != &io->out ||
		   args->out_args[0].size != sizeof(io->out)) {
		return -EIO;
	}
	if (expected_in == 2 &&
	    (!args->in_args[1].value ||
	     args->in_args[1].value != args->out_args[0].value ||
	     args->in_args[1].size != args->out_args[0].size))
		return -EIO;
	return 0;
}

int fuse_bpf_listxattr_backing(struct fuse_bpf_args *args,
			       struct dentry *entry, char *list,
			       size_t size)
{
	struct inode *inode = d_inode(entry);
	struct fuse_getxattr_in *in;
	struct fuse_bpf_listxattr_io *io;
	struct path path;
	ssize_t ret;
	int error;

	if (!args->in_args[0].value)
		return -EINVAL;
	in = (struct fuse_getxattr_in *)args->in_args[0].value;
	io = container_of(in, struct fuse_bpf_listxattr_io, in);
	error = fuse_bpf_listxattr_validate(args, io, inode);
	if (error)
		return error;
	error = fuse_bpf_xattr_path(inode, entry, &path);
	if (error)
		return error;

	ret = vfs_listxattr(path.dentry, io->list, io->requested_size);
	fuse_put_backing_path(&path);
	if (ret < 0)
		return ret;
	if ((size_t)ret > (io->requested_size ?
			   io->requested_size : XATTR_LIST_MAX))
		return -EIO;
	if (io->requested_size &&
	    fuse_bpf_verify_xattr_list(io->list, ret))
		return -EIO;

	io->executed = true;
	io->actual_ret = ret;
	if (io->requested_size) {
		args->out_args[0].size = ret;
		args->out_args[0].end_offset =
			fuse_bpf_xattr_end(io->list, ret);
		if (!args->out_args[0].end_offset && io->list)
			return -EOVERFLOW;
	} else {
		io->out.size = ret;
	}
	(void)list;
	(void)size;
	return 0;
}

void *fuse_bpf_listxattr_finalize(struct fuse_bpf_args *args,
				  struct dentry *entry, char *list,
				  size_t size)
{
	struct inode *inode = d_inode(entry);
	struct fuse_getxattr_in *in;
	struct fuse_bpf_listxattr_io *io;
	ssize_t ret;
	int error = (s32)args->error_in;

	if (error)
		return ERR_PTR(error < 0 ? error : -EIO);
	if (!args->in_numargs || !args->in_args[0].value)
		return ERR_PTR(-EIO);
	in = (struct fuse_getxattr_in *)args->in_args[0].value;
	io = container_of(in, struct fuse_bpf_listxattr_io, in);
	if (fuse_bpf_listxattr_validate(args, io, inode) || !io->executed ||
	    io->actual_ret < 0)
		return ERR_PTR(-EIO);

	if (io->requested_size) {
		ret = args->out_args[0].size;
		if (ret > io->actual_ret ||
		    fuse_bpf_verify_xattr_list(io->list, ret))
			return ERR_PTR(-EIO);
	} else {
		if (io->out.padding || io->out.size > io->actual_ret)
			return ERR_PTR(-EIO);
		ret = io->out.size;
	}
	(void)list;
	(void)size;
	return ERR_PTR(ret);
}
