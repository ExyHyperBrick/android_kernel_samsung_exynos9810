/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2001-2016  Miklos Szeredi <miklos@szeredi.hu>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#include "fuse_i.h"

#include <linux/xattr.h>
#include <linux/posix_acl_xattr.h>

#ifdef CONFIG_FUSE_BPF
#include "xattr_bpf.h"
#endif

int fuse_setxattr(struct inode *inode, const char *name, const void *value,
		  size_t size, int flags)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);
	struct fuse_setxattr_in inarg;
	int err;

#ifdef CONFIG_FUSE_BPF
	if (fuse_inode_has_backing(inode)) {
		struct dentry *alias;

		alias = d_find_alias(inode);
		if (!alias)
			return -ESTALE;
		err = fuse_bpf_setxattr(alias, name, value, size, flags);
		dput(alias);
		return err;
	}
#endif
	if (fc->no_setxattr)
		return -EOPNOTSUPP;

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	inarg.flags = flags;
	args.in.h.opcode = FUSE_SETXATTR;
	args.in.h.nodeid = get_node_id(inode);
	args.in.numargs = 3;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.in.args[1].size = strlen(name) + 1;
	args.in.args[1].value = name;
	args.in.args[2].size = size;
	args.in.args[2].value = value;
	err = fuse_simple_request(fc, &args);
	if (err == -ENOSYS) {
		fc->no_setxattr = 1;
		err = -EOPNOTSUPP;
	}
	if (!err) {
		fuse_invalidate_attr(inode);
		fuse_update_ctime(inode);
	}
	return err;
}

#ifdef CONFIG_FUSE_BPF
static ssize_t fuse_getxattr_daemon(struct inode *inode, const char *name,
				    void *value, size_t size)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);
	struct fuse_getxattr_in inarg;
	struct fuse_getxattr_out outarg;
	ssize_t ret;

	if (fc->no_getxattr)
		return -EOPNOTSUPP;

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	args.in.h.opcode = FUSE_GETXATTR;
	args.in.h.nodeid = get_node_id(inode);
	args.in.numargs = 2;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.in.args[1].size = strlen(name) + 1;
	args.in.args[1].value = name;
	args.out.numargs = 1;
	if (size) {
		args.out.argvar = 1;
		args.out.args[0].size = size;
		args.out.args[0].value = value;
	} else {
		args.out.args[0].size = sizeof(outarg);
		args.out.args[0].value = &outarg;
	}
	ret = fuse_simple_request(fc, &args);
	if (!ret && !size)
		ret = min_t(ssize_t, outarg.size, XATTR_SIZE_MAX);
	if (ret == -ENOSYS) {
		fc->no_getxattr = 1;
		ret = -EOPNOTSUPP;
	}
	return ret;
}

static ssize_t fuse_getxattr_backing_dispatch(struct dentry *entry,
					      struct inode *inode,
					      const char *name,
					      void *value, size_t size)
{
	struct fuse_err_ret result;

	result = fuse_bpf_backing(inode, struct fuse_bpf_getxattr_io,
				  fuse_bpf_getxattr_initialize,
				  fuse_bpf_getxattr_backing,
				  fuse_bpf_getxattr_finalize,
				  entry, name, value, size);
	if (result.ret)
		return PTR_ERR(result.result);
	if (!get_node_id(inode))
		return -EOPNOTSUPP;
	return fuse_getxattr_daemon(inode, name, value, size);
}
#endif

ssize_t fuse_getxattr(struct inode *inode, const char *name, void *value,
		      size_t size)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);
	struct fuse_getxattr_in inarg;
	struct fuse_getxattr_out outarg;
	ssize_t ret;

#ifdef CONFIG_FUSE_BPF
	if (fuse_inode_has_backing(inode)) {
		struct dentry *alias;
		ssize_t result;

		alias = d_find_alias(inode);
		if (!alias)
			return -ESTALE;
		result = fuse_getxattr_backing_dispatch(alias, inode, name,
							value, size);
		dput(alias);
		return result;
	}
#endif
	if (fc->no_getxattr)
		return -EOPNOTSUPP;

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	args.in.h.opcode = FUSE_GETXATTR;
	args.in.h.nodeid = get_node_id(inode);
	args.in.numargs = 2;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.in.args[1].size = strlen(name) + 1;
	args.in.args[1].value = name;
	/* This is really two different operations rolled into one */
	args.out.numargs = 1;
	if (size) {
		args.out.argvar = 1;
		args.out.args[0].size = size;
		args.out.args[0].value = value;
	} else {
		args.out.args[0].size = sizeof(outarg);
		args.out.args[0].value = &outarg;
	}
	ret = fuse_simple_request(fc, &args);
	if (!ret && !size)
		ret = min_t(ssize_t, outarg.size, XATTR_SIZE_MAX);
	if (ret == -ENOSYS) {
		fc->no_getxattr = 1;
		ret = -EOPNOTSUPP;
	}
	return ret;
}

static int fuse_verify_xattr_list(char *list, size_t size)
{
	size_t origsize = size;

	while (size) {
		size_t thislen = strnlen(list, size);

		if (!thislen || thislen == size)
			return -EIO;

		size -= thislen + 1;
		list += thislen + 1;
	}

	return origsize;
}

ssize_t fuse_listxattr(struct dentry *entry, char *list, size_t size)
{
	struct inode *inode = d_inode(entry);
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);
	struct fuse_getxattr_in inarg;
	struct fuse_getxattr_out outarg;
	ssize_t ret;

	if (fuse_is_bad(inode))
		return -EIO;

	if (!fuse_allow_current_process(fc))
		return -EACCES;

#ifdef CONFIG_FUSE_BPF
	if (fuse_inode_has_backing(inode)) {
		struct fuse_err_ret result;

		result = fuse_bpf_backing(inode,
					 struct fuse_bpf_listxattr_io,
					 fuse_bpf_listxattr_initialize,
					 fuse_bpf_listxattr_backing,
					 fuse_bpf_listxattr_finalize,
					 entry, list, size);
		if (result.ret)
			return PTR_ERR(result.result);
		if (!get_node_id(inode))
			return -EOPNOTSUPP;
	}
#endif
	if (fc->no_listxattr)
		return -EOPNOTSUPP;

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	args.in.h.opcode = FUSE_LISTXATTR;
	args.in.h.nodeid = get_node_id(inode);
	args.in.numargs = 1;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	/* This is really two different operations rolled into one */
	args.out.numargs = 1;
	if (size) {
		args.out.argvar = 1;
		args.out.args[0].size = size;
		args.out.args[0].value = list;
	} else {
		args.out.args[0].size = sizeof(outarg);
		args.out.args[0].value = &outarg;
	}
	ret = fuse_simple_request(fc, &args);
	if (!ret && !size)
		ret = min_t(ssize_t, outarg.size, XATTR_LIST_MAX);
	if (ret > 0 && size)
		ret = fuse_verify_xattr_list(list, ret);
	if (ret == -ENOSYS) {
		fc->no_listxattr = 1;
		ret = -EOPNOTSUPP;
	}
	return ret;
}

int fuse_removexattr(struct inode *inode, const char *name)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);
	int err;

#ifdef CONFIG_FUSE_BPF
	if (fuse_inode_has_backing(inode)) {
		struct dentry *alias;

		alias = d_find_alias(inode);
		if (!alias)
			return -ESTALE;
		err = fuse_bpf_removexattr(alias, name);
		dput(alias);
		return err;
	}
#endif
	if (fc->no_removexattr)
		return -EOPNOTSUPP;

	args.in.h.opcode = FUSE_REMOVEXATTR;
	args.in.h.nodeid = get_node_id(inode);
	args.in.numargs = 1;
	args.in.args[0].size = strlen(name) + 1;
	args.in.args[0].value = name;
	err = fuse_simple_request(fc, &args);
	if (err == -ENOSYS) {
		fc->no_removexattr = 1;
		err = -EOPNOTSUPP;
	}
	if (!err) {
		fuse_invalidate_attr(inode);
		fuse_update_ctime(inode);
	}
	return err;
}

static int fuse_xattr_get(const struct xattr_handler *handler,
			 struct dentry *dentry, struct inode *inode,
			 const char *name, void *value, size_t size)
{
	if (fuse_is_bad(inode))
		return -EIO;

#ifdef CONFIG_FUSE_BPF
	if (fuse_inode_has_backing(inode))
		return fuse_getxattr_backing_dispatch(dentry, inode, name,
						     value, size);
#endif
	return fuse_getxattr(inode, name, value, size);
}

static int fuse_xattr_set(const struct xattr_handler *handler,
			  struct dentry *dentry, struct inode *inode,
			  const char *name, const void *value, size_t size,
			  int flags)
{
	if (fuse_is_bad(inode))
		return -EIO;

#ifdef CONFIG_FUSE_BPF
	if (fuse_inode_has_backing(inode)) {
		if (!value)
			return fuse_bpf_removexattr(dentry, name);
		return fuse_bpf_setxattr(dentry, name, value, size, flags);
	}
#endif
	if (!value)
		return fuse_removexattr(inode, name);

	return fuse_setxattr(inode, name, value, size, flags);
}

static const struct xattr_handler fuse_xattr_handler = {
	.prefix = "",
	.get    = fuse_xattr_get,
	.set    = fuse_xattr_set,
};

const struct xattr_handler *fuse_xattr_handlers[] = {
	&fuse_xattr_handler,
	NULL
};

const struct xattr_handler *fuse_acl_xattr_handlers[] = {
	&posix_acl_access_xattr_handler,
	&posix_acl_default_xattr_handler,
	&fuse_xattr_handler,
	NULL
};
