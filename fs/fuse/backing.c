// SPDX-License-Identifier: GPL-2.0
/*
 * FUSE-BPF request dispatcher
 * Copyright (c) 2021 Google LLC
 */

#include "fuse_i.h"

#include <linux/errno.h>
#include <linux/fs_stack.h>
#include <linux/fsnotify.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/string.h>

#define FUSE_BPF_RET_MASK	(FUSE_BPF_USER_FILTER | FUSE_BPF_BACKING | \
				 FUSE_BPF_POST_FILTER)

static const void *fuse_bpf_const_end(const void *value, u32 size)
{
	return value ? (const char *)value + size : NULL;
}

static void *fuse_bpf_end(void *value, u32 size)
{
	return value ? (char *)value + size : NULL;
}

static int fuse_bpf_validate_args(const struct fuse_bpf_args *args)
{
	u32 filter = args->opcode & ~FUSE_OPCODE_FILTER;

	if (args->in_numargs > FUSE_MAX_IN_ARGS ||
	    args->out_numargs > FUSE_MAX_OUT_ARGS)
		return -E2BIG;
	if (filter & ~(FUSE_PREFILTER | FUSE_POSTFILTER))
		return -EINVAL;
	if (filter == (FUSE_PREFILTER | FUSE_POSTFILTER))
		return -EINVAL;
	if (args->flags & ~(FUSE_BPF_FORCE | FUSE_BPF_OUT_ARGVAR))
		return -EINVAL;
	if ((args->flags & FUSE_BPF_OUT_ARGVAR) && !args->out_numargs)
		return -EINVAL;
	return 0;
}

int fuse_bpf_prepare_prefilter(struct fuse_bpf_args *args,
			       struct fuse_bpf_args *backup)
{
	u32 i;
	int ret;

	ret = fuse_bpf_validate_args(args);
	if (ret)
		return ret;
	if (args->opcode & (FUSE_PREFILTER | FUSE_POSTFILTER))
		return -EINVAL;
	if (args->in_numargs > FUSE_MAX_OUT_ARGS)
		return -E2BIG;

	for (i = 0; i < args->in_numargs; i++)
		args->in_args[i].end_offset =
			fuse_bpf_const_end(args->in_args[i].value,
					   args->in_args[i].size);
	for (i = 0; i < args->out_numargs; i++)
		args->out_args[i].end_offset =
			fuse_bpf_end(args->out_args[i].value,
				     args->out_args[i].size);

	*backup = *args;
	args->flags &= ~FUSE_BPF_OUT_ARGVAR;
	memset(args->out_args, 0, sizeof(args->out_args));
	for (i = 0; i < args->in_numargs; i++) {
		args->out_args[i].size = args->in_args[i].size;
		args->out_args[i].value = (void *)args->in_args[i].value;
		args->out_args[i].end_offset =
			(void *)args->in_args[i].end_offset;
	}
	args->out_numargs = args->in_numargs;
	args->opcode |= FUSE_PREFILTER;
	return 0;
}

int fuse_bpf_prepare_backing(struct fuse_bpf_args *args,
			     const struct fuse_bpf_args *backup)
{
	u32 i;
	int ret;

	ret = fuse_bpf_validate_args(args);
	if (ret)
		return ret;
	ret = fuse_bpf_validate_args(backup);
	if (ret)
		return ret;
	if (args->opcode != (backup->opcode | FUSE_PREFILTER) ||
	    args->out_numargs != backup->in_numargs)
		return -EINVAL;

	memset(args->in_args, 0, sizeof(args->in_args));
	for (i = 0; i < backup->in_numargs; i++) {
		args->in_args[i].size = args->out_args[i].size;
		args->in_args[i].value = args->out_args[i].value;
		args->in_args[i].end_offset = args->out_args[i].end_offset;
	}
	args->in_numargs = backup->in_numargs;
	args->nodeid = backup->nodeid;
	args->opcode = backup->opcode;
	args->error_in = backup->error_in;
	args->flags = backup->flags;
	args->out_numargs = backup->out_numargs;
	memcpy(args->out_args, backup->out_args, sizeof(args->out_args));
	return 0;
}

int fuse_bpf_prepare_postfilter(struct fuse_bpf_args *args)
{
	u32 i;
	int ret;

	ret = fuse_bpf_validate_args(args);
	if (ret)
		return ret;
	if (args->opcode & (FUSE_PREFILTER | FUSE_POSTFILTER))
		return -EINVAL;
	if (args->in_numargs + args->out_numargs > FUSE_MAX_IN_ARGS)
		return -E2BIG;

	for (i = 0; i < args->out_numargs; i++) {
		struct fuse_bpf_in_arg *in =
			&args->in_args[args->in_numargs++];

		in->size = args->out_args[i].size;
		in->value = args->out_args[i].value;
		in->end_offset = args->out_args[i].end_offset;
	}
	args->opcode |= FUSE_POSTFILTER;
	return 0;
}

int fuse_bpf_restore_outputs(struct fuse_bpf_args *args,
			     const struct fuse_bpf_args *backup)
{
	int ret;

	ret = fuse_bpf_validate_args(backup);
	if (ret)
		return ret;
	args->out_numargs = backup->out_numargs;
	memcpy(args->out_args, backup->out_args, sizeof(args->out_args));
	return 0;
}

int fuse_bpf_run_filter(struct bpf_prog *prog, struct fuse_bpf_args *args)
{
	int ret;

	if (!prog)
		return -EINVAL;
	ret = (int)bpf_prog_run_pin_on_cpu(prog, args);
	if (ret < 0)
		return ret;
	if (ret & ~FUSE_BPF_RET_MASK)
		return -EINVAL;
	return ret;
}

struct bpf_prog *fuse_bpf_get_prog(struct fuse_conn *fc,
				   struct fuse_inode *fi)
{
	struct bpf_prog *prog;

	spin_lock(&fc->lock);
	prog = fi->bpf;
	if (prog)
		bpf_prog_inc(prog);
	spin_unlock(&fc->lock);
	return prog;
}

ssize_t fuse_bpf_simple_request(struct fuse_conn *fc,
				struct fuse_bpf_args *bpf_args)
{
	struct fuse_args args = { };
	ssize_t ret;
	u32 i;

	ret = fuse_bpf_validate_args(bpf_args);
	if (ret)
		return ret;

	args.error_in = bpf_args->error_in;
	args.force = !!(bpf_args->flags & FUSE_BPF_FORCE);
	args.in.h.opcode = bpf_args->opcode;
	args.in.h.nodeid = bpf_args->nodeid;
	args.in.numargs = bpf_args->in_numargs;
	for (i = 0; i < bpf_args->in_numargs; i++) {
		args.in.args[i].size = bpf_args->in_args[i].size;
		args.in.args[i].value = bpf_args->in_args[i].value;
	}
	args.out.argvar = !!(bpf_args->flags & FUSE_BPF_OUT_ARGVAR);
	args.out.numargs = bpf_args->out_numargs;
	for (i = 0; i < bpf_args->out_numargs; i++) {
		args.out.args[i].size = bpf_args->out_args[i].size;
		args.out.args[i].value = bpf_args->out_args[i].value;
	}

	ret = fuse_simple_request(fc, &args);
	for (i = 0; i < bpf_args->out_numargs; i++) {
		bpf_args->out_args[i].size = args.out.args[i].size;
		bpf_args->out_args[i].value = args.out.args[i].value;
		bpf_args->out_args[i].end_offset =
			fuse_bpf_end(args.out.args[i].value,
				     args.out.args[i].size);
	}
	return ret;
}

static void fuse_bpf_path_put(struct path *path)
{
	if (path->dentry)
		path_put(path);
	path->dentry = NULL;
	path->mnt = NULL;
}

static void fuse_bpf_put_lookup_files(struct fuse_entry_bpf *entry)
{
	if (!entry)
		return;

	if (entry->backing_file && !IS_ERR(entry->backing_file))
		fput(entry->backing_file);
	entry->backing_file = NULL;

	if (entry->bpf_file && !IS_ERR(entry->bpf_file))
		fput(entry->bpf_file);
	entry->bpf_file = NULL;
}

static void fuse_stat_to_attr(struct fuse_conn *fc, struct inode *inode,
			      struct kstat *stat, struct fuse_attr *attr)
{
	unsigned int blkbits;

	if (fc->writeback_cache && S_ISREG(inode->i_mode)) {
		stat->size = i_size_read(inode);
		stat->mtime.tv_sec = inode->i_mtime.tv_sec;
		stat->mtime.tv_nsec = inode->i_mtime.tv_nsec;
		stat->ctime.tv_sec = inode->i_ctime.tv_sec;
		stat->ctime.tv_nsec = inode->i_ctime.tv_nsec;
	}

	memset(attr, 0, sizeof(*attr));
	attr->ino = stat->ino;
	attr->mode = (inode->i_mode & S_IFMT) | (stat->mode & 07777);
	attr->nlink = stat->nlink;
	attr->uid = from_kuid(&init_user_ns, stat->uid);
	attr->gid = from_kgid(&init_user_ns, stat->gid);
	attr->rdev = new_encode_dev(stat->rdev);
	attr->atime = stat->atime.tv_sec;
	attr->atimensec = stat->atime.tv_nsec;
	attr->mtime = stat->mtime.tv_sec;
	attr->mtimensec = stat->mtime.tv_nsec;
	attr->ctime = stat->ctime.tv_sec;
	attr->ctimensec = stat->ctime.tv_nsec;
	attr->size = stat->size;
	attr->blocks = stat->blocks;

	if (stat->blksize)
		blkbits = ilog2(stat->blksize);
	else
		blkbits = inode->i_sb->s_blocksize_bits;
	attr->blksize = 1U << blkbits;
}

static int fuse_lookup_refresh_attr(struct fuse_conn *fc,
				    struct path *path,
				    struct fuse_entry_out *out)
{
	struct inode *inode;
	struct kstat stat;
	int ret;

	if (!path->dentry)
		return -ENOENT;
	inode = d_inode(path->dentry);
	if (!inode)
		return -ENOENT;

	ret = vfs_getattr(path, &stat, STATX_BASIC_STATS, 0);
	if (ret)
		return ret;
	fuse_stat_to_attr(fc, inode, &stat, &out->attr);
	return 0;
}

int fuse_lookup_initialize(struct fuse_bpf_args *args,
			   struct fuse_lookup_io *io,
			   struct inode *dir, struct dentry *entry,
			   unsigned int flags)
{
	if (entry->d_name.len > FUSE_NAME_MAX)
		return -ENAMETOOLONG;

	memset(io, 0, sizeof(*io));
	*args = (struct fuse_bpf_args) {
		.nodeid = get_node_id(dir),
		.opcode = FUSE_LOOKUP,
		.in_numargs = 1,
		.out_numargs = 2,
		.flags = FUSE_BPF_OUT_ARGVAR,
		.in_args[0] = (struct fuse_bpf_in_arg) {
			.size = entry->d_name.len + 1,
			.value = entry->d_name.name,
		},
		.out_args[0] = (struct fuse_bpf_arg) {
			.size = sizeof(io->entry),
			.value = &io->entry,
		},
		.out_args[1] = (struct fuse_bpf_arg) {
			.size = sizeof(io->bpf.out),
			.value = &io->bpf.out,
		},
	};
	(void)flags;
	return 0;
}

int fuse_lookup_backing(struct fuse_bpf_args *args, struct inode *dir,
			struct dentry *entry, unsigned int flags)
{
	struct fuse_entry_out *out = args->out_args[0].value;
	struct fuse_dentry *parent_data;
	struct fuse_dentry *entry_data;
	struct dentry *backing_parent;
	struct dentry *backing_entry;
	struct inode *backing_dir;
	const char *name;
	u32 name_size;
	int ret;

	parent_data = get_fuse_dentry(entry->d_parent);
	entry_data = get_fuse_dentry(entry);
	if (!parent_data || !entry_data ||
	    !parent_data->backing_path.dentry ||
	    !parent_data->backing_path.mnt) {
		args->error_in = -EIO;
		return -EIO;
	}

	backing_parent = parent_data->backing_path.dentry;
	backing_dir = d_inode(backing_parent);
	if (!backing_dir) {
		args->error_in = -ENOENT;
		return -ENOENT;
	}

	name = args->in_args[0].value;
	name_size = args->in_args[0].size;
	if (!name || !name_size || name_size > FUSE_NAME_MAX + 1 ||
	    name[name_size - 1] != '\0') {
		args->error_in = -EINVAL;
		return -EINVAL;
	}

	fuse_bpf_path_put(&entry_data->backing_path);
	inode_lock_nested(backing_dir, I_MUTEX_PARENT);
	backing_entry = lookup_one_len(name, backing_parent, name_size - 1);
	inode_unlock(backing_dir);
	if (IS_ERR(backing_entry)) {
		ret = PTR_ERR(backing_entry);
		args->error_in = ret;
		return ret;
	}

	entry_data->backing_path.dentry = backing_entry;
	entry_data->backing_path.mnt = mntget(parent_data->backing_path.mnt);
	if (d_really_is_negative(backing_entry)) {
		args->error_in = -ENOENT;
		return 0;
	}

	ret = fuse_lookup_refresh_attr(get_fuse_conn(dir),
				       &entry_data->backing_path, out);
	if (ret) {
		args->error_in = ret;
		fuse_bpf_path_put(&entry_data->backing_path);
		return ret;
	}

	out->nodeid = 0;
	args->error_in = 0;
	(void)flags;
	return 0;
}

int fuse_handle_backing(struct fuse_entry_bpf *entry,
			struct inode **backing_inode,
			struct path *backing_path)
{
	struct inode *new_inode;
	struct path new_path;
	struct file *file;

	switch (entry->out.backing_action) {
	case FUSE_ACTION_KEEP:
		return 0;

	case FUSE_ACTION_REMOVE:
		if (*backing_inode) {
			iput(*backing_inode);
			*backing_inode = NULL;
		}
		fuse_bpf_path_put(backing_path);
		return 0;

	case FUSE_ACTION_REPLACE:
		file = entry->backing_file;
		entry->backing_file = NULL;
		if (!file)
			return -EBADF;
		if (IS_ERR(file))
			return PTR_ERR(file);
		if (!file_inode(file) || !file->f_path.dentry ||
		    !file->f_path.mnt) {
			fput(file);
			return -EINVAL;
		}

		new_inode = file_inode(file);
		ihold(new_inode);
		new_path = file->f_path;
		path_get(&new_path);
		fput(file);

		if (*backing_inode)
			iput(*backing_inode);
		fuse_bpf_path_put(backing_path);
		*backing_inode = new_inode;
		*backing_path = new_path;
		return 0;

	default:
		return -EINVAL;
	}
}

int fuse_handle_bpf_prog(struct fuse_entry_bpf *entry,
			 struct inode *parent, struct bpf_prog **prog)
{
	struct fuse_conn *fc;
	struct bpf_prog *new_prog = NULL;
	struct bpf_prog *old_prog;
	struct file *file;
	int ret;

	if (!parent) {
		if (entry->out.bpf_action == FUSE_ACTION_KEEP)
			return 0;
		return -EINVAL;
	}
	fc = get_fuse_conn(parent);

	switch (entry->out.bpf_action) {
	case FUSE_ACTION_KEEP:
		spin_lock(&fc->lock);
		new_prog = get_fuse_inode(parent)->bpf;
		if (new_prog)
			bpf_prog_inc(new_prog);
		spin_unlock(&fc->lock);
		break;

	case FUSE_ACTION_REMOVE:
		break;

	case FUSE_ACTION_REPLACE:
		file = entry->bpf_file;
		entry->bpf_file = NULL;
		if (!file)
			return -EBADF;
		new_prog = fuse_get_bpf_prog(file);
		if (IS_ERR(new_prog)) {
			ret = PTR_ERR(new_prog);
			return ret;
		}
		break;

	default:
		return -EINVAL;
	}

	spin_lock(&fc->lock);
	old_prog = *prog;
	*prog = new_prog;
	spin_unlock(&fc->lock);
	if (old_prog)
		bpf_prog_put(old_prog);
	return 0;
}

static void fuse_bpf_copy_alias_path(struct dentry *from,
				     struct dentry *to)
{
	struct fuse_dentry *from_data = get_fuse_dentry(from);
	struct fuse_dentry *to_data = get_fuse_dentry(to);

	if (!from_data || !to_data || !from_data->backing_path.dentry)
		return;
	fuse_bpf_path_put(&to_data->backing_path);
	to_data->backing_path = from_data->backing_path;
	path_get(&to_data->backing_path);
}

void *fuse_lookup_finalize(struct fuse_bpf_args *args,
			   struct inode *dir, struct dentry *entry,
			   unsigned int flags)
{
	struct fuse_entry_out *out;
	struct fuse_entry_bpf_out *bpf_out;
	struct fuse_entry_bpf *bpf_entry = NULL;
	struct fuse_dentry *entry_data;
	struct inode *backing_inode = NULL;
	struct inode *inode = NULL;
	struct dentry *alias;
	void *result = NULL;
	u64 nodeid;
	int error;
	int ret;

	if (args->out_numargs < 2 || !args->out_args[0].value ||
	    !args->out_args[1].value)
		goto out_files;

	out = args->out_args[0].value;
	bpf_out = args->out_args[1].value;
	bpf_entry = container_of(bpf_out, struct fuse_entry_bpf, out);
	if (args->out_args[0].size != sizeof(*out) ||
	    (args->out_args[1].size &&
	     args->out_args[1].size != sizeof(*bpf_out))) {
		result = ERR_PTR(-EIO);
		goto out_files;
	}
	entry_data = get_fuse_dentry(entry);
	if (!entry_data) {
		result = ERR_PTR(-EIO);
		goto out_files;
	}

	if (entry_data->backing_path.dentry) {
		backing_inode = d_inode(entry_data->backing_path.dentry);
		if (backing_inode)
			ihold(backing_inode);
	}

	ret = fuse_handle_backing(bpf_entry, &backing_inode,
				  &entry_data->backing_path);
	if (ret) {
		result = ERR_PTR(ret);
		goto out_inode;
	}

	if (backing_inode &&
	    (bpf_entry->out.backing_action == FUSE_ACTION_REPLACE ||
	     fuse_invalid_attr(&out->attr))) {
		ret = fuse_lookup_refresh_attr(get_fuse_conn(dir),
					       &entry_data->backing_path, out);
		if (ret) {
			result = ERR_PTR(ret);
			goto out_inode;
		}
	}

	if (!backing_inode) {
		error = (s32)args->error_in;
		if (error && error != -ENOENT) {
			result = ERR_PTR(error);
			goto out_inode;
		}
		if (!out->nodeid) {
			fuse_invalidate_entry_cache(entry);
			result = NULL;
			goto out_inode;
		}
		if (out->nodeid == FUSE_ROOT_ID ||
		    fuse_invalid_attr(&out->attr)) {
			result = ERR_PTR(-EIO);
			goto out_inode;
		}
		inode = fuse_iget(dir->i_sb, out->nodeid, out->generation,
				  &out->attr, entry_attr_timeout(out), 0);
	} else {
		if (out->nodeid == FUSE_ROOT_ID ||
		    fuse_invalid_attr(&out->attr)) {
			result = ERR_PTR(-EIO);
			goto out_inode;
		}
		nodeid = out->nodeid;
		if (!nodeid && d_inode(entry))
			nodeid = get_node_id(d_inode(entry));
		inode = fuse_iget_backing(dir->i_sb, nodeid,
					  backing_inode);
		if (inode)
			fuse_change_attributes(inode, &out->attr,
					       entry_attr_timeout(out), 0);
	}
	if (!inode) {
		result = ERR_PTR(-ENOMEM);
		goto out_inode;
	}

	ret = fuse_handle_bpf_prog(bpf_entry, dir,
				   &get_fuse_inode(inode)->bpf);
	if (ret) {
		iput(inode);
		result = ERR_PTR(ret);
		goto out_inode;
	}

	alias = d_splice_alias(inode, entry);
	if (IS_ERR(alias)) {
		result = alias;
		goto out_inode;
	}
	if (alias)
		fuse_bpf_copy_alias_path(entry, alias);
	fuse_change_entry_timeout(alias ? alias : entry, out);
	result = alias;
	(void)flags;

out_inode:
	if (backing_inode)
		iput(backing_inode);
out_files:
	fuse_bpf_put_lookup_files(bpf_entry);
	return result;
}

int fuse_revalidate_backing(struct dentry *entry, unsigned int flags)
{
	struct fuse_dentry *data = get_fuse_dentry(entry);
	struct dentry *backing;

	if (!data || !data->backing_path.dentry)
		return 1;

	backing = data->backing_path.dentry;
	spin_lock(&backing->d_lock);
	if (d_unhashed(backing)) {
		spin_unlock(&backing->d_lock);
		return 0;
	}
	spin_unlock(&backing->d_lock);
	if ((backing->d_flags & DCACHE_OP_REVALIDATE) &&
	    backing->d_op && backing->d_op->d_revalidate)
		return backing->d_op->d_revalidate(backing, flags);
	return 1;
}

int fuse_open_initialize(struct fuse_bpf_args *args,
			 struct fuse_open_io *io, struct inode *inode,
			 struct file *file, bool isdir)
{
	u32 flags = file->f_flags & ~(O_CREAT | O_EXCL | O_NOCTTY);

	memset(io, 0, sizeof(*io));
	if (!get_fuse_conn(inode)->atomic_o_trunc)
		flags &= ~O_TRUNC;
	io->in.flags = flags;
	*args = (struct fuse_bpf_args) {
		.nodeid = get_node_id(inode),
		.opcode = isdir ? FUSE_OPENDIR : FUSE_OPEN,
		.in_numargs = 1,
		.out_numargs = 1,
		.in_args[0] = (struct fuse_bpf_in_arg) {
			.size = sizeof(io->in),
			.value = &io->in,
		},
		.out_args[0] = (struct fuse_bpf_arg) {
			.size = sizeof(io->out),
			.value = &io->out,
		},
	};
	return 0;
}

static int fuse_open_access_mask(u32 flags)
{
	int mask;

	switch (flags & O_ACCMODE) {
	case O_RDONLY:
		mask = MAY_READ;
		break;
	case O_WRONLY:
		mask = MAY_WRITE;
		break;
	case O_RDWR:
		mask = MAY_READ | MAY_WRITE;
		break;
	default:
		return -EINVAL;
	}
	if (flags & O_TRUNC)
		mask |= MAY_WRITE;
	if (flags & O_APPEND)
		mask |= MAY_APPEND;
	return mask;
}

int fuse_open_backing(struct fuse_bpf_args *args, struct inode *inode,
		      struct file *file, bool isdir)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	const struct fuse_open_in *in;
	struct file *backing_file;
	struct inode *backing_inode;
	struct fuse_file *ff;
	struct path path;
	u32 flags;
	int mask;
	int ret;

	if (args->in_numargs != 1 || !args->in_args[0].value ||
	    args->in_args[0].size != sizeof(*in) ||
	    args->out_numargs != 1 || !args->out_args[0].value ||
	    args->out_args[0].size != sizeof(struct fuse_open_out))
		return -EINVAL;

	in = args->in_args[0].value;
	flags = in->flags & ~(O_CREAT | O_EXCL | O_NOCTTY);
	flags |= file->f_flags & FMODE_EXEC;
	mask = fuse_open_access_mask(flags);
	if (mask < 0)
		return mask;
	if (file->f_flags & FMODE_EXEC)
		mask |= MAY_EXEC;

	get_fuse_backing_path(file->f_path.dentry, &path);
	if (!path.dentry || !path.mnt)
		return -EBADF;
	backing_inode = d_inode(path.dentry);
	if (!fi || !fi->backing_inode || !backing_inode ||
	    backing_inode != fi->backing_inode) {
		ret = -ESTALE;
		goto out_path;
	}
	if (isdir && !S_ISDIR(backing_inode->i_mode)) {
		ret = -ENOTDIR;
		goto out_path;
	}
	if (!isdir && !S_ISREG(backing_inode->i_mode)) {
		ret = S_ISDIR(backing_inode->i_mode) ? -EISDIR :
			-EOPNOTSUPP;
		goto out_path;
	}
	if ((file->f_flags & FMODE_EXEC) &&
	    ((path.mnt->mnt_flags & MNT_NOEXEC) ||
	     (path.mnt->mnt_sb->s_iflags & SB_I_NOEXEC))) {
		ret = -EACCES;
		goto out_path;
	}
	if (S_ISDIR(backing_inode->i_mode) && (mask & MAY_WRITE)) {
		ret = -EISDIR;
		goto out_path;
	}
	ret = inode_permission2(path.mnt, backing_inode, MAY_OPEN | mask);
	if (ret)
		goto out_path;
	if (IS_APPEND(backing_inode) &&
	    (flags & O_ACCMODE) != O_RDONLY && !(flags & O_APPEND)) {
		ret = -EPERM;
		goto out_path;
	}
	if ((flags & O_NOATIME) &&
	    !inode_owner_or_capable(backing_inode)) {
		ret = -EPERM;
		goto out_path;
	}

	backing_file = dentry_open(&path, flags, current_cred());
	if (IS_ERR(backing_file)) {
		ret = PTR_ERR(backing_file);
		goto out_path;
	}

	ff = fuse_file_alloc(get_fuse_conn(inode));
	if (!ff) {
		fput(backing_file);
		ret = -ENOMEM;
		goto out_path;
	}
	ff->backing_file = backing_file;
	ff->open_flags = 0;
	ff->nodeid = get_node_id(inode);
	file->private_data = fuse_file_get(ff);
	ret = 0;

out_path:
	path_put(&path);
	return ret;
}

void *fuse_open_finalize(struct fuse_bpf_args *args, struct inode *inode,
			 struct file *file, bool isdir)
{
	struct fuse_open_out *out;
	struct fuse_file *ff = file->private_data;
	int error = (s32)args->error_in;

	if (error)
		return ERR_PTR(error < 0 ? error : -EIO);
	if (!ff)
		return NULL;
	if (args->out_numargs != 1 || !args->out_args[0].value ||
	    args->out_args[0].size != sizeof(*out))
		return ERR_PTR(-EIO);

	out = args->out_args[0].value;
	ff->fh = out->fh;
	ff->nodeid = get_node_id(inode);
	ff->open_flags = out->open_flags;
	if (isdir)
		ff->open_flags &= ~FOPEN_DIRECT_IO;
	return NULL;
}

static int fuse_bpf_rw_flags(struct kiocb *iocb, struct file *backing_file)
{
	int backing_flags = iocb_flags(backing_file);

	if (!is_sync_kiocb(iocb) ||
	    (iocb->ki_flags & (IOCB_EVENTFD | IOCB_NOWAIT | IOCB_HIPRI)))
		return -EOPNOTSUPP;
	if ((iocb->ki_flags & (IOCB_APPEND | IOCB_DIRECT)) !=
	    (backing_flags & (IOCB_APPEND | IOCB_DIRECT)))
		return -EOPNOTSUPP;
	return 0;
}

static ssize_t fuse_bpf_sync_iter(struct kiocb *iocb,
				  struct iov_iter *iter,
				  struct file *backing_file,
				  int type, bool *executed)
{
	struct kiocb lower_iocb;
	loff_t pos = iocb->ki_pos;
	ssize_t ret;

	if (type == READ) {
		if (!(backing_file->f_mode & FMODE_READ))
			return -EBADF;
		if (!(backing_file->f_mode & FMODE_CAN_READ) ||
		    !backing_file->f_op->read_iter)
			return -EINVAL;
	} else {
		if (!(backing_file->f_mode & FMODE_WRITE))
			return -EBADF;
		if (!(backing_file->f_mode & FMODE_CAN_WRITE) ||
		    !backing_file->f_op->write_iter)
			return -EINVAL;
	}
	if (!iov_iter_count(iter)) {
		*executed = true;
		return 0;
	}

	ret = rw_verify_area(type, backing_file, &pos,
			     iov_iter_count(iter));
	if (ret)
		return ret;

	lower_iocb = *iocb;
	lower_iocb.ki_filp = backing_file;
	lower_iocb.ki_pos = pos;
	lower_iocb.ki_complete = NULL;
	lower_iocb.private = NULL;
	lower_iocb.ki_flags &= IOCB_DSYNC | IOCB_SYNC;
	lower_iocb.ki_flags |= iocb_flags(backing_file);
	*executed = true;

	if (type == READ) {
		iter->type |= READ;
		ret = backing_file->f_op->read_iter(&lower_iocb, iter);
	} else {
		iter->type |= WRITE;
		file_start_write(backing_file);
		ret = backing_file->f_op->write_iter(&lower_iocb, iter);
		file_end_write(backing_file);
	}
	BUG_ON(ret == -EIOCBQUEUED);
	if (ret > 0) {
		iocb->ki_pos = lower_iocb.ki_pos;
		if (type == READ)
			fsnotify_access(backing_file);
		else
			fsnotify_modify(backing_file);
	}
	return ret;
}

static void fuse_bpf_file_accessed(struct file *file,
				   struct file *backing_file)
{
	if (file->f_flags & O_NOATIME)
		return;
	fsstack_copy_attr_atime(file_inode(file), file_inode(backing_file));
}

static void fuse_bpf_copy_write_attr(struct file *file,
				     struct file *backing_file)
{
	struct inode *inode = file_inode(file);
	struct inode *backing_inode = file_inode(backing_file);

	fsstack_copy_attr_times(inode, backing_inode);
	fsstack_copy_inode_size(inode, backing_inode);
	inode->i_mode &= ~(S_ISUID | S_ISGID);
	inode->i_mode |= backing_inode->i_mode & (S_ISUID | S_ISGID);
}

int fuse_file_read_iter_initialize(struct fuse_bpf_args *args,
				   struct fuse_file_read_iter_io *io,
				   struct kiocb *iocb,
				   struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;
	size_t count = iov_iter_count(to);

	if (!ff || !ff->backing_file)
		return -EBADF;
	if (count > U32_MAX)
		return -E2BIG;

	memset(io, 0, sizeof(*io));
	io->in.fh = ff->fh;
	io->in.offset = iocb->ki_pos;
	io->in.size = count;
	io->in.flags = file->f_flags;
	io->out.ret = -EINPROGRESS;
	io->original_pos = iocb->ki_pos;
	io->original_count = count;
	io->actual_ret = -EINPROGRESS;

	*args = (struct fuse_bpf_args) {
		.opcode = FUSE_READ,
		/* Lower-only handles must never be sent to the daemon. */
		.nodeid = 0,
		.in_numargs = 1,
		.out_numargs = 1,
		.in_args[0] = (struct fuse_bpf_in_arg) {
			.size = sizeof(io->in),
			.value = &io->in,
		},
		.out_args[0] = (struct fuse_bpf_arg) {
			.size = sizeof(io->out),
			.value = &io->out,
		},
	};
	return 0;
}

int fuse_file_read_iter_backing(struct fuse_bpf_args *args,
				struct kiocb *iocb,
				struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;
	struct fuse_read_in *in;
	struct fuse_file_read_iter_io *io;
	ssize_t ret;

	if (!ff || !ff->backing_file || args->opcode != FUSE_READ ||
	    args->nodeid || args->in_numargs != 1 ||
	    args->out_numargs != 1 || !args->in_args[0].value ||
	    !args->out_args[0].value ||
	    args->in_args[0].size != sizeof(*in) ||
	    args->out_args[0].size != sizeof(struct fuse_bpf_rw_out))
		return -EINVAL;

	in = (struct fuse_read_in *)args->in_args[0].value;
	io = container_of(in, struct fuse_file_read_iter_io, in);
	if (args->out_args[0].value != &io->out || in->fh != ff->fh ||
	    in->offset != io->original_pos ||
	    in->size != io->original_count ||
	    in->flags != file->f_flags || in->read_flags ||
	    in->lock_owner || in->padding)
		return -EOPNOTSUPP;
	ret = fuse_bpf_rw_flags(iocb, ff->backing_file);
	if (ret)
		return ret;

	ret = fuse_bpf_sync_iter(iocb, to, ff->backing_file, READ,
				 &io->executed);
	io->actual_ret = ret;
	io->out.ret = ret;
	if (ret >= 0)
		fuse_bpf_file_accessed(file, ff->backing_file);
	return ret;
}

void *fuse_file_read_iter_finalize(struct fuse_bpf_args *args,
				   struct kiocb *iocb,
				   struct iov_iter *to)
{
	struct fuse_read_in *in;
	struct fuse_file_read_iter_io *io;
	ssize_t ret;
	int error = (s32)args->error_in;

	if (error > 0)
		error = -EIO;
	if (!args->in_numargs || !args->in_args[0].value)
		return ERR_PTR(error ? error : -EIO);
	in = (struct fuse_read_in *)args->in_args[0].value;
	io = container_of(in, struct fuse_file_read_iter_io, in);
	if (io->executed && io->actual_ret > 0)
		ret = io->actual_ret;
	else if (error)
		ret = error;
	else if (args->in_args[0].size != sizeof(*in))
		ret = -EIO;
	else if (io->executed)
		ret = io->actual_ret;
	else
		ret = -EIO;
	(void)iocb;
	(void)to;
	return ERR_PTR(ret);
}

int fuse_file_write_iter_initialize(struct fuse_bpf_args *args,
				    struct fuse_file_write_iter_io *io,
				    struct kiocb *iocb,
				    struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;
	size_t count = iov_iter_count(from);

	if (!ff || !ff->backing_file)
		return -EBADF;
	if (count > U32_MAX)
		return -E2BIG;

	memset(io, 0, sizeof(*io));
	io->in.fh = ff->fh;
	io->in.offset = iocb->ki_pos;
	io->in.size = count;
	io->in.flags = file->f_flags;
	io->out.ret = -EINPROGRESS;
	io->original_pos = iocb->ki_pos;
	io->original_count = count;
	io->actual_ret = -EINPROGRESS;

	*args = (struct fuse_bpf_args) {
		.opcode = FUSE_WRITE,
		/* Lower-only handles must never be sent to the daemon. */
		.nodeid = 0,
		.in_numargs = 1,
		.out_numargs = 1,
		.in_args[0] = (struct fuse_bpf_in_arg) {
			.size = sizeof(io->in),
			.value = &io->in,
		},
		.out_args[0] = (struct fuse_bpf_arg) {
			.size = sizeof(io->out),
			.value = &io->out,
		},
	};
	return 0;
}

int fuse_file_write_iter_backing(struct fuse_bpf_args *args,
				 struct kiocb *iocb,
				 struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;
	struct inode *inode = file_inode(file);
	struct fuse_write_in *in;
	struct fuse_file_write_iter_io *io;
	ssize_t ret;

	if (!ff || !ff->backing_file || args->opcode != FUSE_WRITE ||
	    args->nodeid || args->in_numargs != 1 ||
	    args->out_numargs != 1 || !args->in_args[0].value ||
	    !args->out_args[0].value ||
	    args->in_args[0].size != sizeof(*in) ||
	    args->out_args[0].size != sizeof(struct fuse_bpf_rw_out))
		return -EINVAL;

	in = (struct fuse_write_in *)args->in_args[0].value;
	io = container_of(in, struct fuse_file_write_iter_io, in);
	if (args->out_args[0].value != &io->out || in->fh != ff->fh ||
	    in->offset != io->original_pos ||
	    in->size != io->original_count ||
	    in->flags != file->f_flags || in->write_flags ||
	    in->lock_owner || in->padding)
		return -EOPNOTSUPP;
	ret = fuse_bpf_rw_flags(iocb, ff->backing_file);
	if (ret)
		return ret;

	inode_lock(inode);
	ret = fuse_bpf_sync_iter(iocb, from, ff->backing_file, WRITE,
				 &io->executed);
	if (ret > 0)
		fuse_bpf_copy_write_attr(file, ff->backing_file);
	inode_unlock(inode);
	io->actual_ret = ret;
	io->out.ret = ret;
	return ret < 0 ? ret : 0;
}

void *fuse_file_write_iter_finalize(struct fuse_bpf_args *args,
				    struct kiocb *iocb,
				    struct iov_iter *from)
{
	struct fuse_write_in *in;
	struct fuse_file_write_iter_io *io;
	ssize_t ret;
	int error = (s32)args->error_in;

	if (error > 0)
		error = -EIO;
	if (!args->in_numargs || !args->in_args[0].value)
		return ERR_PTR(error ? error : -EIO);
	in = (struct fuse_write_in *)args->in_args[0].value;
	io = container_of(in, struct fuse_file_write_iter_io, in);
	if (io->executed && io->actual_ret > 0)
		ret = io->actual_ret;
	else if (error)
		ret = error;
	else if (args->in_args[0].size != sizeof(*in))
		ret = -EIO;
	else if (io->executed)
		ret = io->actual_ret;
	else
		ret = -EIO;
	(void)iocb;
	(void)from;
	return ERR_PTR(ret);
}

int fuse_release_initialize(struct fuse_bpf_args *args,
			    struct fuse_release_in *in,
			    struct inode *inode, struct fuse_file *ff)
{
	struct fuse_req *req;
	u32 opcode;

	if (!ff || !ff->reserved_req)
		return -EINVAL;
	req = ff->reserved_req;
	opcode = req->in.h.opcode;
	if (opcode != FUSE_RELEASE && opcode != FUSE_RELEASEDIR)
		return -EINVAL;

	/* The lower file is no longer needed after the last ff reference. */
	fuse_file_put_backing(ff);
	*in = req->misc.release.in;
	*args = (struct fuse_bpf_args) {
		/* The daemon did not open this lower-only handle. */
		.nodeid = 0,
		.opcode = opcode,
		.in_numargs = 1,
		.in_args[0] = (struct fuse_bpf_in_arg) {
			.size = sizeof(*in),
			.value = in,
		},
	};
	(void)inode;
	return 0;
}

int fuse_release_backing(struct fuse_bpf_args *args,
			 struct inode *inode, struct fuse_file *ff)
{
	(void)args;
	(void)inode;
	(void)ff;
	return 0;
}

void *fuse_release_finalize(struct fuse_bpf_args *args,
			    struct inode *inode, struct fuse_file *ff)
{
	(void)args;
	(void)inode;
	(void)ff;
	return NULL;
}
