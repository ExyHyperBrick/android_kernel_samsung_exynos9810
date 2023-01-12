// SPDX-License-Identifier: GPL-2.0
/*
 * FUSE-BPF request dispatcher
 * Copyright (c) 2021 Google LLC
 */

#include "fuse_i.h"

#include <linux/errno.h>
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
	struct bpf_prog *new_prog = NULL;
	struct file *file;
	int ret;

	switch (entry->out.bpf_action) {
	case FUSE_ACTION_KEEP:
		if (!parent)
			return 0;
		new_prog = get_fuse_inode(parent)->bpf;
		if (new_prog)
			bpf_prog_inc(new_prog);
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

	if (*prog)
		bpf_prog_put(*prog);
	*prog = new_prog;
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
