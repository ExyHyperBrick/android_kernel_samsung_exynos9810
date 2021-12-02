/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "fuse_i.h"

#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/xattr.h>
#include <linux/posix_acl.h>

static bool fuse_use_readdirplus(struct inode *dir, struct dir_context *ctx)
{
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_inode *fi = get_fuse_inode(dir);

	if (!fc->do_readdirplus)
		return false;
	if (!fc->readdirplus_auto)
		return true;
	if (test_and_clear_bit(FUSE_I_ADVISE_RDPLUS, &fi->state))
		return true;
	if (ctx->pos == 0)
		return true;
	return false;
}

static void fuse_advise_use_readdirplus(struct inode *dir)
{
	struct fuse_inode *fi = get_fuse_inode(dir);

	set_bit(FUSE_I_ADVISE_RDPLUS, &fi->state);
}

static inline void fuse_dentry_settime(struct dentry *entry, u64 time)
{
	get_fuse_dentry(entry)->time = time;
}

static inline u64 fuse_dentry_time(struct dentry *entry)
{
	return get_fuse_dentry(entry)->time;
}

void fuse_init_dentry_root(struct dentry *root, struct file *backing_dir)
{
#ifdef CONFIG_FUSE_BPF
	struct fuse_dentry *fd = get_fuse_dentry(root);
	struct path path = { };

	if (backing_dir && fd) {
		path = backing_dir->f_path;
		path_get(&path);
		fuse_replace_backing_path(fd, &path);
	}
#else
	(void)root;
	(void)backing_dir;
#endif
}

/*
 * Set dentry and possibly attribute timeouts from the lookup/mk*
 * replies
 */
void fuse_change_entry_timeout(struct dentry *entry,
			       struct fuse_entry_out *o)
{
	fuse_dentry_settime(entry,
		time_to_jiffies(o->entry_valid, o->entry_valid_nsec));
}

u64 entry_attr_timeout(struct fuse_entry_out *o)
{
	return time_to_jiffies(o->attr_valid, o->attr_valid_nsec);
}

/*
 * Mark the attributes as stale, so that at the next call to
 * ->getattr() they will be fetched from userspace
 */
void fuse_invalidate_attr(struct inode *inode)
{
	get_fuse_inode(inode)->i_time = 0;
}

/**
 * Mark the attributes as stale due to an atime change.  Avoid the invalidate if
 * atime is not used.
 */
void fuse_invalidate_atime(struct inode *inode)
{
	if (!IS_RDONLY(inode))
		fuse_invalidate_attr(inode);
}

/*
 * Just mark the entry as stale, so that a next attempt to look it up
 * will result in a new lookup call to userspace
 *
 * This is called when a dentry is about to become negative and the
 * timeout is unknown (unlink, rmdir, rename and in some cases
 * lookup)
 */
void fuse_invalidate_entry_cache(struct dentry *entry)
{
	fuse_dentry_settime(entry, 0);
}

/*
 * Same as fuse_invalidate_entry_cache(), but also try to remove the
 * dentry from the hash
 */
static void fuse_invalidate_entry(struct dentry *entry)
{
	d_invalidate(entry);
	fuse_invalidate_entry_cache(entry);
}

static void fuse_lookup_init(struct fuse_conn *fc, struct fuse_args *args,
			     u64 nodeid, const struct qstr *name,
			     struct fuse_entry_out *outarg)
{
	memset(outarg, 0, sizeof(struct fuse_entry_out));
	args->in.h.opcode = FUSE_LOOKUP;
	args->in.h.nodeid = nodeid;
	args->in.numargs = 1;
	args->in.args[0].size = name->len + 1;
	args->in.args[0].value = name->name;
	args->out.numargs = 1;
	args->out.args[0].size = sizeof(struct fuse_entry_out);
	args->out.args[0].value = outarg;
}

u64 fuse_get_attr_version(struct fuse_conn *fc)
{
	u64 curr_version;

	/*
	 * The spin lock isn't actually needed on 64bit archs, but we
	 * don't yet care too much about such optimizations.
	 */
	spin_lock(&fc->lock);
	curr_version = fc->attr_version;
	spin_unlock(&fc->lock);

	return curr_version;
}

/*
 * Check whether the dentry is still valid
 *
 * If the entry validity timeout has expired and the dentry is
 * positive, try to redo the lookup.  If the lookup results in a
 * different inode, then let the VFS invalidate the dentry and redo
 * the lookup once more.  If the lookup results in the same inode,
 * then refresh the attributes, timeouts and mark the dentry valid.
 */
static int fuse_dentry_revalidate(struct dentry *entry, unsigned int flags)
{
	struct inode *inode;
	struct dentry *parent;
	struct fuse_conn *fc;
	struct fuse_inode *fi;
	int ret;

	inode = d_inode_rcu(entry);
	if (inode && fuse_is_bad(inode))
		goto invalid;

#ifdef CONFIG_FUSE_BPF
	if (fuse_has_backing_path(entry) ||
	    fuse_inode_has_backing(inode)) {
		if (flags & LOOKUP_RCU)
			return -ECHILD;
		ret = fuse_revalidate_backing(entry, flags);
		if (ret <= 0)
			goto out;
	}
#endif

	if (time_before64(fuse_dentry_time(entry), get_jiffies_64()) ||
	    (flags & LOOKUP_REVAL)) {
		struct fuse_entry_out outarg;
		FUSE_ARGS(args);
		struct fuse_forget_link *forget;
		u64 attr_version;

		/* For negative dentries, always do a fresh lookup */
		if (!inode)
			goto invalid;

		ret = -ECHILD;
		if (flags & LOOKUP_RCU)
			goto out;

		fc = get_fuse_conn(inode);
		parent = dget_parent(entry);
#ifdef CONFIG_FUSE_BPF
		if (fuse_inode_has_backing(inode)) {
			ret = fuse_inode_has_backing(d_inode(parent)) &&
				fuse_has_backing_path(entry) ? 1 : 0;
			dput(parent);
			goto out;
		}
#endif

		forget = fuse_alloc_forget();
		ret = -ENOMEM;
		if (!forget) {
			dput(parent);
			goto out;
		}

		attr_version = fuse_get_attr_version(fc);

		fuse_lookup_init(fc, &args, get_node_id(d_inode(parent)),
				 &entry->d_name, &outarg);
		ret = fuse_simple_request(fc, &args);
		dput(parent);
		/* Zero nodeid is same as -ENOENT */
		if (!ret && !outarg.nodeid)
			ret = -ENOENT;
		if (!ret) {
			fi = get_fuse_inode(inode);
			if (outarg.nodeid != get_node_id(inode)) {
				fuse_queue_forget(fc, forget, outarg.nodeid, 1);
				goto invalid;
			}
			spin_lock(&fc->lock);
			fi->nlookup++;
			spin_unlock(&fc->lock);
		}
		kfree(forget);
		if (ret == -ENOMEM)
			goto out;
		if (ret || fuse_invalid_attr(&outarg.attr) ||
		    (outarg.attr.mode ^ inode->i_mode) & S_IFMT)
			goto invalid;

		forget_all_cached_acls(inode);
		fuse_change_attributes(inode, &outarg.attr,
				       entry_attr_timeout(&outarg),
				       attr_version);
		fuse_change_entry_timeout(entry, &outarg);
	} else if (inode) {
		fi = get_fuse_inode(inode);
		if (flags & LOOKUP_RCU) {
			if (test_bit(FUSE_I_INIT_RDPLUS, &fi->state))
				return -ECHILD;
		} else if (test_and_clear_bit(FUSE_I_INIT_RDPLUS, &fi->state)) {
			parent = dget_parent(entry);
			fuse_advise_use_readdirplus(d_inode(parent));
			dput(parent);
		}
	}
	ret = 1;
out:
	return ret;

invalid:
	ret = 0;
	goto out;
}

/*
 * Get the canonical path. Since we must translate to a path, this must be done
 * in the context of the userspace daemon, however, the userspace daemon cannot
 * look up paths on its own. Instead, we handle the lookup as a special case
 * inside of the write request.
 */
static void fuse_dentry_canonical_path(const struct path *path, struct path *canonical_path) {
	struct inode *inode = path->dentry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	int err;
	char *path_name;

#ifdef CONFIG_FUSE_BPF
	if (fuse_inode_has_backing(inode))
		goto default_path;
#endif
	req = fuse_get_req(fc, 1);
	err = PTR_ERR(req);
	if (IS_ERR(req))
		goto default_path;

	path_name = (char*)__get_free_page(GFP_KERNEL);
	if (!path_name) {
		fuse_put_request(fc, req);
		goto default_path;
	}

	req->in.h.opcode = FUSE_CANONICAL_PATH;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 0;
	req->out.numargs = 1;
	req->out.args[0].size = PATH_MAX;
	req->out.args[0].value = path_name;
	req->canonical_path = canonical_path;
	req->out.argvar = 1;
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	free_page((unsigned long)path_name);
	if (!err)
		return;
default_path:
	canonical_path->dentry = path->dentry;
	canonical_path->mnt = path->mnt;
	path_get(canonical_path);
}

static int invalid_nodeid(u64 nodeid)
{
	return !nodeid || nodeid == FUSE_ROOT_ID;
}

static int fuse_dentry_init(struct dentry *dentry)
{
	dentry->d_fsdata = kzalloc(sizeof(struct fuse_dentry), GFP_KERNEL);
#ifdef CONFIG_FUSE_BPF
	if (dentry->d_fsdata)
		fuse_backing_path_init(dentry->d_fsdata);
#endif

	return dentry->d_fsdata ? 0 : -ENOMEM;
}
static void fuse_dentry_release(struct dentry *dentry)
{
	struct fuse_dentry *fd = get_fuse_dentry(dentry);

#ifdef CONFIG_FUSE_BPF
	struct path path = { };

	fuse_replace_backing_path(fd, &path);
#endif
	kfree_rcu(fd, rcu);
}

const struct dentry_operations fuse_dentry_operations = {
	.d_revalidate	= fuse_dentry_revalidate,
	.d_init		= fuse_dentry_init,
	.d_release	= fuse_dentry_release,
	.d_canonical_path = fuse_dentry_canonical_path,
};

const struct dentry_operations fuse_root_dentry_operations = {
	.d_init		= fuse_dentry_init,
	.d_release	= fuse_dentry_release,
	.d_canonical_path = fuse_dentry_canonical_path,
};

int fuse_valid_type(int m)
{
	return S_ISREG(m) || S_ISDIR(m) || S_ISLNK(m) || S_ISCHR(m) ||
		S_ISBLK(m) || S_ISFIFO(m) || S_ISSOCK(m);
}

bool fuse_invalid_attr(struct fuse_attr *attr)
{
	return !fuse_valid_type(attr->mode) ||
		attr->size > LLONG_MAX;
}

int fuse_lookup_name(struct super_block *sb, u64 nodeid, const struct qstr *name,
		     struct fuse_entry_out *outarg, struct inode **inode)
{
	struct fuse_conn *fc = get_fuse_conn_super(sb);
	FUSE_ARGS(args);
	struct fuse_forget_link *forget;
	u64 attr_version;
	int err;

	*inode = NULL;
	err = -ENAMETOOLONG;
	if (name->len > FUSE_NAME_MAX)
		goto out;


	forget = fuse_alloc_forget();
	err = -ENOMEM;
	if (!forget)
		goto out;

	attr_version = fuse_get_attr_version(fc);

	fuse_lookup_init(fc, &args, nodeid, name, outarg);
	err = fuse_simple_request(fc, &args);
	/* Zero nodeid is same as -ENOENT, but with valid timeout */
	if (err || !outarg->nodeid)
		goto out_put_forget;

	err = -EIO;
	if (!outarg->nodeid)
		goto out_put_forget;
	if (fuse_invalid_attr(&outarg->attr))
		goto out_put_forget;

	*inode = fuse_iget(sb, outarg->nodeid, outarg->generation,
			   &outarg->attr, entry_attr_timeout(outarg),
			   attr_version);
	err = -ENOMEM;
	if (!*inode) {
		fuse_queue_forget(fc, forget, outarg->nodeid, 1);
		goto out;
	}
	err = 0;

 out_put_forget:
	kfree(forget);
 out:
	return err;
}

static struct dentry *fuse_lookup(struct inode *dir, struct dentry *entry,
				  unsigned int flags)
{
	int err;
	struct fuse_entry_out outarg;
	struct inode *inode;
	struct dentry *newent;
	bool outarg_valid = true;
	bool locked;

	if (fuse_is_bad(dir))
		return ERR_PTR(-EIO);

#ifdef CONFIG_FUSE_BPF
	{
		struct fuse_err_ret result;

		result = fuse_bpf_backing(dir, struct fuse_lookup_io,
				 fuse_lookup_initialize,
				 fuse_lookup_backing,
				 fuse_lookup_finalize,
				 dir, entry, flags);
		if (result.ret) {
			/*
			 * Positive lookups are completed by the finalizer through
			 * d_splice_alias(). Complete handled negative lookups too;
			 * d_add() also leaves DCACHE_PAR_LOOKUP before atomic_open
			 * reuses the dentry for creation.
			 */
			if (!result.result && d_really_is_negative(entry))
				d_add(entry, NULL);
			return result.result;
		}
	}
	/* A backing-only inode has no valid daemon fallback. */
	if (fuse_inode_has_backing(dir) && !get_node_id(dir))
		return ERR_PTR(-EOPNOTSUPP);
#endif

	locked = fuse_lock_inode(dir);
	err = fuse_lookup_name(dir->i_sb, get_node_id(dir), &entry->d_name,
			       &outarg, &inode);
	fuse_unlock_inode(dir, locked);
	if (err == -ENOENT) {
		outarg_valid = false;
		err = 0;
	}
	if (err)
		goto out_err;

	err = -EIO;
	if (inode && get_node_id(inode) == FUSE_ROOT_ID)
		goto out_iput;

	newent = d_splice_alias(inode, entry);
	err = PTR_ERR(newent);
	if (IS_ERR(newent))
		goto out_err;

	entry = newent ? newent : entry;
	if (outarg_valid)
		fuse_change_entry_timeout(entry, &outarg);
	else
		fuse_invalidate_entry_cache(entry);

	fuse_advise_use_readdirplus(dir);
	return newent;

 out_iput:
	iput(inode);
 out_err:
	return ERR_PTR(err);
}

/*
 * Atomic create+open operation
 *
 * If the filesystem doesn't support this, then fall back to separate
 * 'mknod' + 'open' requests.
 */
static int fuse_create_open(struct inode *dir, struct dentry *entry,
			    struct file *file, unsigned flags,
			    umode_t mode, int *opened)
{
	int err;
	struct inode *inode;
	struct fuse_conn *fc = get_fuse_conn(dir);
	FUSE_ARGS(args);
	struct fuse_forget_link *forget;
	struct fuse_create_in inarg;
	struct fuse_open_out outopen;
	struct fuse_entry_out outentry;
	struct fuse_file *ff;

	/* Userspace expects S_IFREG in create mode */
	BUG_ON((mode & S_IFMT) != S_IFREG);

#ifdef CONFIG_FUSE_BPF
	if (fuse_inode_has_backing(dir))
		return -EOPNOTSUPP;
#endif
	forget = fuse_alloc_forget();
	err = -ENOMEM;
	if (!forget)
		goto out_err;

	err = -ENOMEM;
	ff = fuse_file_alloc(fc);
	if (!ff)
		goto out_put_forget_req;

	if (!fc->dont_mask)
		mode &= ~current_umask();

	flags &= ~O_NOCTTY;
	memset(&inarg, 0, sizeof(inarg));
	memset(&outentry, 0, sizeof(outentry));
	inarg.flags = flags;
	inarg.mode = mode;
	inarg.umask = current_umask();
	args.in.h.opcode = FUSE_CREATE;
	args.in.h.nodeid = get_node_id(dir);
	args.in.numargs = 2;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.in.args[1].size = entry->d_name.len + 1;
	args.in.args[1].value = entry->d_name.name;
	args.out.numargs = 2;
	args.out.args[0].size = sizeof(outentry);
	args.out.args[0].value = &outentry;
	args.out.args[1].size = sizeof(outopen);
	args.out.args[1].value = &outopen;
	err = fuse_simple_request(fc, &args);
	if (err)
		goto out_free_ff;

	err = -EIO;
	if (!S_ISREG(outentry.attr.mode) || invalid_nodeid(outentry.nodeid) ||
	    fuse_invalid_attr(&outentry.attr))
		goto out_free_ff;

	ff->fh = outopen.fh;
	ff->nodeid = outentry.nodeid;
	ff->open_flags = outopen.open_flags;
	inode = fuse_iget(dir->i_sb, outentry.nodeid, outentry.generation,
			  &outentry.attr, entry_attr_timeout(&outentry), 0);
	if (!inode) {
		flags &= ~(O_CREAT | O_EXCL | O_TRUNC);
		fuse_sync_release(ff, flags);
		fuse_queue_forget(fc, forget, outentry.nodeid, 1);
		err = -ENOMEM;
		goto out_err;
	}
	kfree(forget);
	d_instantiate(entry, inode);
	fuse_change_entry_timeout(entry, &outentry);
	fuse_invalidate_attr(dir);
	err = finish_open(file, entry, generic_file_open, opened);
	if (err) {
		fuse_sync_release(ff, flags);
	} else {
		file->private_data = fuse_file_get(ff);
		fuse_finish_open(inode, file);
	}
	return err;

out_free_ff:
	fuse_file_free(ff);
out_put_forget_req:
	kfree(forget);
out_err:
	return err;
}

static int fuse_mknod(struct inode *, struct dentry *, umode_t, dev_t);
#ifdef CONFIG_FUSE_BPF
static int fuse_bpf_create_open(struct inode *dir, struct dentry *entry,
				struct file *file, unsigned int flags,
				umode_t mode, int *opened);
#endif
static int fuse_atomic_open(struct inode *dir, struct dentry *entry,
			    struct file *file, unsigned flags,
			    umode_t mode, int *opened)
{
	int err;
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct dentry *res = NULL;

	if (fuse_is_bad(dir))
		return -EIO;

	if (d_in_lookup(entry)) {
		res = fuse_lookup(dir, entry, 0);
		if (IS_ERR(res))
			return PTR_ERR(res);

		if (res)
			entry = res;
	}

	if (!(flags & O_CREAT) || d_really_is_positive(entry))
		goto no_open;

	/* Only creates */
#ifdef CONFIG_FUSE_BPF
	if (fuse_inode_has_backing(dir)) {
		err = fuse_bpf_create_open(dir, entry, file, flags,
					   mode, opened);
		goto out_dput;
	}
#endif
	*opened |= FILE_CREATED;

	if (fc->no_create)
		goto mknod;

	err = fuse_create_open(dir, entry, file, flags, mode, opened);
	if (err == -ENOSYS) {
		fc->no_create = 1;
		goto mknod;
	}
out_dput:
	dput(res);
	return err;

mknod:
	err = fuse_mknod(dir, entry, mode, 0);
	if (err)
		goto out_dput;
no_open:
	return finish_no_open(file, res);
}

/*
 * Code shared between mknod, mkdir, symlink and link
 */
static int create_new_entry(struct fuse_conn *fc, struct fuse_args *args,
			    struct inode *dir, struct dentry *entry,
			    umode_t mode)
{
	struct fuse_entry_out outarg;
	struct inode *inode;
	int err;
	struct fuse_forget_link *forget;

	if (fuse_is_bad(dir))
		return -EIO;

#ifdef CONFIG_FUSE_BPF
	if (fuse_inode_has_backing(dir))
		return -EOPNOTSUPP;
#endif
	forget = fuse_alloc_forget();
	if (!forget)
		return -ENOMEM;

	memset(&outarg, 0, sizeof(outarg));
	args->in.h.nodeid = get_node_id(dir);
	args->out.numargs = 1;
	args->out.args[0].size = sizeof(outarg);
	args->out.args[0].value = &outarg;
	err = fuse_simple_request(fc, args);
	if (err)
		goto out_put_forget_req;

	err = -EIO;
	if (invalid_nodeid(outarg.nodeid) || fuse_invalid_attr(&outarg.attr))
		goto out_put_forget_req;

	if ((outarg.attr.mode ^ mode) & S_IFMT)
		goto out_put_forget_req;

	inode = fuse_iget(dir->i_sb, outarg.nodeid, outarg.generation,
			  &outarg.attr, entry_attr_timeout(&outarg), 0);
	if (!inode) {
		fuse_queue_forget(fc, forget, outarg.nodeid, 1);
		return -ENOMEM;
	}
	kfree(forget);

	err = d_instantiate_no_diralias(entry, inode);
	if (err)
		return err;

	fuse_change_entry_timeout(entry, &outarg);
	fuse_invalidate_attr(dir);
	return 0;

 out_put_forget_req:
	kfree(forget);
	return err;
}

#ifdef CONFIG_FUSE_BPF
static int fuse_bpf_mknod(struct inode *dir, struct dentry *entry,
			  umode_t mode, dev_t rdev, bool excl);
static int fuse_bpf_mkdir(struct inode *dir, struct dentry *entry,
			  umode_t mode);
#endif

static int fuse_mknod(struct inode *dir, struct dentry *entry, umode_t mode,
		      dev_t rdev)
{
	struct fuse_mknod_in inarg;
	struct fuse_conn *fc = get_fuse_conn(dir);
	FUSE_ARGS(args);

	if (!fc->dont_mask)
		mode &= ~current_umask();

#ifdef CONFIG_FUSE_BPF
	if (fuse_inode_has_backing(dir))
		return fuse_bpf_mknod(dir, entry, mode, rdev, true);
#endif

	memset(&inarg, 0, sizeof(inarg));
	inarg.mode = mode;
	inarg.rdev = new_encode_dev(rdev);
	inarg.umask = current_umask();
	args.in.h.opcode = FUSE_MKNOD;
	args.in.numargs = 2;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.in.args[1].size = entry->d_name.len + 1;
	args.in.args[1].value = entry->d_name.name;
	return create_new_entry(fc, &args, dir, entry, mode);
}

static int fuse_create(struct inode *dir, struct dentry *entry, umode_t mode,
		       bool excl)
{
#ifdef CONFIG_FUSE_BPF
	if (fuse_inode_has_backing(dir))
		return fuse_bpf_mknod(dir, entry, mode, 0, excl);
#endif
	return fuse_mknod(dir, entry, mode, 0);
}

static int fuse_mkdir(struct inode *dir, struct dentry *entry, umode_t mode)
{
	struct fuse_mkdir_in inarg;
	struct fuse_conn *fc = get_fuse_conn(dir);
	FUSE_ARGS(args);

	if (!fc->dont_mask)
		mode &= ~current_umask();

#ifdef CONFIG_FUSE_BPF
	if (fuse_inode_has_backing(dir))
		return fuse_bpf_mkdir(dir, entry, mode);
#endif

	memset(&inarg, 0, sizeof(inarg));
	inarg.mode = mode;
	inarg.umask = current_umask();
	args.in.h.opcode = FUSE_MKDIR;
	args.in.numargs = 2;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.in.args[1].size = entry->d_name.len + 1;
	args.in.args[1].value = entry->d_name.name;
	return create_new_entry(fc, &args, dir, entry, S_IFDIR);
}

#ifdef CONFIG_FUSE_BPF
/*
 * Route operations which are intentionally lower-only in this checkpoint.
 * A userspace prefilter may approve the request, but a lower action is
 * mandatory and postfiltering is rejected before any irreversible mutation.
 */
static int fuse_bpf_prepare_lower_only(struct inode *inode,
				       struct fuse_bpf_args *args,
				       struct fuse_bpf_args *backup)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct bpf_prog *prog;
	bool locked;
	ssize_t res;
	int actions;
	int ret;

	prog = fuse_bpf_get_prog(fc, fi);
	ret = fuse_bpf_prepare_prefilter(args, backup);
	if (ret)
		goto out_prog;

	actions = prog ? fuse_bpf_run_filter(prog, args) :
			 FUSE_BPF_BACKING;
	if (actions < 0) {
		ret = actions;
		goto out_prog;
	}
	if (!(actions & FUSE_BPF_BACKING) ||
	    (actions & FUSE_BPF_POST_FILTER)) {
		ret = -EOPNOTSUPP;
		goto out_prog;
	}
	if (actions & FUSE_BPF_USER_FILTER) {
		if (!args->nodeid) {
			ret = -EOPNOTSUPP;
			goto out_prog;
		}
		locked = fuse_lock_inode(inode);
		res = fuse_bpf_simple_request(fc, args);
		fuse_unlock_inode(inode, locked);
		if (res < 0) {
			ret = res;
			goto out_prog;
		}
	}
	ret = fuse_bpf_prepare_backing(args, backup);

out_prog:
	if (prog)
		bpf_prog_put(prog);
	return ret;
}

static int fuse_bpf_create_paths(struct inode *dir,
				  struct dentry *entry,
				  struct path *parent_path,
				  struct path *child_path)
{
	struct fuse_inode *fi = get_fuse_inode(dir);
	struct inode *backing_dir;

	*parent_path = (struct path) { };
	*child_path = (struct path) { };
	if (entry->d_parent == entry || d_inode(entry->d_parent) != dir ||
	    d_really_is_positive(entry))
		return -ESTALE;
	if (!get_fuse_backing_path(entry->d_parent, parent_path))
		return -EBADF;
	if (!get_fuse_backing_path(entry, child_path)) {
		fuse_put_backing_path(parent_path);
		return -EBADF;
	}

	backing_dir = d_inode(parent_path->dentry);
	if (!backing_dir || !S_ISDIR(backing_dir->i_mode) ||
	    backing_dir != fi->backing_inode ||
	    parent_path->mnt != fi->backing_mnt ||
	    child_path->mnt != parent_path->mnt ||
	    child_path->dentry->d_parent != parent_path->dentry ||
	    d_really_is_positive(child_path->dentry) ||
	    d_unhashed(child_path->dentry) ||
	    child_path->dentry->d_name.len != entry->d_name.len ||
	    memcmp(child_path->dentry->d_name.name,
		   entry->d_name.name, entry->d_name.len)) {
		fuse_put_backing_path(child_path);
		fuse_put_backing_path(parent_path);
		return -ESTALE;
	}
	return 0;
}

static void fuse_bpf_copy_parent_attr(struct inode *dir,
				      struct inode *backing_dir)
{
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_inode *fi = get_fuse_inode(dir);

	spin_lock(&fc->lock);
	dir->i_atime = backing_dir->i_atime;
	dir->i_mtime = backing_dir->i_mtime;
	dir->i_ctime = backing_dir->i_ctime;
	i_size_write(dir, i_size_read(backing_dir));
	set_nlink(dir, backing_dir->i_nlink);
	fi->attr_version = ++fc->attr_version;
	spin_unlock(&fc->lock);
}

static int fuse_bpf_rollback_create(const struct path *parent_path,
				    const struct path *child_path,
				    bool directory)
{
	struct inode *backing_dir = d_inode(parent_path->dentry);
	int ret;

	if (!backing_dir || !child_path->dentry ||
	    child_path->dentry->d_parent != parent_path->dentry ||
	    child_path->mnt != parent_path->mnt)
		return -ESTALE;

	inode_lock_nested(backing_dir, I_MUTEX_PARENT);
	if (directory)
		ret = vfs_rmdir2(parent_path->mnt, backing_dir,
				 child_path->dentry);
	else
		ret = vfs_unlink2(parent_path->mnt, backing_dir,
				  child_path->dentry, NULL);
	inode_unlock(backing_dir);
	return ret;
}

static int fuse_bpf_finish_create(struct inode *dir, struct dentry *entry,
				  const struct path *parent_path,
				  const struct path *child_path,
				  umode_t type)
{
	struct inode *backing_dir = d_inode(parent_path->dentry);
	struct inode *backing_inode = d_inode(child_path->dentry);
	struct fuse_entry_bpf bpf_entry = { };
	struct inode *inode;
	int ret;

	if (!backing_dir || !backing_inode ||
	    (backing_inode->i_mode & S_IFMT) != type ||
	    unlikely(d_unhashed(child_path->dentry)))
		return -EIO;

	inode = fuse_iget_backing(dir->i_sb, 0, backing_inode,
				  child_path->mnt);
	if (!inode)
		return -ENOMEM;
	ret = fuse_handle_bpf_prog(&bpf_entry, dir,
				   &get_fuse_inode(inode)->bpf);
	if (ret) {
		iput(inode);
		return ret;
	}
	ret = d_instantiate_no_diralias(entry, inode);
	if (ret)
		return ret;

	fuse_bpf_copy_parent_attr(dir, backing_dir);
	fuse_invalidate_entry_cache(entry);
	return 0;
}

static char *fuse_bpf_create_name(struct dentry *entry, size_t *name_len)
{
	char *name;

	if (!entry->d_name.len || entry->d_name.len > FUSE_NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);
	*name_len = entry->d_name.len + 1;
	name = kmalloc(*name_len, GFP_KERNEL);
	if (!name)
		return ERR_PTR(-ENOMEM);
	memcpy(name, entry->d_name.name, entry->d_name.len);
	name[entry->d_name.len] = '\0';
	return name;
}

static int fuse_bpf_mknod(struct inode *dir, struct dentry *entry,
			  umode_t mode, dev_t rdev, bool excl)
{
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_mknod_in inarg = { };
	struct fuse_mknod_in original;
	struct fuse_bpf_args args = { };
	struct fuse_bpf_args backup = { };
	struct path parent_path = { };
	struct path child_path = { };
	struct inode *backing_dir;
	char *name;
	size_t name_len;
	bool created = false;
	int rollback;
	int ret;

	if (!fc->dont_mask)
		mode &= ~current_umask();
	switch (mode & S_IFMT) {
	case S_IFREG:
	case S_IFCHR:
	case S_IFBLK:
	case S_IFIFO:
	case S_IFSOCK:
		break;
	default:
		return -EINVAL;
	}

	name = fuse_bpf_create_name(entry, &name_len);
	if (IS_ERR(name))
		return PTR_ERR(name);
	inarg.mode = mode;
	inarg.rdev = new_encode_dev(rdev);
	inarg.umask = current_umask();
	original = inarg;
	args.nodeid = get_node_id(dir);
	args.opcode = FUSE_MKNOD;
	args.in_numargs = 2;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;
	args.in_args[1].size = name_len;
	args.in_args[1].value = name;

	ret = fuse_bpf_prepare_lower_only(dir, &args, &backup);
	if (ret)
		goto out_name;
	if (args.opcode != FUSE_MKNOD ||
	    args.nodeid != get_node_id(dir) || args.flags ||
	    args.in_numargs != 2 || args.out_numargs || args.error_in ||
	    args.in_args[0].value != &inarg ||
	    args.in_args[1].value != name ||
	    args.in_args[0].size != sizeof(inarg) ||
	    args.in_args[1].size != name_len ||
	    args.in_args[0].end_offset != (char *)&inarg + sizeof(inarg) ||
	    args.in_args[1].end_offset != name + name_len ||
	    memcmp(&inarg, &original, sizeof(inarg)) ||
	    name[name_len - 1] ||
	    memcmp(name, entry->d_name.name, name_len - 1)) {
		ret = -EOPNOTSUPP;
		goto out_name;
	}

	ret = fuse_bpf_create_paths(dir, entry, &parent_path,
				    &child_path);
	if (ret)
		goto out_name;
	backing_dir = d_inode(parent_path.dentry);
	ret = mnt_want_write(parent_path.mnt);
	if (ret)
		goto out_paths;

	inode_lock_nested(backing_dir, I_MUTEX_PARENT);
	if (S_ISREG(mode))
		ret = vfs_create2(parent_path.mnt, backing_dir,
				  child_path.dentry, mode, excl);
	else
		ret = vfs_mknod2(parent_path.mnt, backing_dir,
				 child_path.dentry, mode, rdev);
	inode_unlock(backing_dir);
	if (ret)
		goto out_write;
	created = true;

	ret = fuse_bpf_finish_create(dir, entry, &parent_path,
				     &child_path, mode & S_IFMT);
out_write:
	if (ret && created) {
		rollback = fuse_bpf_rollback_create(&parent_path,
					    &child_path, false);
		if (rollback)
			fuse_invalidate_entry_cache(entry);
		fuse_bpf_copy_parent_attr(dir, backing_dir);
	}
	mnt_drop_write(parent_path.mnt);
out_paths:
	fuse_put_backing_path(&child_path);
	fuse_put_backing_path(&parent_path);
out_name:
	kfree(name);
	return ret;
}

static int fuse_bpf_mkdir(struct inode *dir, struct dentry *entry,
			  umode_t mode)
{
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_mkdir_in inarg = { };
	struct fuse_mkdir_in original;
	struct fuse_bpf_args args = { };
	struct fuse_bpf_args backup = { };
	struct path parent_path = { };
	struct path child_path = { };
	struct inode *backing_dir;
	char *name;
	size_t name_len;
	bool created = false;
	int rollback;
	int ret;

	if (!fc->dont_mask)
		mode &= ~current_umask();
	name = fuse_bpf_create_name(entry, &name_len);
	if (IS_ERR(name))
		return PTR_ERR(name);
	inarg.mode = mode;
	inarg.umask = current_umask();
	original = inarg;
	args.nodeid = get_node_id(dir);
	args.opcode = FUSE_MKDIR;
	args.in_numargs = 2;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;
	args.in_args[1].size = name_len;
	args.in_args[1].value = name;

	ret = fuse_bpf_prepare_lower_only(dir, &args, &backup);
	if (ret)
		goto out_name;
	if (args.opcode != FUSE_MKDIR ||
	    args.nodeid != get_node_id(dir) || args.flags ||
	    args.in_numargs != 2 || args.out_numargs || args.error_in ||
	    args.in_args[0].value != &inarg ||
	    args.in_args[1].value != name ||
	    args.in_args[0].size != sizeof(inarg) ||
	    args.in_args[1].size != name_len ||
	    args.in_args[0].end_offset != (char *)&inarg + sizeof(inarg) ||
	    args.in_args[1].end_offset != name + name_len ||
	    memcmp(&inarg, &original, sizeof(inarg)) ||
	    name[name_len - 1] ||
	    memcmp(name, entry->d_name.name, name_len - 1)) {
		ret = -EOPNOTSUPP;
		goto out_name;
	}

	ret = fuse_bpf_create_paths(dir, entry, &parent_path,
				    &child_path);
	if (ret)
		goto out_name;
	backing_dir = d_inode(parent_path.dentry);
	ret = mnt_want_write(parent_path.mnt);
	if (ret)
		goto out_paths;

	inode_lock_nested(backing_dir, I_MUTEX_PARENT);
	ret = vfs_mkdir2(parent_path.mnt, backing_dir,
			 child_path.dentry, mode);
	inode_unlock(backing_dir);
	if (ret)
		goto out_write;
	created = true;

	ret = fuse_bpf_finish_create(dir, entry, &parent_path,
				     &child_path, S_IFDIR);
out_write:
	if (ret && created) {
		rollback = fuse_bpf_rollback_create(&parent_path,
					    &child_path, true);
		if (rollback)
			fuse_invalidate_entry_cache(entry);
		fuse_bpf_copy_parent_attr(dir, backing_dir);
	}
	mnt_drop_write(parent_path.mnt);
out_paths:
	fuse_put_backing_path(&child_path);
	fuse_put_backing_path(&parent_path);
out_name:
	kfree(name);
	return ret;
}

static int fuse_bpf_open_created(struct inode *inode, struct file *file)
{
	struct fuse_open_in in = { };
	struct fuse_open_out out = { };
	struct fuse_bpf_args args = { };
	int ret;

	ret = generic_file_open(inode, file);
	if (ret)
		return ret;

	in.flags = file->f_flags &
		~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
	args.nodeid = get_node_id(inode);
	args.opcode = FUSE_OPEN;
	args.in_numargs = 1;
	args.out_numargs = 1;
	args.in_args[0].size = sizeof(in);
	args.in_args[0].value = &in;
	args.out_args[0].size = sizeof(out);
	args.out_args[0].value = &out;
	return fuse_open_backing(&args, inode, file, false);
}

static int fuse_bpf_create_open(struct inode *dir, struct dentry *entry,
				struct file *file, unsigned int flags,
				umode_t mode, int *opened)
{
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_create_in inarg = { };
	struct fuse_create_in original;
	struct fuse_entry_out outentry = { };
	struct fuse_open_out outopen = { };
	struct fuse_bpf_args args = { };
	struct fuse_bpf_args backup = { };
	struct path parent_path = { };
	struct path child_path = { };
	struct inode *backing_dir;
	struct inode *backing_inode;
	struct fuse_file *ff;
	char *name;
	size_t name_len;
	bool created = false;
	int rollback;
	int ret;

	if ((mode & S_IFMT) != S_IFREG)
		return -EINVAL;
	if (!fc->dont_mask)
		mode &= ~current_umask();

	name = fuse_bpf_create_name(entry, &name_len);
	if (IS_ERR(name))
		return PTR_ERR(name);
	inarg.flags = file->f_flags & ~(O_CREAT | O_EXCL | O_NOCTTY);
	if (!fc->atomic_o_trunc)
		inarg.flags &= ~O_TRUNC;
	inarg.mode = mode;
	inarg.umask = current_umask();
	original = inarg;

	args.nodeid = get_node_id(dir);
	args.opcode = FUSE_CREATE;
	args.in_numargs = 2;
	args.out_numargs = 2;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;
	args.in_args[1].size = name_len;
	args.in_args[1].value = name;
	args.out_args[0].size = sizeof(outentry);
	args.out_args[0].value = &outentry;
	args.out_args[1].size = sizeof(outopen);
	args.out_args[1].value = &outopen;

	ret = fuse_bpf_prepare_lower_only(dir, &args, &backup);
	if (ret)
		goto out_name;
	if (args.opcode != FUSE_CREATE ||
	    args.nodeid != get_node_id(dir) || args.flags ||
	    args.in_numargs != 2 || args.out_numargs != 2 ||
	    args.error_in || args.in_args[0].value != &inarg ||
	    args.in_args[1].value != name ||
	    args.out_args[0].value != &outentry ||
	    args.out_args[1].value != &outopen ||
	    args.in_args[0].size != sizeof(inarg) ||
	    args.in_args[1].size != name_len ||
	    args.out_args[0].size != sizeof(outentry) ||
	    args.out_args[1].size != sizeof(outopen) ||
	    args.in_args[0].end_offset !=
			(char *)&inarg + sizeof(inarg) ||
	    args.in_args[1].end_offset != name + name_len ||
	    args.out_args[0].end_offset !=
			(char *)&outentry + sizeof(outentry) ||
	    args.out_args[1].end_offset !=
			(char *)&outopen + sizeof(outopen) ||
	    memcmp(&inarg, &original, sizeof(inarg)) ||
	    name[name_len - 1] ||
	    memcmp(name, entry->d_name.name, name_len - 1)) {
		ret = -EOPNOTSUPP;
		goto out_name;
	}

	ret = fuse_bpf_create_paths(dir, entry, &parent_path,
				    &child_path);
	if (ret)
		goto out_name;
	backing_dir = d_inode(parent_path.dentry);
	ret = mnt_want_write(parent_path.mnt);
	if (ret)
		goto out_paths;

	inode_lock_nested(backing_dir, I_MUTEX_PARENT);
	backing_inode = d_inode(child_path.dentry);
	if (backing_inode) {
		if (flags & O_EXCL)
			ret = -EEXIST;
		else if (!S_ISREG(backing_inode->i_mode))
			ret = S_ISDIR(backing_inode->i_mode) ?
				-EISDIR : -EOPNOTSUPP;
		else
			ret = 0;
	} else {
		ret = vfs_create2(parent_path.mnt, backing_dir,
				  child_path.dentry, mode,
				  !!(flags & O_EXCL));
		if (!ret)
			created = true;
	}
	inode_unlock(backing_dir);
	if (ret)
		goto out_write;

	ret = fuse_bpf_finish_create(dir, entry, &parent_path,
				     &child_path, S_IFREG);
	if (ret)
		goto out_write;

	mnt_drop_write(parent_path.mnt);
	fuse_put_backing_path(&child_path);
	fuse_put_backing_path(&parent_path);
	kfree(name);

	if (created)
		*opened |= FILE_CREATED;
	ret = finish_open(file, entry, fuse_bpf_open_created, opened);
	if (ret)
		return ret;

	ff = file->private_data;
	ff->fh = outopen.fh;
	ff->nodeid = get_node_id(d_inode(entry));
	ff->open_flags = outopen.open_flags;
	fuse_finish_open(d_inode(entry), file);
	return 0;

out_write:
	if (ret && created) {
		rollback = fuse_bpf_rollback_create(&parent_path,
					    &child_path, false);
		if (rollback)
			fuse_invalidate_entry_cache(entry);
		fuse_bpf_copy_parent_attr(dir, backing_dir);
	}
	mnt_drop_write(parent_path.mnt);
out_paths:
	fuse_put_backing_path(&child_path);
	fuse_put_backing_path(&parent_path);
out_name:
	kfree(name);
	return ret;
}

static int fuse_bpf_symlink(struct inode *dir, struct dentry *entry,
			    const char *link, size_t link_len)
{
	struct fuse_bpf_args args = { };
	struct fuse_bpf_args backup = { };
	struct path parent_path = { };
	struct path child_path = { };
	struct inode *backing_dir;
	struct inode *backing_inode;
	struct inode *inode;
	struct fuse_entry_bpf bpf_entry = { };
	char *name_copy;
	char *link_copy;
	size_t name_len;
	bool created = false;
	int rollback;
	int ret;

	if (!link_len || entry->d_name.len > FUSE_NAME_MAX ||
	    link_len > PATH_MAX)
		return -ENAMETOOLONG;
	name_len = entry->d_name.len + 1;
	name_copy = kmalloc(name_len, GFP_KERNEL);
	if (!name_copy)
		return -ENOMEM;
	memcpy(name_copy, entry->d_name.name, entry->d_name.len);
	name_copy[entry->d_name.len] = '\0';
	link_copy = kmemdup(link, link_len, GFP_KERNEL);
	if (!link_copy) {
		ret = -ENOMEM;
		goto out_name;
	}

	args.nodeid = get_node_id(dir);
	args.opcode = FUSE_SYMLINK;
	args.in_numargs = 2;
	args.in_args[0].size = name_len;
	args.in_args[0].value = name_copy;
	args.in_args[1].size = link_len;
	args.in_args[1].value = link_copy;

	ret = fuse_bpf_prepare_lower_only(dir, &args, &backup);
	if (ret)
		goto out_link;
	if (args.opcode != FUSE_SYMLINK ||
	    args.nodeid != get_node_id(dir) || args.flags ||
	    args.in_numargs != 2 || args.out_numargs ||
	    args.in_args[0].value != name_copy ||
	    args.in_args[1].value != link_copy ||
	    args.in_args[0].size != name_len ||
	    args.in_args[1].size != link_len || args.error_in ||
	    args.in_args[0].end_offset != name_copy + name_len ||
	    args.in_args[1].end_offset != link_copy + link_len ||
	    name_copy[name_len - 1] || link_copy[link_len - 1] ||
	    memcmp(name_copy, entry->d_name.name, name_len - 1) ||
	    memcmp(link_copy, link, link_len)) {
		ret = -EOPNOTSUPP;
		goto out_link;
	}

	ret = fuse_bpf_create_paths(dir, entry, &parent_path,
				    &child_path);
	if (ret)
		goto out_link;
	backing_dir = d_inode(parent_path.dentry);

	ret = mnt_want_write(parent_path.mnt);
	if (ret)
		goto out_paths;
	inode_lock_nested(backing_dir, I_MUTEX_PARENT);
	ret = vfs_symlink2(parent_path.mnt, backing_dir,
			   child_path.dentry, link_copy);
	inode_unlock(backing_dir);
	if (ret)
		goto out_write;
	created = true;

	backing_inode = d_inode(child_path.dentry);
	if (!backing_inode || !S_ISLNK(backing_inode->i_mode) ||
	    unlikely(d_unhashed(child_path.dentry))) {
		ret = -EIO;
		goto out_write;
	}
	inode = fuse_iget_backing(dir->i_sb, 0, backing_inode,
				  child_path.mnt);
	if (!inode) {
		ret = -ENOMEM;
		goto out_write;
	}
	ret = fuse_handle_bpf_prog(&bpf_entry, dir,
				   &get_fuse_inode(inode)->bpf);
	if (ret) {
		iput(inode);
		goto out_write;
	}
	ret = d_instantiate_no_diralias(entry, inode);
	if (ret)
		goto out_write;

	fuse_bpf_copy_parent_attr(dir, backing_dir);
	fuse_invalidate_entry_cache(entry);
	ret = 0;

out_write:
	if (ret && created) {
		rollback = fuse_bpf_rollback_create(&parent_path,
					    &child_path, false);
		if (rollback)
			fuse_invalidate_entry_cache(entry);
		fuse_bpf_copy_parent_attr(dir, backing_dir);
	}
	mnt_drop_write(parent_path.mnt);
out_paths:
	fuse_put_backing_path(&child_path);
	fuse_put_backing_path(&parent_path);
out_link:
	kfree(link_copy);
out_name:
	kfree(name_copy);
	return ret;
}
#endif

static int fuse_symlink(struct inode *dir, struct dentry *entry,
			const char *link)
{
	struct fuse_conn *fc = get_fuse_conn(dir);
	unsigned len = strlen(link) + 1;
	FUSE_ARGS(args);

#ifdef CONFIG_FUSE_BPF
	if (fuse_inode_has_backing(dir))
		return fuse_bpf_symlink(dir, entry, link, len);
#endif

	args.in.h.opcode = FUSE_SYMLINK;
	args.in.numargs = 2;
	args.in.args[0].size = entry->d_name.len + 1;
	args.in.args[0].value = entry->d_name.name;
	args.in.args[1].size = len;
	args.in.args[1].value = link;
	return create_new_entry(fc, &args, dir, entry, S_IFLNK);
}

void fuse_update_ctime(struct inode *inode)
{
	if (!IS_NOCMTIME(inode)) {
		inode->i_ctime = current_time(inode);
		mark_inode_dirty_sync(inode);
	}
}

#ifdef CONFIG_FUSE_BPF
static int fuse_bpf_remove_paths(struct inode *dir, struct dentry *entry,
				 bool directory,
				 struct path *parent_path,
				 struct path *child_path)
{
	struct fuse_inode *dir_fi = get_fuse_inode(dir);
	struct inode *inode = d_inode(entry);
	struct fuse_inode *fi;
	struct inode *backing_dir;
	struct inode *backing_inode;

	*parent_path = (struct path) { };
	*child_path = (struct path) { };
	if (!inode || entry->d_parent == entry ||
	    d_inode(entry->d_parent) != dir)
		return -ESTALE;
	if (directory != S_ISDIR(inode->i_mode))
		return directory ? -ENOTDIR : -EISDIR;

	fi = get_fuse_inode(inode);
	if (!dir_fi->backing_inode || !dir_fi->backing_mnt ||
	    !fi->backing_inode || !fi->backing_mnt)
		return -EOPNOTSUPP;
	if (!get_fuse_backing_path(entry->d_parent, parent_path))
		return -EBADF;
	if (!get_fuse_backing_path(entry, child_path)) {
		fuse_put_backing_path(parent_path);
		return -EBADF;
	}

	backing_dir = d_inode(parent_path->dentry);
	backing_inode = d_inode(child_path->dentry);
	if (!backing_dir || !backing_inode ||
	    backing_dir == dir || backing_inode == inode ||
	    backing_dir != dir_fi->backing_inode ||
	    parent_path->mnt != dir_fi->backing_mnt ||
	    backing_inode != fi->backing_inode ||
	    child_path->mnt != fi->backing_mnt ||
	    child_path->mnt != parent_path->mnt ||
	    child_path->dentry->d_parent != parent_path->dentry ||
	    unlikely(d_unhashed(child_path->dentry)) ||
	    directory != S_ISDIR(backing_inode->i_mode) ||
	    child_path->dentry->d_name.len != entry->d_name.len ||
	    memcmp(child_path->dentry->d_name.name,
		   entry->d_name.name, entry->d_name.len)) {
		fuse_put_backing_path(child_path);
		fuse_put_backing_path(parent_path);
		return -ESTALE;
	}
	return 0;
}

static void fuse_bpf_copy_removed_attr(struct inode *inode,
				       struct inode *backing_inode)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);

	spin_lock(&fc->lock);
	inode->i_atime = backing_inode->i_atime;
	inode->i_mtime = backing_inode->i_mtime;
	inode->i_ctime = backing_inode->i_ctime;
	i_size_write(inode, i_size_read(backing_inode));
	set_nlink(inode, backing_inode->i_nlink);
	fi->attr_version = ++fc->attr_version;
	spin_unlock(&fc->lock);
}

static int fuse_bpf_remove(struct inode *dir, struct dentry *entry,
			   bool directory)
{
	struct fuse_bpf_args args = { };
	struct fuse_bpf_args backup = { };
	struct path parent_path = { };
	struct path child_path = { };
	struct inode *backing_dir;
	struct inode *backing_inode;
	struct inode *delegated_inode = NULL;
	char *name;
	size_t name_len;
	int ret;

	name = fuse_bpf_create_name(entry, &name_len);
	if (IS_ERR(name))
		return PTR_ERR(name);
	args.nodeid = get_node_id(dir);
	args.opcode = directory ? FUSE_RMDIR : FUSE_UNLINK;
	args.in_numargs = 1;
	args.in_args[0].size = name_len;
	args.in_args[0].value = name;

	ret = fuse_bpf_prepare_lower_only(dir, &args, &backup);
	if (ret)
		goto out_name;
	if (args.opcode != (directory ? FUSE_RMDIR : FUSE_UNLINK) ||
	    args.nodeid != get_node_id(dir) || args.flags ||
	    args.in_numargs != 1 || args.out_numargs || args.error_in ||
	    args.in_args[0].value != name ||
	    args.in_args[0].size != name_len ||
	    args.in_args[0].end_offset != name + name_len ||
	    name[name_len - 1] ||
	    memcmp(name, entry->d_name.name, name_len - 1)) {
		ret = -EOPNOTSUPP;
		goto out_name;
	}

	ret = fuse_bpf_remove_paths(dir, entry, directory,
				    &parent_path, &child_path);
	if (ret)
		goto out_name;
	backing_dir = d_inode(parent_path.dentry);
	backing_inode = d_inode(child_path.dentry);
	ihold(backing_inode);

	ret = mnt_want_write(parent_path.mnt);
	if (ret)
		goto out_inode;
	if (directory) {
		inode_lock_nested(backing_dir, I_MUTEX_PARENT);
		ret = vfs_rmdir2(parent_path.mnt, backing_dir,
				 child_path.dentry);
		inode_unlock(backing_dir);
	} else {
retry_unlink:
		inode_lock_nested(backing_dir, I_MUTEX_PARENT);
		ret = vfs_unlink2(parent_path.mnt, backing_dir,
				  child_path.dentry, &delegated_inode);
		inode_unlock(backing_dir);
		if (delegated_inode) {
			int delegated_ret;

			delegated_ret = break_deleg_wait(&delegated_inode);
			if (!delegated_ret)
				goto retry_unlink;
			ret = delegated_ret;
		}
	}
	mnt_drop_write(parent_path.mnt);
	if (ret)
		goto out_inode;

	fuse_bpf_copy_removed_attr(d_inode(entry), backing_inode);
	fuse_bpf_copy_parent_attr(dir, backing_dir);
	fuse_invalidate_entry_cache(entry);

out_inode:
	iput(backing_inode);
	fuse_put_backing_path(&child_path);
	fuse_put_backing_path(&parent_path);
out_name:
	kfree(name);
	return ret;
}
#endif

static int fuse_unlink(struct inode *dir, struct dentry *entry)
{
	int err;
	struct fuse_conn *fc = get_fuse_conn(dir);
	FUSE_ARGS(args);

	if (fuse_is_bad(dir))
		return -EIO;

#ifdef CONFIG_FUSE_BPF
	if (fuse_inode_has_backing(dir) ||
	    (d_really_is_positive(entry) &&
	     fuse_inode_has_backing(d_inode(entry)))) {
		if (!fuse_inode_has_backing(dir) ||
		    !d_really_is_positive(entry) ||
		    !fuse_inode_has_backing(d_inode(entry)))
			return -EOPNOTSUPP;
		return fuse_bpf_remove(dir, entry, false);
	}
#endif
	args.in.h.opcode = FUSE_UNLINK;
	args.in.h.nodeid = get_node_id(dir);
	args.in.numargs = 1;
	args.in.args[0].size = entry->d_name.len + 1;
	args.in.args[0].value = entry->d_name.name;
	err = fuse_simple_request(fc, &args);
	if (!err) {
		struct inode *inode = d_inode(entry);
		struct fuse_inode *fi = get_fuse_inode(inode);

		spin_lock(&fc->lock);
		fi->attr_version = ++fc->attr_version;
		/*
		 * If i_nlink == 0 then unlink doesn't make sense, yet this can
		 * happen if userspace filesystem is careless.  It would be
		 * difficult to enforce correct nlink usage so just ignore this
		 * condition here
		 */
		if (inode->i_nlink > 0)
			drop_nlink(inode);
		spin_unlock(&fc->lock);
		fuse_invalidate_attr(inode);
		fuse_invalidate_attr(dir);
		fuse_invalidate_entry_cache(entry);
		fuse_update_ctime(inode);
	} else if (err == -EINTR)
		fuse_invalidate_entry(entry);
	return err;
}

static int fuse_rmdir(struct inode *dir, struct dentry *entry)
{
	int err;
	struct fuse_conn *fc = get_fuse_conn(dir);
	FUSE_ARGS(args);

	if (fuse_is_bad(dir))
		return -EIO;

#ifdef CONFIG_FUSE_BPF
	if (fuse_inode_has_backing(dir) ||
	    (d_really_is_positive(entry) &&
	     fuse_inode_has_backing(d_inode(entry)))) {
		if (!fuse_inode_has_backing(dir) ||
		    !d_really_is_positive(entry) ||
		    !fuse_inode_has_backing(d_inode(entry)))
			return -EOPNOTSUPP;
		return fuse_bpf_remove(dir, entry, true);
	}
#endif
	args.in.h.opcode = FUSE_RMDIR;
	args.in.h.nodeid = get_node_id(dir);
	args.in.numargs = 1;
	args.in.args[0].size = entry->d_name.len + 1;
	args.in.args[0].value = entry->d_name.name;
	err = fuse_simple_request(fc, &args);
	if (!err) {
		clear_nlink(d_inode(entry));
		fuse_invalidate_attr(dir);
		fuse_invalidate_entry_cache(entry);
	} else if (err == -EINTR)
		fuse_invalidate_entry(entry);
	return err;
}

static int fuse_rename_common(struct inode *olddir, struct dentry *oldent,
			      struct inode *newdir, struct dentry *newent,
			      unsigned int flags, int opcode, size_t argsize)
{
	int err;
	struct fuse_rename2_in inarg;
	struct fuse_conn *fc = get_fuse_conn(olddir);
	FUSE_ARGS(args);

	memset(&inarg, 0, argsize);
	inarg.newdir = get_node_id(newdir);
	inarg.flags = flags;
	args.in.h.opcode = opcode;
	args.in.h.nodeid = get_node_id(olddir);
	args.in.numargs = 3;
	args.in.args[0].size = argsize;
	args.in.args[0].value = &inarg;
	args.in.args[1].size = oldent->d_name.len + 1;
	args.in.args[1].value = oldent->d_name.name;
	args.in.args[2].size = newent->d_name.len + 1;
	args.in.args[2].value = newent->d_name.name;
	err = fuse_simple_request(fc, &args);
	if (!err) {
		/* ctime changes */
		fuse_invalidate_attr(d_inode(oldent));
		fuse_update_ctime(d_inode(oldent));

		if (flags & RENAME_EXCHANGE) {
			fuse_invalidate_attr(d_inode(newent));
			fuse_update_ctime(d_inode(newent));
		}

		fuse_invalidate_attr(olddir);
		if (olddir != newdir)
			fuse_invalidate_attr(newdir);

		/* newent will end up negative */
		if (!(flags & RENAME_EXCHANGE) && d_really_is_positive(newent)) {
			fuse_invalidate_attr(d_inode(newent));
			fuse_invalidate_entry_cache(newent);
			fuse_update_ctime(d_inode(newent));
		}
	} else if (err == -EINTR) {
		/* If request was interrupted, DEITY only knows if the
		   rename actually took place.  If the invalidation
		   fails (e.g. some process has CWD under the renamed
		   directory), then there can be inconsistency between
		   the dcache and the real filesystem.  Tough luck. */
		fuse_invalidate_entry(oldent);
		if (d_really_is_positive(newent))
			fuse_invalidate_entry(newent);
	}

	return err;
}

static int fuse_rename2(struct inode *olddir, struct dentry *oldent,
			struct inode *newdir, struct dentry *newent,
			unsigned int flags)
{
	struct fuse_conn *fc = get_fuse_conn(olddir);
	int err;

	if (fuse_is_bad(olddir))
		return -EIO;

	if (flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE))
		return -EINVAL;

#ifdef CONFIG_FUSE_BPF
	if (fuse_inode_has_backing(olddir) ||
	    fuse_inode_has_backing(newdir) ||
	    (d_really_is_positive(oldent) &&
	     fuse_inode_has_backing(d_inode(oldent))) ||
	    (d_really_is_positive(newent) &&
	     fuse_inode_has_backing(d_inode(newent))))
		return -EOPNOTSUPP;
#endif
	if (flags) {
		if (fc->no_rename2 || fc->minor < 23)
			return -EINVAL;

		err = fuse_rename_common(olddir, oldent, newdir, newent, flags,
					 FUSE_RENAME2,
					 sizeof(struct fuse_rename2_in));
		if (err == -ENOSYS) {
			fc->no_rename2 = 1;
			err = -EINVAL;
		}
	} else {
		err = fuse_rename_common(olddir, oldent, newdir, newent, 0,
					 FUSE_RENAME,
					 sizeof(struct fuse_rename_in));
	}

	return err;
}

static int fuse_link(struct dentry *entry, struct inode *newdir,
		     struct dentry *newent)
{
	int err;
	struct fuse_link_in inarg;
	struct inode *inode = d_inode(entry);
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);

#ifdef CONFIG_FUSE_BPF
	if (fuse_inode_has_backing(inode) ||
	    fuse_inode_has_backing(newdir))
		return -EOPNOTSUPP;
#endif
	memset(&inarg, 0, sizeof(inarg));
	inarg.oldnodeid = get_node_id(inode);
	args.in.h.opcode = FUSE_LINK;
	args.in.numargs = 2;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.in.args[1].size = newent->d_name.len + 1;
	args.in.args[1].value = newent->d_name.name;
	err = create_new_entry(fc, &args, newdir, newent, inode->i_mode);
	/* Contrary to "normal" filesystems it can happen that link
	   makes two "logical" inodes point to the same "physical"
	   inode.  We invalidate the attributes of the old one, so it
	   will reflect changes in the backing inode (link count,
	   etc.)
	*/
	if (!err) {
		struct fuse_inode *fi = get_fuse_inode(inode);

		spin_lock(&fc->lock);
		fi->attr_version = ++fc->attr_version;
		if (likely(inode->i_nlink < UINT_MAX))
			inc_nlink(inode);
		spin_unlock(&fc->lock);
		fuse_invalidate_attr(inode);
		fuse_update_ctime(inode);
	} else if (err == -EINTR) {
		fuse_invalidate_attr(inode);
	}
	return err;
}

void fuse_fillattr(struct inode *inode, struct fuse_attr *attr,
			  struct kstat *stat)
{
	unsigned int blkbits;
	struct fuse_conn *fc = get_fuse_conn(inode);

	/* see the comment in fuse_change_attributes() */
	if (fc->writeback_cache && S_ISREG(inode->i_mode)) {
		attr->size = i_size_read(inode);
		attr->mtime = inode->i_mtime.tv_sec;
		attr->mtimensec = inode->i_mtime.tv_nsec;
		attr->ctime = inode->i_ctime.tv_sec;
		attr->ctimensec = inode->i_ctime.tv_nsec;
	}

	stat->dev = inode->i_sb->s_dev;
	stat->ino = attr->ino;
	stat->mode = (inode->i_mode & S_IFMT) | (attr->mode & 07777);
	stat->nlink = attr->nlink;
	stat->uid = make_kuid(&init_user_ns, attr->uid);
	stat->gid = make_kgid(&init_user_ns, attr->gid);
	stat->rdev = inode->i_rdev;
	stat->atime.tv_sec = attr->atime;
	stat->atime.tv_nsec = attr->atimensec;
	stat->mtime.tv_sec = attr->mtime;
	stat->mtime.tv_nsec = attr->mtimensec;
	stat->ctime.tv_sec = attr->ctime;
	stat->ctime.tv_nsec = attr->ctimensec;
	stat->size = attr->size;
	stat->blocks = attr->blocks;

	if (attr->blksize != 0)
		blkbits = ilog2(attr->blksize);
	else
		blkbits = inode->i_sb->s_blocksize_bits;

	stat->blksize = 1 << blkbits;
}

static int fuse_do_getattr(struct inode *inode, struct kstat *stat,
			   struct file *file)
{
	int err;
	struct fuse_getattr_in inarg;
	struct fuse_attr_out outarg;
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);
	u64 attr_version;

#ifdef CONFIG_FUSE_BPF
	if (get_fuse_inode(inode)->backing_inode)
		return -EOPNOTSUPP;
#endif
	attr_version = fuse_get_attr_version(fc);

	memset(&inarg, 0, sizeof(inarg));
	memset(&outarg, 0, sizeof(outarg));
	/* Directories have separate file-handle space */
	if (file && S_ISREG(inode->i_mode)) {
		struct fuse_file *ff = file->private_data;

		inarg.getattr_flags |= FUSE_GETATTR_FH;
		inarg.fh = ff->fh;
	}
	args.in.h.opcode = FUSE_GETATTR;
	args.in.h.nodeid = get_node_id(inode);
	args.in.numargs = 1;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.out.numargs = 1;
	args.out.args[0].size = sizeof(outarg);
	args.out.args[0].value = &outarg;
	err = fuse_simple_request(fc, &args);
	if (!err) {
		if (fuse_invalid_attr(&outarg.attr) ||
		    (inode->i_mode ^ outarg.attr.mode) & S_IFMT) {
			fuse_make_bad(inode);
			err = -EIO;
		} else {
			fuse_change_attributes(inode, &outarg.attr,
					       attr_timeout(&outarg),
					       attr_version);
			if (stat)
				fuse_fillattr(inode, &outarg.attr, stat);
		}
	}
	return err;
}

int fuse_update_attributes(struct inode *inode, struct kstat *stat,
			   struct file *file, bool *refreshed)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	int err;
	bool r;

	if (time_before64(fi->i_time, get_jiffies_64())) {
		r = true;
		forget_all_cached_acls(inode);
		err = fuse_do_getattr(inode, stat, file);
	} else {
		r = false;
		err = 0;
		if (stat) {
			generic_fillattr(inode, stat);
			stat->mode = fi->orig_i_mode;
			stat->ino = fi->orig_ino;
		}
	}

	if (refreshed != NULL)
		*refreshed = r;

	return err;
}

int fuse_reverse_inval_entry(struct super_block *sb, u64 parent_nodeid,
			     u64 child_nodeid, struct qstr *name)
{
	int err = -ENOTDIR;
	struct inode *parent;
	struct dentry *dir;
	struct dentry *entry;

	parent = ilookup5(sb, parent_nodeid, fuse_inode_eq, &parent_nodeid);
	if (!parent)
		return -ENOENT;

	inode_lock_nested(parent, I_MUTEX_PARENT);
	if (!S_ISDIR(parent->i_mode))
		goto unlock;

	err = -ENOENT;
	dir = d_find_alias(parent);
	if (!dir)
		goto unlock;

	name->hash = full_name_hash(dir, name->name, name->len);
	entry = d_lookup(dir, name);
	dput(dir);
	if (!entry)
		goto unlock;

	fuse_invalidate_attr(parent);
	fuse_invalidate_entry(entry);

	if (child_nodeid != 0 && d_really_is_positive(entry)) {
		inode_lock(d_inode(entry));
		if (get_node_id(d_inode(entry)) != child_nodeid) {
			err = -ENOENT;
			goto badentry;
		}
		if (d_mountpoint(entry)) {
			err = -EBUSY;
			goto badentry;
		}
		if (d_is_dir(entry)) {
			shrink_dcache_parent(entry);
			if (!simple_empty(entry)) {
				err = -ENOTEMPTY;
				goto badentry;
			}
			d_inode(entry)->i_flags |= S_DEAD;
		}
		dont_mount(entry);
		clear_nlink(d_inode(entry));
		err = 0;
 badentry:
		inode_unlock(d_inode(entry));
		if (!err)
			d_delete(entry);
	} else {
		err = 0;
	}
	dput(entry);

 unlock:
	inode_unlock(parent);
	iput(parent);
	return err;
}

/*
 * Calling into a user-controlled filesystem gives the filesystem
 * daemon ptrace-like capabilities over the current process.  This
 * means, that the filesystem daemon is able to record the exact
 * filesystem operations performed, and can also control the behavior
 * of the requester process in otherwise impossible ways.  For example
 * it can delay the operation for arbitrary length of time allowing
 * DoS against the requester.
 *
 * For this reason only those processes can call into the filesystem,
 * for which the owner of the mount has ptrace privilege.  This
 * excludes processes started by other users, suid or sgid processes.
 */
int fuse_allow_current_process(struct fuse_conn *fc)
{
	const struct cred *cred;

	if (fc->allow_other)
		return 1;

	cred = current_cred();
	if (uid_eq(cred->euid, fc->user_id) &&
	    uid_eq(cred->suid, fc->user_id) &&
	    uid_eq(cred->uid,  fc->user_id) &&
	    gid_eq(cred->egid, fc->group_id) &&
	    gid_eq(cred->sgid, fc->group_id) &&
	    gid_eq(cred->gid,  fc->group_id))
		return 1;

	return 0;
}

static int fuse_access(struct inode *inode, int mask)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);
	struct fuse_access_in inarg;
	int err;

	BUG_ON(mask & MAY_NOT_BLOCK);

#ifdef CONFIG_FUSE_BPF
	if (get_fuse_inode(inode)->backing_inode)
		return -EOPNOTSUPP;
#endif
	if (fc->no_access)
		return 0;

	memset(&inarg, 0, sizeof(inarg));
	inarg.mask = mask & (MAY_READ | MAY_WRITE | MAY_EXEC);
	args.in.h.opcode = FUSE_ACCESS;
	args.in.h.nodeid = get_node_id(inode);
	args.in.numargs = 1;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	err = fuse_simple_request(fc, &args);
	if (err == -ENOSYS) {
		fc->no_access = 1;
		err = 0;
	}
	return err;
}

static int fuse_perm_getattr(struct inode *inode, int mask)
{
	if (mask & MAY_NOT_BLOCK)
		return -ECHILD;

	forget_all_cached_acls(inode);
	return fuse_do_getattr(inode, NULL, NULL);
}

/*
 * Check permission.  The two basic access models of FUSE are:
 *
 * 1) Local access checking ('default_permissions' mount option) based
 * on file mode.  This is the plain old disk filesystem permission
 * modell.
 *
 * 2) "Remote" access checking, where server is responsible for
 * checking permission in each inode operation.  An exception to this
 * is if ->permission() was invoked from sys_access() in which case an
 * access request is sent.  Execute permission is still checked
 * locally based on file mode.
 */
static int fuse_permission(struct inode *inode, int mask)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
#ifdef CONFIG_FUSE_BPF
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_err_ret fer;
#endif
	bool refreshed = false;
	int err = 0;

	if (fuse_is_bad(inode))
		return -EIO;

	if (!fuse_allow_current_process(fc))
		return -EACCES;

#ifdef CONFIG_FUSE_BPF
	if (fi->backing_inode) {
		if (mask & MAY_NOT_BLOCK)
			return -ECHILD;
		fer = fuse_bpf_backing(inode, struct fuse_access_io,
				       fuse_access_initialize,
				       fuse_access_backing,
				       fuse_access_finalize, inode, mask);
		if (fer.ret)
			return PTR_ERR_OR_ZERO(fer.result);
		if (!get_node_id(inode))
			return -EOPNOTSUPP;
	}
#endif

	/*
	 * If attributes are needed, refresh them before proceeding
	 */
	if (fc->default_permissions ||
	    ((mask & MAY_EXEC) && S_ISREG(inode->i_mode))) {
		struct fuse_inode *fi = get_fuse_inode(inode);

		if (time_before64(fi->i_time, get_jiffies_64())) {
			refreshed = true;

			err = fuse_perm_getattr(inode, mask);
			if (err)
				return err;
		}
	}

	if (fc->default_permissions) {
		err = generic_permission(inode, mask);

		/* If permission is denied, try to refresh file
		   attributes.  This is also needed, because the root
		   node will at first have no permissions */
		if (err == -EACCES && !refreshed) {
			err = fuse_perm_getattr(inode, mask);
			if (!err)
				err = generic_permission(inode, mask);
		}

		/* Note: the opposite of the above test does not
		   exist.  So if permissions are revoked this won't be
		   noticed immediately, only after the attribute
		   timeout has expired */
	} else if (mask & (MAY_ACCESS | MAY_CHDIR)) {
		err = fuse_access(inode, mask);
	} else if ((mask & MAY_EXEC) && S_ISREG(inode->i_mode)) {
		if (!(inode->i_mode & S_IXUGO)) {
			if (refreshed)
				return -EACCES;

			err = fuse_perm_getattr(inode, mask);
			if (!err && !(inode->i_mode & S_IXUGO))
				return -EACCES;
		}
	}
	return err;
}

int fuse_parse_dirfile(char *buf, size_t nbytes, struct file *file,
			 struct dir_context *ctx)
{
	while (nbytes >= FUSE_NAME_OFFSET) {
		struct fuse_dirent *dirent = (struct fuse_dirent *) buf;
		size_t reclen = FUSE_DIRENT_SIZE(dirent);
		if (!dirent->namelen || dirent->namelen > FUSE_NAME_MAX)
			return -EIO;
		if (reclen > nbytes)
			break;
		if (memchr(dirent->name, '/', dirent->namelen) != NULL)
			return -EIO;

		if (!dir_emit(ctx, dirent->name, dirent->namelen,
			       dirent->ino, dirent->type))
			break;

		buf += reclen;
		nbytes -= reclen;
		ctx->pos = dirent->off;
	}

	return 0;
}

static int fuse_direntplus_link(struct file *file,
				struct fuse_direntplus *direntplus,
				u64 attr_version)
{
	struct fuse_entry_out *o = &direntplus->entry_out;
	struct fuse_dirent *dirent = &direntplus->dirent;
	struct dentry *parent = file->f_path.dentry;
	struct qstr name = QSTR_INIT(dirent->name, dirent->namelen);
	struct dentry *dentry;
	struct dentry *alias;
	struct inode *dir = d_inode(parent);
	struct fuse_conn *fc;
	struct inode *inode;
	DECLARE_WAIT_QUEUE_HEAD_ONSTACK(wq);

	if (!o->nodeid) {
		/*
		 * Unlike in the case of fuse_lookup, zero nodeid does not mean
		 * ENOENT. Instead, it only means the userspace filesystem did
		 * not want to return attributes/handle for this entry.
		 *
		 * So do nothing.
		 */
		return 0;
	}

	if (name.name[0] == '.') {
		/*
		 * We could potentially refresh the attributes of the directory
		 * and its parent?
		 */
		if (name.len == 1)
			return 0;
		if (name.name[1] == '.' && name.len == 2)
			return 0;
	}

	if (invalid_nodeid(o->nodeid))
		return -EIO;
	if (fuse_invalid_attr(&o->attr))
		return -EIO;

	fc = get_fuse_conn(dir);

	name.hash = full_name_hash(parent, name.name, name.len);
	dentry = d_lookup(parent, &name);
	if (!dentry) {
retry:
		dentry = d_alloc_parallel(parent, &name, &wq);
		if (IS_ERR(dentry))
			return PTR_ERR(dentry);
	}
	if (!d_in_lookup(dentry)) {
		struct fuse_inode *fi;
		inode = d_inode(dentry);
		if (!inode ||
		    get_node_id(inode) != o->nodeid ||
		    ((o->attr.mode ^ inode->i_mode) & S_IFMT)) {
			d_invalidate(dentry);
			dput(dentry);
			goto retry;
		}
		if (fuse_is_bad(inode)) {
			dput(dentry);
			return -EIO;
		}

		fi = get_fuse_inode(inode);
		spin_lock(&fc->lock);
		fi->nlookup++;
		spin_unlock(&fc->lock);

		forget_all_cached_acls(inode);
		fuse_change_attributes(inode, &o->attr,
				       entry_attr_timeout(o),
				       attr_version);
		/*
		 * The other branch comes via fuse_iget()
		 * which bumps nlookup inside
		 */
	} else {
		inode = fuse_iget(dir->i_sb, o->nodeid, o->generation,
				  &o->attr, entry_attr_timeout(o),
				  attr_version);
		if (!inode)
			inode = ERR_PTR(-ENOMEM);

		alias = d_splice_alias(inode, dentry);
		d_lookup_done(dentry);
		if (alias) {
			dput(dentry);
			dentry = alias;
		}
		if (IS_ERR(dentry))
			return PTR_ERR(dentry);
	}
	if (fc->readdirplus_auto)
		set_bit(FUSE_I_INIT_RDPLUS, &get_fuse_inode(inode)->state);
	fuse_change_entry_timeout(dentry, o);

	dput(dentry);
	return 0;
}

static int parse_dirplusfile(char *buf, size_t nbytes, struct file *file,
			     struct dir_context *ctx, u64 attr_version)
{
	struct fuse_direntplus *direntplus;
	struct fuse_dirent *dirent;
	size_t reclen;
	int over = 0;
	int ret;

	while (nbytes >= FUSE_NAME_OFFSET_DIRENTPLUS) {
		direntplus = (struct fuse_direntplus *) buf;
		dirent = &direntplus->dirent;
		reclen = FUSE_DIRENTPLUS_SIZE(direntplus);

		if (!dirent->namelen || dirent->namelen > FUSE_NAME_MAX)
			return -EIO;
		if (reclen > nbytes)
			break;
		if (memchr(dirent->name, '/', dirent->namelen) != NULL)
			return -EIO;

		if (!over) {
			/* We fill entries into dstbuf only as much as
			   it can hold. But we still continue iterating
			   over remaining entries to link them. If not,
			   we need to send a FORGET for each of those
			   which we did not link.
			*/
			over = !dir_emit(ctx, dirent->name, dirent->namelen,
				       dirent->ino, dirent->type);
			if (!over)
				ctx->pos = dirent->off;
		}

		buf += reclen;
		nbytes -= reclen;

		ret = fuse_direntplus_link(file, direntplus, attr_version);
		if (ret)
			fuse_force_forget(file, direntplus->entry_out.nodeid);
	}

	return 0;
}

#ifdef CONFIG_FUSE_BPF
struct fuse_bpf_readdir_io {
	struct fuse_read_in in;
	struct fuse_read_out out;
	char *page;
	loff_t original_pos;
	loff_t lower_end;
	size_t bytes;
	bool executed;
};

struct fuse_bpf_readdir_ctx {
	struct dir_context ctx;
	char *page;
	size_t bytes;
	int error;
};

static int fuse_bpf_readdir_fill(struct dir_context *ctx, const char *name,
				 int namelen, loff_t offset, u64 ino,
				 unsigned int type)
{
	struct fuse_bpf_readdir_ctx *buffer =
		container_of(ctx, struct fuse_bpf_readdir_ctx, ctx);
	struct fuse_dirent *dirent;
	size_t reclen;

	if (namelen <= 0 || namelen > FUSE_NAME_MAX ||
	    memchr(name, '/', namelen)) {
		buffer->error = -EIO;
		return -EIO;
	}

	reclen = FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + namelen);
	if (reclen > PAGE_SIZE - buffer->bytes)
		return 1;

	dirent = (struct fuse_dirent *)(buffer->page + buffer->bytes);
	memset(dirent, 0, reclen);
	dirent->ino = ino;
	dirent->off = offset;
	dirent->namelen = namelen;
	dirent->type = type;
	memcpy(dirent->name, name, namelen);
	buffer->bytes += reclen;
	return 0;
}

static int fuse_bpf_readdir_lower(struct file *file,
				  struct fuse_bpf_args *args,
				  struct fuse_bpf_readdir_io *io)
{
	struct fuse_file *ff = file->private_data;
	struct file *backing_file = ff ? ff->backing_file : NULL;
	struct fuse_read_in *in;
	struct fuse_read_out *out;
	struct fuse_bpf_readdir_ctx buffer = {
		.ctx.actor = fuse_bpf_readdir_fill,
		.ctx.pos = io->original_pos,
		.page = io->page,
	};
	int ret;

	if (!backing_file || !S_ISDIR(file_inode(backing_file)->i_mode))
		return -EBADF;
	if (file_inode(backing_file) == file_inode(file))
		return -ELOOP;
	if (args->opcode != FUSE_READDIR || args->nodeid != ff->nodeid ||
	    args->flags != FUSE_BPF_OUT_ARGVAR ||
	    args->in_numargs != 1 || args->out_numargs != 2 ||
	    !args->in_args[0].value || !args->out_args[0].value ||
	    args->out_args[1].value != io->page ||
	    args->in_args[0].size != sizeof(*in) ||
	    args->out_args[0].size != sizeof(*out) ||
	    args->out_args[1].size != PAGE_SIZE)
		return -EINVAL;

	in = (struct fuse_read_in *)args->in_args[0].value;
	out = args->out_args[0].value;
	if (in != &io->in || out != &io->out || in->fh != ff->fh ||
	    in->offset != (u64)io->original_pos || in->size != PAGE_SIZE ||
	    in->read_flags || in->lock_owner || in->flags || in->padding ||
	    out->offset != (u64)io->original_pos || out->again || out->padding)
		return -EOPNOTSUPP;

	backing_file->f_pos = io->original_pos;
	io->executed = true;
	ret = iterate_dir(backing_file, &buffer.ctx);
	if (!ret && buffer.error)
		ret = buffer.error;
	if (!ret && buffer.ctx.pos < 0)
		ret = -EIO;

	io->lower_end = buffer.ctx.pos;
	io->bytes = buffer.bytes;
	io->out.offset = (u64)buffer.ctx.pos;
	args->out_args[1].size = buffer.bytes;
	args->out_args[1].end_offset = io->page + buffer.bytes;
	return ret;
}

static int fuse_bpf_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_file *ff = file->private_data;
	struct fuse_bpf_readdir_io io = { };
	struct fuse_bpf_args args = { };
	struct fuse_bpf_args backup = { };
	struct bpf_prog *prog;
	int actions;
	int ret;

	if (!ff || !ff->backing_file)
		return -EBADF;
	if (ctx->pos < 0)
		return -EINVAL;

	io.page = (char *)get_zeroed_page(GFP_KERNEL);
	if (!io.page)
		return -ENOMEM;
	io.original_pos = ctx->pos;
	io.out.offset = ctx->pos;
	io.in.fh = ff->fh;
	io.in.offset = ctx->pos;
	io.in.size = PAGE_SIZE;

	args.nodeid = ff->nodeid;
	args.opcode = FUSE_READDIR;
	args.in_numargs = 1;
	args.out_numargs = 2;
	args.flags = FUSE_BPF_OUT_ARGVAR;
	args.in_args[0].size = sizeof(io.in);
	args.in_args[0].value = &io.in;
	args.out_args[0].size = sizeof(io.out);
	args.out_args[0].value = &io.out;
	args.out_args[1].size = PAGE_SIZE;
	args.out_args[1].value = io.page;

	prog = fuse_bpf_get_prog(fc, fi);
	ret = fuse_bpf_prepare_prefilter(&args, &backup);
	if (ret)
		goto out;

	actions = prog ? fuse_bpf_run_filter(prog, &args) :
			 FUSE_BPF_BACKING;
	if (actions < 0) {
		ret = actions;
		goto out;
	}
	/* Result rewriting and daemon continuation are added separately. */
	if (actions != FUSE_BPF_BACKING) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	ret = fuse_bpf_prepare_backing(&args, &backup);
	if (ret)
		goto out;
	ret = fuse_bpf_readdir_lower(file, &args, &io);
	if (ret)
		goto out_rewind;

	if (args.opcode != FUSE_READDIR || args.nodeid != ff->nodeid ||
	    args.flags != FUSE_BPF_OUT_ARGVAR ||
	    args.in_numargs != 1 || args.out_numargs != 2 ||
	    args.out_args[0].value != &io.out ||
	    args.out_args[0].size != sizeof(io.out) ||
	    args.out_args[1].value != io.page ||
	    args.out_args[1].size != io.bytes ||
	    io.out.offset != (u64)io.lower_end || io.out.again ||
	    io.out.padding) {
		ret = -EIO;
		goto out_rewind;
	}

	ret = fuse_parse_dirfile(io.page, io.bytes, file, ctx);
	if (ret)
		goto out_rewind;
	ff->backing_file->f_pos = ctx->pos;
	goto out;

out_rewind:
	ff->backing_file->f_pos = io.original_pos;
out:
	if (prog)
		bpf_prog_put(prog);
	free_page((unsigned long)io.page);
	if (io.executed)
		fuse_invalidate_atime(inode);
	return ret;
}
#endif

static int fuse_readdir(struct file *file, struct dir_context *ctx)
{
	int plus, err;
	size_t nbytes;
	struct page *page;
	struct inode *inode = file_inode(file);
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	u64 attr_version = 0;
	bool locked;

	if (fuse_is_bad(inode))
		return -EIO;

#ifdef CONFIG_FUSE_BPF
	if (fuse_file_has_backing(file))
		return fuse_bpf_readdir(file, ctx);
#endif

	req = fuse_get_req(fc, 1);
	if (IS_ERR(req))
		return PTR_ERR(req);

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		fuse_put_request(fc, req);
		return -ENOMEM;
	}

	plus = fuse_use_readdirplus(inode, ctx);
	req->out.argpages = 1;
	req->num_pages = 1;
	req->pages[0] = page;
	req->page_descs[0].length = PAGE_SIZE;
	if (plus) {
		attr_version = fuse_get_attr_version(fc);
		fuse_read_fill(req, file, ctx->pos, PAGE_SIZE,
			       FUSE_READDIRPLUS);
	} else {
		fuse_read_fill(req, file, ctx->pos, PAGE_SIZE,
			       FUSE_READDIR);
	}
	locked = fuse_lock_inode(inode);
	fuse_request_send(fc, req);
	fuse_unlock_inode(inode, locked);
	nbytes = req->out.args[0].size;
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err) {
		if (plus) {
			err = parse_dirplusfile(page_address(page), nbytes,
						file, ctx,
						attr_version);
		} else {
			err = fuse_parse_dirfile(page_address(page), nbytes, file,
					    ctx);
		}
	}

	__free_page(page);
	fuse_invalidate_atime(inode);
	return err;
}

#ifdef CONFIG_FUSE_BPF
static ssize_t fuse_bpf_readlink(struct inode *inode,
				 struct dentry *dentry,
				 char *link, size_t capacity)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_bpf_args args = { };
	struct fuse_bpf_args backup = { };
	struct delayed_call lower_done = { };
	struct path path = { };
	struct inode *backing_inode;
	const char *target;
	size_t length;
	int ret;

	args.nodeid = get_node_id(inode);
	args.opcode = FUSE_READLINK;
	args.out_numargs = 1;
	args.flags = FUSE_BPF_OUT_ARGVAR;
	args.out_args[0].size = capacity;
	args.out_args[0].value = link;

	ret = fuse_bpf_prepare_lower_only(inode, &args, &backup);
	if (ret)
		return ret;
	if (args.opcode != FUSE_READLINK ||
	    args.nodeid != get_node_id(inode) ||
	    args.flags != FUSE_BPF_OUT_ARGVAR || args.in_numargs ||
	    args.out_numargs != 1 || args.error_in ||
	    args.out_args[0].value != link ||
	    args.out_args[0].size != capacity ||
	    args.out_args[0].end_offset != link + capacity)
		return -EIO;
	if (d_inode(dentry) != inode ||
	    !get_fuse_backing_path(dentry, &path))
		return -ESTALE;
	backing_inode = d_inode(path.dentry);
	if (!backing_inode || backing_inode != fi->backing_inode ||
	    path.mnt != fi->backing_mnt ||
	    !S_ISLNK(backing_inode->i_mode)) {
		ret = -ESTALE;
		goto out_path;
	}

	target = vfs_get_link(path.dentry, &lower_done);
	if (IS_ERR_OR_NULL(target)) {
		ret = target ? PTR_ERR(target) : -EIO;
		goto out_done;
	}
	length = strnlen(target, capacity + 1);
	if (length > capacity) {
		ret = -ENAMETOOLONG;
		goto out_done;
	}
	memcpy(link, target, length);
	link[length] = '\0';
	args.out_args[0].size = length;
	args.out_args[0].end_offset = link + length;
	touch_atime(&path);

	if (args.out_args[0].value != link ||
	    args.out_args[0].size != length ||
	    args.out_args[0].end_offset != link + length) {
		ret = -EIO;
		goto out_done;
	}
	ret = length;

out_done:
	do_delayed_call(&lower_done);
out_path:
	fuse_put_backing_path(&path);
	return ret;
}
#endif

static const char *fuse_get_link(struct dentry *dentry,
				 struct inode *inode,
				 struct delayed_call *done)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);
	char *link;
	ssize_t ret;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	if (fuse_is_bad(inode))
		return ERR_PTR(-EIO);

	link = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!link)
		return ERR_PTR(-ENOMEM);

#ifdef CONFIG_FUSE_BPF
	if (fuse_inode_has_backing(inode)) {
		ret = fuse_bpf_readlink(inode, dentry, link,
					PAGE_SIZE - 1);
		fuse_invalidate_atime(inode);
		if (ret < 0) {
			kfree(link);
			return ERR_PTR(ret);
		}
		set_delayed_call(done, kfree_link, link);
		return link;
	}
#endif

	args.in.h.opcode = FUSE_READLINK;
	args.in.h.nodeid = get_node_id(inode);
	args.out.argvar = 1;
	args.out.numargs = 1;
	args.out.args[0].size = PAGE_SIZE - 1;
	args.out.args[0].value = link;
	ret = fuse_simple_request(fc, &args);
	if (ret < 0) {
		kfree(link);
		link = ERR_PTR(ret);
	} else {
		link[ret] = '\0';
		set_delayed_call(done, kfree_link, link);
	}
	fuse_invalidate_atime(inode);
	return link;
}

static int fuse_dir_open(struct inode *inode, struct file *file)
{
	return fuse_open_common(inode, file, true);
}

static int fuse_dir_release(struct inode *inode, struct file *file)
{
	fuse_release_common(file, FUSE_RELEASEDIR);

	return 0;
}

static int fuse_dir_fsync(struct file *file, loff_t start, loff_t end,
			  int datasync)
{
	return fuse_fsync_common(file, start, end, datasync, 1);
}

static long fuse_dir_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	struct fuse_conn *fc = get_fuse_conn(file->f_mapping->host);

	/* FUSE_IOCTL_DIR only supported for API version >= 7.18 */
	if (fc->minor < 18)
		return -ENOTTY;

	return fuse_ioctl_common(file, cmd, arg, FUSE_IOCTL_DIR);
}

static long fuse_dir_compat_ioctl(struct file *file, unsigned int cmd,
				   unsigned long arg)
{
	struct fuse_conn *fc = get_fuse_conn(file->f_mapping->host);

	if (fc->minor < 18)
		return -ENOTTY;

	return fuse_ioctl_common(file, cmd, arg,
				 FUSE_IOCTL_COMPAT | FUSE_IOCTL_DIR);
}

/*
 * Prevent concurrent writepages on inode
 *
 * This is done by adding a negative bias to the inode write counter
 * and waiting for all pending writes to finish.
 */
void fuse_set_nowrite(struct inode *inode)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);

	BUG_ON(!inode_is_locked(inode));

	spin_lock(&fc->lock);
	BUG_ON(fi->writectr < 0);
	fi->writectr += FUSE_NOWRITE;
	spin_unlock(&fc->lock);
	fuse_wait_event(fi->page_waitq, fi->writectr == FUSE_NOWRITE);
}

/*
 * Allow writepages on inode
 *
 * Remove the bias from the writecounter and send any queued
 * writepages.
 */
static void __fuse_release_nowrite(struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);

	BUG_ON(fi->writectr != FUSE_NOWRITE);
	fi->writectr = 0;
	fuse_flush_writepages(inode);
}

void fuse_release_nowrite(struct inode *inode)
{
	struct fuse_conn *fc = get_fuse_conn(inode);

	spin_lock(&fc->lock);
	__fuse_release_nowrite(inode);
	spin_unlock(&fc->lock);
}

static void fuse_setattr_fill(struct fuse_conn *fc, struct fuse_args *args,
			      struct inode *inode,
			      struct fuse_setattr_in *inarg_p,
			      struct fuse_attr_out *outarg_p)
{
	args->in.h.opcode = FUSE_SETATTR;
	args->in.h.nodeid = get_node_id(inode);
	args->in.numargs = 1;
	args->in.args[0].size = sizeof(*inarg_p);
	args->in.args[0].value = inarg_p;
	args->out.numargs = 1;
	args->out.args[0].size = sizeof(*outarg_p);
	args->out.args[0].value = outarg_p;
}

/*
 * Flush inode->i_mtime to the server
 */
int fuse_flush_times(struct inode *inode, struct fuse_file *ff)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);
	struct fuse_setattr_in inarg;
	struct fuse_attr_out outarg;

#ifdef CONFIG_FUSE_BPF
	if (fuse_inode_has_backing(inode))
		return -EOPNOTSUPP;
#endif
	memset(&inarg, 0, sizeof(inarg));
	memset(&outarg, 0, sizeof(outarg));

	inarg.valid = FATTR_MTIME;
	inarg.mtime = inode->i_mtime.tv_sec;
	inarg.mtimensec = inode->i_mtime.tv_nsec;
	if (fc->minor >= 23) {
		inarg.valid |= FATTR_CTIME;
		inarg.ctime = inode->i_ctime.tv_sec;
		inarg.ctimensec = inode->i_ctime.tv_nsec;
	}
	if (ff) {
		inarg.valid |= FATTR_FH;
		inarg.fh = ff->fh;
	}
	fuse_setattr_fill(fc, &args, inode, &inarg, &outarg);

	return fuse_simple_request(fc, &args);
}

/*
 * Set attributes, and at the same time refresh them.
 *
 * Truncation is slightly complicated, because the 'truncate' request
 * may fail, in which case we don't want to touch the mapping.
 * vmtruncate() doesn't allow for this case, so do the rlimit checking
 * and the actual truncation by hand.
 */
int fuse_do_setattr(struct dentry *dentry, struct iattr *attr,
		    struct file *file)
{
	struct inode *inode = d_inode(dentry);
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	FUSE_ARGS(args);
	struct fuse_setattr_in inarg;
	struct fuse_attr_out outarg;
	bool is_truncate = false;
	bool is_wb = fc->writeback_cache;
	loff_t oldsize;
	int err;
	bool trust_local_cmtime = is_wb && S_ISREG(inode->i_mode);

	if (!fc->default_permissions)
		attr->ia_valid |= ATTR_FORCE;

	err = setattr_prepare(dentry, attr);
	if (err)
		return err;

#ifdef CONFIG_FUSE_BPF
	if (fuse_inode_has_backing(inode)) {
		struct fuse_err_ret result;

		result = fuse_bpf_backing(inode, struct fuse_setattr_io,
					  fuse_setattr_initialize,
					  fuse_setattr_backing,
					  fuse_setattr_finalize,
					  dentry, attr, file);
		if (result.ret)
			return PTR_ERR_OR_ZERO(result.result);
		return -EOPNOTSUPP;
	}
#endif

	if (attr->ia_valid & ATTR_OPEN) {
		/* This is coming from open(..., ... | O_TRUNC); */
		WARN_ON(!(attr->ia_valid & ATTR_SIZE));
		WARN_ON(attr->ia_size != 0);
		if (fc->atomic_o_trunc) {
			/*
			 * No need to send request to userspace, since actual
			 * truncation has already been done by OPEN.  But still
			 * need to truncate page cache.
			 */
			i_size_write(inode, 0);
			truncate_pagecache(inode, 0);
			return 0;
		}
		file = NULL;
	}

	if (attr->ia_valid & ATTR_SIZE)
		is_truncate = true;

	/* Flush dirty data/metadata before non-truncate SETATTR */
	if (is_wb && S_ISREG(inode->i_mode) &&
	    attr->ia_valid &
			(ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_MTIME_SET |
			 ATTR_TIMES_SET)) {
		err = write_inode_now(inode, true);
		if (err)
			return err;

		fuse_set_nowrite(inode);
		fuse_release_nowrite(inode);
	}

	if (is_truncate) {
		fuse_set_nowrite(inode);
		set_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);
		if (trust_local_cmtime && attr->ia_size != inode->i_size)
			attr->ia_valid |= ATTR_MTIME | ATTR_CTIME;
	}

	memset(&inarg, 0, sizeof(inarg));
	memset(&outarg, 0, sizeof(outarg));
	iattr_to_fattr(attr, &inarg, trust_local_cmtime);
	if (file) {
		struct fuse_file *ff = file->private_data;
		inarg.valid |= FATTR_FH;
		inarg.fh = ff->fh;
	}
	if (attr->ia_valid & ATTR_SIZE) {
		/* For mandatory locking in truncate */
		inarg.valid |= FATTR_LOCKOWNER;
		inarg.lock_owner = fuse_lock_owner_id(fc, current->files);
	}
	fuse_setattr_fill(fc, &args, inode, &inarg, &outarg);
	err = fuse_simple_request(fc, &args);
	if (err) {
		if (err == -EINTR)
			fuse_invalidate_attr(inode);
		goto error;
	}

	if (fuse_invalid_attr(&outarg.attr) ||
	    (inode->i_mode ^ outarg.attr.mode) & S_IFMT) {
		fuse_make_bad(inode);
		err = -EIO;
		goto error;
	}

	spin_lock(&fc->lock);
	/* the kernel maintains i_mtime locally */
	if (trust_local_cmtime) {
		if (attr->ia_valid & ATTR_MTIME)
			inode->i_mtime = attr->ia_mtime;
		if (attr->ia_valid & ATTR_CTIME)
			inode->i_ctime = attr->ia_ctime;
		/* FIXME: clear I_DIRTY_SYNC? */
	}

	fuse_change_attributes_common(inode, &outarg.attr,
				      attr_timeout(&outarg));
	oldsize = inode->i_size;
	/* see the comment in fuse_change_attributes() */
	if (!is_wb || is_truncate || !S_ISREG(inode->i_mode))
		i_size_write(inode, outarg.attr.size);

	if (is_truncate) {
		/* NOTE: this may release/reacquire fc->lock */
		__fuse_release_nowrite(inode);
	}
	spin_unlock(&fc->lock);

	/*
	 * Only call invalidate_inode_pages2() after removing
	 * FUSE_NOWRITE, otherwise fuse_launder_page() would deadlock.
	 */
	if ((is_truncate || !is_wb) &&
	    S_ISREG(inode->i_mode) && oldsize != outarg.attr.size) {
		truncate_pagecache(inode, outarg.attr.size);
		invalidate_inode_pages2(inode->i_mapping);
	}

	clear_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);
	return 0;

error:
	if (is_truncate)
		fuse_release_nowrite(inode);

	clear_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);
	return err;
}

static int fuse_setattr(struct dentry *entry, struct iattr *attr)
{
	struct inode *inode = d_inode(entry);
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct file *file = (attr->ia_valid & ATTR_FILE) ? attr->ia_file : NULL;
	int ret;

	if (fuse_is_bad(inode))
		return -EIO;

	if (!fuse_allow_current_process(get_fuse_conn(inode)))
		return -EACCES;

	if (attr->ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID)) {
#ifdef CONFIG_FUSE_BPF
		if (fuse_inode_has_backing(inode)) {
			/* Let the lower inode derive its own exact mode. */
			attr->ia_valid &= ~ATTR_MODE;
			goto setattr;
		}
#endif
		attr->ia_valid &= ~(ATTR_KILL_SUID | ATTR_KILL_SGID |
				    ATTR_MODE);

		/*
		 * The only sane way to reliably kill suid/sgid is to do it in
		 * the userspace filesystem
		 *
		 * This should be done on write(), truncate() and chown().
		 */
		if (!fc->handle_killpriv) {
			/*
			 * ia_mode calculation may have used stale i_mode.
			 * Refresh and recalculate.
			 */
			ret = fuse_do_getattr(inode, NULL, file);
			if (ret)
				return ret;

			attr->ia_mode = inode->i_mode;
			if (inode->i_mode & S_ISUID) {
				attr->ia_valid |= ATTR_MODE;
				attr->ia_mode &= ~S_ISUID;
			}
			if ((inode->i_mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)) {
				attr->ia_valid |= ATTR_MODE;
				attr->ia_mode &= ~S_ISGID;
			}
		}
	}
	if (!attr->ia_valid)
		return 0;

#ifdef CONFIG_FUSE_BPF
setattr:
#endif
	ret = fuse_do_setattr(entry, attr, file);
	if (!ret) {
		/*
		 * If filesystem supports acls it may have updated acl xattrs in
		 * the filesystem, so forget cached acls for the inode.
		 */
		if (fc->posix_acl)
			forget_all_cached_acls(inode);

		/* Directory mode changed, may need to revalidate access */
		if (d_is_dir(entry) && (attr->ia_valid & ATTR_MODE))
			fuse_invalidate_entry_cache(entry);
	}
	return ret;
}

static int fuse_getattr(const struct path *path, struct kstat *stat,
			u32 request_mask, unsigned int flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct fuse_conn *fc = get_fuse_conn(inode);
#ifdef CONFIG_FUSE_BPF
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_err_ret fer;
	u64 attr_version;
#endif

	if (fuse_is_bad(inode))
		return -EIO;

	if (!fuse_allow_current_process(fc))
		return -EACCES;

#ifdef CONFIG_FUSE_BPF
	if (fi->backing_inode) {
		attr_version = fuse_get_attr_version(fc);
		fer = fuse_bpf_backing(inode, struct fuse_getattr_io,
				       fuse_getattr_initialize,
				       fuse_getattr_backing,
				       fuse_getattr_finalize, inode, path,
				       stat, request_mask, flags,
				       attr_version);
		if (fer.ret)
			return PTR_ERR_OR_ZERO(fer.result);
		if (!get_node_id(inode))
			return -EOPNOTSUPP;
	}
#endif

	return fuse_update_attributes(inode, stat, NULL, NULL);
}

static const struct inode_operations fuse_dir_inode_operations = {
	.lookup		= fuse_lookup,
	.mkdir		= fuse_mkdir,
	.symlink	= fuse_symlink,
	.unlink		= fuse_unlink,
	.rmdir		= fuse_rmdir,
	.rename		= fuse_rename2,
	.link		= fuse_link,
	.setattr	= fuse_setattr,
	.create		= fuse_create,
	.atomic_open	= fuse_atomic_open,
	.mknod		= fuse_mknod,
	.permission	= fuse_permission,
	.getattr	= fuse_getattr,
	.listxattr	= fuse_listxattr,
	.get_acl	= fuse_get_acl,
	.set_acl	= fuse_set_acl,
};

static const struct file_operations fuse_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate_shared	= fuse_readdir,
	.open		= fuse_dir_open,
	.release	= fuse_dir_release,
	.fsync		= fuse_dir_fsync,
	.unlocked_ioctl	= fuse_dir_ioctl,
	.compat_ioctl	= fuse_dir_compat_ioctl,
};

static const struct inode_operations fuse_common_inode_operations = {
	.setattr	= fuse_setattr,
	.permission	= fuse_permission,
	.getattr	= fuse_getattr,
	.listxattr	= fuse_listxattr,
	.get_acl	= fuse_get_acl,
	.set_acl	= fuse_set_acl,
};

static const struct inode_operations fuse_symlink_inode_operations = {
	.setattr	= fuse_setattr,
	.get_link	= fuse_get_link,
	.readlink	= generic_readlink,
	.getattr	= fuse_getattr,
	.listxattr	= fuse_listxattr,
};

void fuse_init_common(struct inode *inode)
{
	inode->i_op = &fuse_common_inode_operations;
}

void fuse_init_dir(struct inode *inode)
{
	inode->i_op = &fuse_dir_inode_operations;
	inode->i_fop = &fuse_dir_operations;
}

void fuse_init_symlink(struct inode *inode)
{
	inode->i_op = &fuse_symlink_inode_operations;
}
