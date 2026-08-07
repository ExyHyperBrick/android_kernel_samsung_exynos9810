/* SPDX-License-Identifier: GPL-2.0 */

/*
 * BinderFS backport for the Exynos9810 4.9 Binder driver.
 *
 * Use the native 4.9 mount_nodev(), parser and IDA interfaces instead of
 * importing the later fs_context/xarray infrastructure.
 */

#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/gfp.h>
#include <linux/idr.h>
#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/kernel.h>
#include <linux/magic.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/parser.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>

#include <uapi/linux/android/binderfs.h>

#include "binder_internal.h"

#define FIRST_INODE		1
#define SECOND_INODE		2
#define INODE_OFFSET		3
#define BINDERFS_MAX_MINOR	(1U << MINORBITS)

static dev_t binderfs_dev;
static DEFINE_MUTEX(binderfs_minors_mutex);
static DEFINE_IDA(binderfs_minors);

enum {
	Opt_max,
	Opt_stats_mode,
	Opt_err,
};

enum binderfs_stats_mode {
	STATS_NONE,
	STATS_GLOBAL,
};

struct binder_features {
	bool oneway_spam_detection;
};

static const match_table_t tokens = {
	{ Opt_max, "max=%d" },
	{ Opt_stats_mode, "stats=%s" },
	{ Opt_err, NULL },
};

static struct binder_features binder_features = {
	.oneway_spam_detection = true,
};

static inline struct binderfs_info *BINDERFS_I(const struct inode *inode)
{
	return inode->i_sb->s_fs_info;
}

bool is_binderfs_device(const struct inode *inode)
{
	return inode->i_sb->s_magic == BINDERFS_SUPER_MAGIC;
}

static int binderfs_get_minor(void)
{
	int minor;

	mutex_lock(&binderfs_minors_mutex);
	minor = ida_simple_get(&binderfs_minors, 0, BINDERFS_MAX_MINOR,
			       GFP_KERNEL);
	mutex_unlock(&binderfs_minors_mutex);

	return minor;
}

static void binderfs_put_minor(unsigned int minor)
{
	mutex_lock(&binderfs_minors_mutex);
	ida_simple_remove(&binderfs_minors, minor);
	mutex_unlock(&binderfs_minors_mutex);
}

static int binderfs_binder_device_create(struct inode *ref_inode,
					 struct binderfs_device __user *userp,
					 struct binderfs_device *req)
{
	int minor, ret = -ENOMEM;
	struct dentry *dentry, *root;
	struct binder_device *device = NULL;
	struct inode *inode = NULL;
	struct binderfs_info *info = ref_inode->i_sb->s_fs_info;
	char *name = NULL;
	size_t name_len;

	req->name[BINDERFS_MAX_NAME] = '\0';
	name_len = strlen(req->name);
	if (!name_len)
		return -EINVAL;

	mutex_lock(&binderfs_minors_mutex);
	if (++info->device_count > info->mount_opts.max) {
		--info->device_count;
		mutex_unlock(&binderfs_minors_mutex);
		return -ENOSPC;
	}

	minor = ida_simple_get(&binderfs_minors, 0, BINDERFS_MAX_MINOR,
			       GFP_KERNEL);
	if (minor < 0)
		--info->device_count;
	mutex_unlock(&binderfs_minors_mutex);
	if (minor < 0)
		return minor;

	device = kzalloc(sizeof(*device), GFP_KERNEL);
	if (!device)
		goto err;

	inode = new_inode(ref_inode->i_sb);
	if (!inode)
		goto err;

	name = kmemdup(req->name, name_len + 1, GFP_KERNEL);
	if (!name)
		goto err;

	inode->i_ino = minor + INODE_OFFSET;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	init_special_inode(inode, S_IFCHR | 0600,
			   MKDEV(MAJOR(binderfs_dev), minor));
	inode->i_fop = &binder_fops;
	inode->i_uid = GLOBAL_ROOT_UID;
	inode->i_gid = GLOBAL_ROOT_GID;

	refcount_set(&device->ref, 1);
	device->binderfs_inode = inode;
	device->context.binder_context_mgr_uid = INVALID_UID;
	device->context.name = name;
	device->miscdev.name = name;
	device->miscdev.minor = minor;
	mutex_init(&device->context.context_mgr_node_lock);

	req->major = MAJOR(binderfs_dev);
	req->minor = minor;

	if (userp && copy_to_user(userp, req, sizeof(*req))) {
		ret = -EFAULT;
		goto err;
	}

	root = ref_inode->i_sb->s_root;
	inode_lock(d_inode(root));

	dentry = lookup_one_len(name, root, name_len);
	if (IS_ERR(dentry)) {
		inode_unlock(d_inode(root));
		ret = PTR_ERR(dentry);
		goto err;
	}

	if (d_really_is_positive(dentry)) {
		dput(dentry);
		inode_unlock(d_inode(root));
		ret = -EEXIST;
		goto err;
	}

	inode->i_private = device;
	d_instantiate(dentry, inode);
	fsnotify_create(d_inode(root), dentry);
	inode_unlock(d_inode(root));

	return 0;

err:
	kfree(name);
	kfree(device);
	iput(inode);

	mutex_lock(&binderfs_minors_mutex);
	--info->device_count;
	ida_simple_remove(&binderfs_minors, minor);
	mutex_unlock(&binderfs_minors_mutex);

	return ret;
}

static long binder_ctl_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	struct binderfs_device __user *userp =
		(struct binderfs_device __user *)arg;
	struct binderfs_device req;

	switch (cmd) {
	case BINDER_CTL_ADD:
		if (copy_from_user(&req, userp, sizeof(req)))
			return -EFAULT;

		return binderfs_binder_device_create(file_inode(file),
						     userp, &req);
	default:
		return -EINVAL;
	}
}

static const struct file_operations binder_ctl_fops = {
	.owner = THIS_MODULE,
	.open = nonseekable_open,
	.unlocked_ioctl = binder_ctl_ioctl,
	.compat_ioctl = binder_ctl_ioctl,
	.llseek = noop_llseek,
};

static void binderfs_evict_inode(struct inode *inode)
{
	struct binder_device *device = inode->i_private;
	struct binderfs_info *info = BINDERFS_I(inode);

	clear_inode(inode);

	if (!S_ISCHR(inode->i_mode) || !device)
		return;

	binderfs_put_minor(device->miscdev.minor);

	/* binder-control has no context name and is not part of device_count. */
	if (device->context.name) {
		mutex_lock(&binderfs_minors_mutex);
		--info->device_count;
		mutex_unlock(&binderfs_minors_mutex);
	}

	if (refcount_dec_and_test(&device->ref)) {
		kfree(device->context.name);
		kfree(device);
	}
}

static int binderfs_parse_mount_opts(char *data,
				     struct binderfs_mount_opts *opts)
{
	char *p, *stats;

	opts->max = BINDERFS_MAX_MINOR;
	opts->stats_mode = STATS_NONE;

	while (data && (p = strsep(&data, ",")) != NULL) {
		substring_t args[MAX_OPT_ARGS];
		int token;
		int max_devices;

		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_max:
			if (match_int(&args[0], &max_devices) ||
			    max_devices < 0 ||
			    max_devices > BINDERFS_MAX_MINOR)
				return -EINVAL;
			opts->max = max_devices;
			break;
		case Opt_stats_mode:
			if (!capable(CAP_SYS_ADMIN))
				return -EPERM;

			stats = match_strdup(&args[0]);
			if (!stats)
				return -ENOMEM;

			if (strcmp(stats, "global")) {
				kfree(stats);
				return -EINVAL;
			}

			opts->stats_mode = STATS_GLOBAL;
			kfree(stats);
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}

static int binderfs_show_mount_opts(struct seq_file *seq,
				    struct dentry *root)
{
	struct binderfs_info *info = root->d_sb->s_fs_info;

	seq_printf(seq, ",max=%d", info->mount_opts.max);
	if (info->mount_opts.stats_mode == STATS_GLOBAL)
		seq_puts(seq, ",stats=global");

	return 0;
}

static const struct super_operations binderfs_super_ops = {
	.evict_inode = binderfs_evict_inode,
	.show_options = binderfs_show_mount_opts,
	.statfs = simple_statfs,
};

static inline bool is_binderfs_control_device(const struct dentry *dentry)
{
	struct binderfs_info *info = dentry->d_sb->s_fs_info;

	return info->control_dentry == dentry;
}

static int binderfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			   struct inode *new_dir, struct dentry *new_dentry,
			   unsigned int flags)
{
	if (is_binderfs_control_device(old_dentry) ||
	    is_binderfs_control_device(new_dentry))
		return -EPERM;

	return simple_rename(old_dir, old_dentry, new_dir, new_dentry, flags);
}

static int binderfs_unlink(struct inode *dir, struct dentry *dentry)
{
	if (is_binderfs_control_device(dentry))
		return -EPERM;

	return simple_unlink(dir, dentry);
}

static const struct inode_operations binderfs_dir_inode_operations = {
	.lookup = simple_lookup,
	.rename = binderfs_rename,
	.unlink = binderfs_unlink,
};

static int binderfs_binder_ctl_create(struct super_block *sb)
{
	int minor, ret = -ENOMEM;
	struct dentry *dentry;
	struct binder_device *device = NULL;
	struct inode *inode = NULL;
	struct binderfs_info *info = sb->s_fs_info;

	if (info->control_dentry)
		return 0;

	minor = binderfs_get_minor();
	if (minor < 0)
		return minor;

	device = kzalloc(sizeof(*device), GFP_KERNEL);
	if (!device)
		goto err;

	inode = new_inode(sb);
	if (!inode)
		goto err;

	inode->i_ino = SECOND_INODE;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	init_special_inode(inode, S_IFCHR | 0600,
			   MKDEV(MAJOR(binderfs_dev), minor));
	inode->i_fop = &binder_ctl_fops;
	inode->i_uid = GLOBAL_ROOT_UID;
	inode->i_gid = GLOBAL_ROOT_GID;

	refcount_set(&device->ref, 1);
	device->binderfs_inode = inode;
	device->miscdev.minor = minor;

	dentry = d_alloc_name(sb->s_root, "binder-control");
	if (!dentry)
		goto err;

	inode->i_private = device;
	info->control_dentry = dentry;
	d_add(dentry, inode);

	return 0;

err:
	iput(inode);
	kfree(device);
	binderfs_put_minor(minor);
	return ret;
}

static struct inode *binderfs_make_inode(struct super_block *sb, int mode)
{
	struct inode *inode;

	inode = new_inode(sb);
	if (!inode)
		return NULL;

	inode->i_ino = iunique(sb, BINDERFS_MAX_MINOR + INODE_OFFSET);
	inode->i_mode = mode;
	inode->i_uid = GLOBAL_ROOT_UID;
	inode->i_gid = GLOBAL_ROOT_GID;
	inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);

	return inode;
}

static struct dentry *binderfs_create_dentry(struct dentry *parent,
					      const char *name)
{
	struct dentry *dentry;

	dentry = lookup_one_len(name, parent, strlen(name));
	if (IS_ERR(dentry))
		return dentry;

	if (d_really_is_positive(dentry)) {
		dput(dentry);
		return ERR_PTR(-EEXIST);
	}

	return dentry;
}

void binderfs_remove_file(struct dentry *dentry)
{
	struct inode *parent_inode;

	parent_inode = d_inode(dentry->d_parent);
	inode_lock(parent_inode);
	if (simple_positive(dentry)) {
		dget(dentry);
		simple_unlink(parent_inode, dentry);
		d_delete(dentry);
		dput(dentry);
	}
	inode_unlock(parent_inode);
}

struct dentry *binderfs_create_file(struct dentry *parent, const char *name,
				    const struct file_operations *fops,
				    void *data)
{
	struct dentry *dentry;
	struct inode *inode, *parent_inode;

	parent_inode = d_inode(parent);
	inode_lock(parent_inode);

	dentry = binderfs_create_dentry(parent, name);
	if (IS_ERR(dentry))
		goto out;

	inode = binderfs_make_inode(parent_inode->i_sb, S_IFREG | 0444);
	if (!inode) {
		dput(dentry);
		dentry = ERR_PTR(-ENOMEM);
		goto out;
	}

	inode->i_fop = fops;
	inode->i_private = data;
	d_instantiate(dentry, inode);
	fsnotify_create(parent_inode, dentry);

out:
	inode_unlock(parent_inode);
	return dentry;
}

static struct dentry *binderfs_create_dir(struct dentry *parent,
					  const char *name)
{
	struct dentry *dentry;
	struct inode *inode, *parent_inode;

	parent_inode = d_inode(parent);
	inode_lock(parent_inode);

	dentry = binderfs_create_dentry(parent, name);
	if (IS_ERR(dentry))
		goto out;

	inode = binderfs_make_inode(parent_inode->i_sb, S_IFDIR | 0755);
	if (!inode) {
		dput(dentry);
		dentry = ERR_PTR(-ENOMEM);
		goto out;
	}

	inode->i_fop = &simple_dir_operations;
	inode->i_op = &simple_dir_inode_operations;
	set_nlink(inode, 2);

	d_instantiate(dentry, inode);
	inc_nlink(parent_inode);
	fsnotify_mkdir(parent_inode, dentry);

out:
	inode_unlock(parent_inode);
	return dentry;
}

static int binder_features_show(struct seq_file *m, void *unused)
{
	bool *feature = m->private;

	seq_printf(m, "%d\n", *feature);
	return 0;
}

static int binder_features_open(struct inode *inode, struct file *file)
{
	return single_open(file, binder_features_show, inode->i_private);
}

static const struct file_operations binder_features_fops = {
	.owner = THIS_MODULE,
	.open = binder_features_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int init_binder_features(struct super_block *sb)
{
	struct dentry *dir, *dentry;

	dir = binderfs_create_dir(sb->s_root, "features");
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	dentry = binderfs_create_file(dir, "oneway_spam_detection",
				      &binder_features_fops,
				      &binder_features.oneway_spam_detection);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	return 0;
}

static int init_binder_logs(struct super_block *sb)
{
	struct dentry *dir, *proc_dir;
	struct binderfs_info *info = sb->s_fs_info;
	int ret;

	dir = binderfs_create_dir(sb->s_root, "binder_logs");
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	ret = binderfs_create_logs(dir);
	if (ret)
		return ret;

	proc_dir = binderfs_create_dir(dir, "proc");
	if (IS_ERR(proc_dir))
		return PTR_ERR(proc_dir);

	info->proc_log_dir = proc_dir;
	return 0;
}

static int binderfs_fill_super(struct super_block *sb, void *data, int silent)
{
	int ret;
	struct binderfs_info *info;
	struct inode *inode;
	struct binderfs_device req = { };
	const char *name;
	size_t len;

	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_magic = BINDERFS_SUPER_MAGIC;
	sb->s_op = &binderfs_super_ops;
	sb->s_time_gran = 1;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;
	sb->s_fs_info = info;

	ret = binderfs_parse_mount_opts(data, &info->mount_opts);
	if (ret)
		return ret;

	info->root_uid = GLOBAL_ROOT_UID;
	info->root_gid = GLOBAL_ROOT_GID;

	inode = new_inode(sb);
	if (!inode)
		return -ENOMEM;

	inode->i_ino = FIRST_INODE;
	inode->i_fop = &simple_dir_operations;
	inode->i_op = &binderfs_dir_inode_operations;
	inode->i_mode = S_IFDIR | 0755;
	inode->i_uid = GLOBAL_ROOT_UID;
	inode->i_gid = GLOBAL_ROOT_GID;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	set_nlink(inode, 2);

	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		return -ENOMEM;

	ret = binderfs_binder_ctl_create(sb);
	if (ret)
		return ret;

	name = binder_devices_param;
	while (*name) {
		len = strcspn(name, ",");
		if (!len) {
			name++;
			continue;
		}
		if (len > BINDERFS_MAX_NAME)
			return -E2BIG;

		memset(&req, 0, sizeof(req));
		memcpy(req.name, name, len);
		req.name[len] = '\0';

		ret = binderfs_binder_device_create(inode, NULL, &req);
		if (ret)
			return ret;

		name += len;
		if (*name == ',')
			name++;
	}

	ret = init_binder_features(sb);
	if (ret)
		return ret;

	if (info->mount_opts.stats_mode == STATS_GLOBAL)
		return init_binder_logs(sb);

	return 0;
}

static struct dentry *binderfs_mount(struct file_system_type *fs_type,
				     int flags, const char *dev_name,
				     void *data)
{
	/*
	 * Upstream BinderFS supports user-namespace mounts. Keep this 4.9
	 * backport restricted to the initial user namespace used by Android init.
	 */
	if (current_user_ns() != &init_user_ns)
		return ERR_PTR(-EPERM);

	return mount_nodev(fs_type, flags, data, binderfs_fill_super);
}

static void binderfs_kill_super(struct super_block *sb)
{
	struct binderfs_info *info = sb->s_fs_info;

	kill_litter_super(sb);
	kfree(info);
}

static struct file_system_type binder_fs_type = {
	.name = "binder",
	.mount = binderfs_mount,
	.kill_sb = binderfs_kill_super,
};

int __init init_binderfs(void)
{
	int ret;
	const char *name;
	size_t len;

	name = binder_devices_param;
	while (*name) {
		len = strcspn(name, ",");
		if (len > BINDERFS_MAX_NAME)
			return -E2BIG;

		name += len;
		if (*name == ',')
			name++;
	}

	ret = alloc_chrdev_region(&binderfs_dev, 0, BINDERFS_MAX_MINOR,
				  "binder");
	if (ret)
		return ret;

	ret = register_filesystem(&binder_fs_type);
	if (ret) {
		unregister_chrdev_region(binderfs_dev, BINDERFS_MAX_MINOR);
		return ret;
	}

	return 0;
}
