/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_BINDER_INTERNAL_H
#define _LINUX_BINDER_INTERNAL_H

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/types.h>
#include <linux/uidgid.h>
#include <uapi/linux/android/binderfs.h>

struct binder_node;

struct binder_context {
	struct binder_node *binder_context_mgr_node;
	struct mutex context_mgr_node_lock;

	kuid_t binder_context_mgr_uid;
	const char *name;
};

/**
 * struct binder_device - information about a binder device node
 * @hlist: list entry for legacy misc Binder devices
 * @miscdev: legacy Binder misc-device information
 * @context: Binder context information
 * @binderfs_inode: BinderFS inode when the device belongs to BinderFS
 */
struct binder_device {
	struct hlist_node hlist;
	struct miscdevice miscdev;
	struct binder_context context;
	struct inode *binderfs_inode;
	refcount_t ref;
};

struct binderfs_mount_opts {
	int max;
	int stats_mode;
};

struct binderfs_info {
	struct dentry *control_dentry;
	kuid_t root_uid;
	kgid_t root_gid;
	struct binderfs_mount_opts mount_opts;
	int device_count;
	struct dentry *proc_log_dir;
};

extern const struct file_operations binder_fops;
extern char *binder_devices_param;

#ifdef CONFIG_ANDROID_BINDERFS
bool is_binderfs_device(const struct inode *inode);
struct dentry *binderfs_create_file(struct dentry *dir, const char *name,
				    const struct file_operations *fops,
				    void *data);
void binderfs_remove_file(struct dentry *dentry);
int binderfs_create_logs(struct dentry *dir);
int __init init_binderfs(void);
#else
static inline bool is_binderfs_device(const struct inode *inode)
{
	return false;
}
static inline struct dentry *binderfs_create_file(
					   struct dentry *dir,
					   const char *name,
					   const struct file_operations *fops,
					   void *data)
{
	return NULL;
}
static inline void binderfs_remove_file(struct dentry *dentry)
{
}
static inline int __init init_binderfs(void)
{
	return 0;
}
#endif

#endif /* _LINUX_BINDER_INTERNAL_H */
