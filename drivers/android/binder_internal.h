/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_BINDER_INTERNAL_H
#define _LINUX_BINDER_INTERNAL_H

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/uidgid.h>

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
};

extern const struct file_operations binder_fops;

#ifdef CONFIG_ANDROID_BINDERFS
bool is_binderfs_device(const struct inode *inode);
#else
static inline bool is_binderfs_device(const struct inode *inode)
{
	return false;
}
#endif

#endif /* _LINUX_BINDER_INTERNAL_H */
