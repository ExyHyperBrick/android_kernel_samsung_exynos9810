/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_ANDROID_BINDERFS_H
#define _UAPI_LINUX_ANDROID_BINDERFS_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define BINDERFS_MAX_NAME 255

/**
 * struct binderfs_device - information about a BinderFS Binder device
 * @name: name of the Binder device
 * @major: major number allocated by BinderFS
 * @minor: minor number allocated to this Binder device
 */
struct binderfs_device {
	char name[BINDERFS_MAX_NAME + 1];
	__u32 major;
	__u32 minor;
};

#define BINDER_CTL_ADD _IOWR('b', 1, struct binderfs_device)

#endif /* _UAPI_LINUX_ANDROID_BINDERFS_H */
