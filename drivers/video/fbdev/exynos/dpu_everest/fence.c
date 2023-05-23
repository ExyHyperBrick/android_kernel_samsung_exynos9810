/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * DPU fence file for Samsung EXYNOS DPU driver
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/sync_file.h>

#include "decon.h"

/* sync fence related functions */
void decon_create_timeline(struct decon_device *decon, char *name)
{
	decon->timeline = sync_timeline_create(name);
	decon->timeline_max = 0;
	if (decon->dt.out_type == DECON_OUT_WB)
		decon->timeline_max = 0;
}

int decon_get_valid_fd(void)
{
	int fd = 0;
	int fd_idx = 0;
	int unused_fd[FD_TRY_CNT] = {0};

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		return -EINVAL;

	if (fd < VALID_FD_VAL) {
		/*
		 * If fd from get_unused_fd() has value between 0 and 2,
		 * fd is tried to get value again except current fd vlaue.
		 */
		while (fd < VALID_FD_VAL) {
			decon_dbg("%s, unvalid fd[%d] is assigned to DECON\n",
					__func__, fd);
			unused_fd[fd_idx++] = fd;
			fd = get_unused_fd_flags(O_CLOEXEC);
			if (fd < 0) {
				decon_err("%s, unvalid fd[%d]\n", __func__,
						fd);
				break;
			}
		}

		while (fd_idx-- > 0) {
			decon_dbg("%s, unvalid fd[%d] is released by DECON\n",
					__func__, unused_fd[fd_idx]);
			put_unused_fd(unused_fd[fd_idx]);
		}

		if (fd < 0)
			return -EINVAL;
	}
	return fd;
}

void decon_create_release_fences(struct decon_device *decon,
		struct decon_win_config_data *win_data,
		struct sync_file *sync_file)
{
	int i = 0;

	for (i = 0; i < MAX_DECON_WIN; i++) {
		int state = win_data->config[i].state;
		int rel_fence = -1;

		if (state == DECON_WIN_STATE_BUFFER) {
			rel_fence = decon_get_valid_fd();
			if (rel_fence < 0) {
				decon_err("%s: failed to get unused fd\n",
						__func__);
				goto err;
			}

			fd_install(rel_fence,
					get_file(sync_file->file));
		}
		win_data->config[i].rel_fence = rel_fence;
	}
	return;
err:
	while (i-- > 0) {
		if (win_data->config[i].state == DECON_WIN_STATE_BUFFER) {
			put_unused_fd(win_data->config[i].rel_fence);
			win_data->config[i].rel_fence = -1;
		}
	}
	return;
}

int decon_create_fence(struct decon_device *decon, struct sync_file **sync_file)
{
	struct sync_pt *pt;
	int fd = -EMFILE;

	decon->timeline_max++;
	pt = sync_pt_create(decon->timeline, sizeof(*pt), decon->timeline_max);
	if (!pt) {
		decon_err("%s: failed to create sync pt\n", __func__);
		goto err;
	}

	*sync_file = sync_file_create(&pt->base);
	fence_put(&pt->base);
	if (!(*sync_file)) {
		decon_err("%s: failed to create sync file\n", __func__);
		goto err;
	}

	fd = decon_get_valid_fd();
	if (fd < 0) {
		decon_err("%s: failed to get unused fd\n", __func__);
		fput((*sync_file)->file);
		goto err;
	}

	return fd;

err:
	decon->timeline_max--;
	return fd;
}

void decon_wait_fence(struct sync_file *sync_file)
{
	int err = sync_file_wait(sync_file, 900);
	if (err >= 0)
		return;

	if (err < 0)
		decon_warn("error waiting on acquire fence: %d\n", err);
}

void decon_signal_fence(struct decon_device *decon)
{
	sync_timeline_signal(decon->timeline, 1);
}
