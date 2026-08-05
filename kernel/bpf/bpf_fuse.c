// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Google LLC

#include <linux/android_fuse.h>
#include <linux/filter.h>

#define FUSE_BPF_COMPAT_ARG_SIZE 256

static const struct bpf_func_proto *
fuse_prog_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_trace_printk:
		return bpf_get_trace_printk_proto();
	case BPF_FUNC_get_current_uid_gid:
		return &bpf_get_current_uid_gid_proto;
	case BPF_FUNC_get_current_pid_tgid:
		return &bpf_get_current_pid_tgid_proto;
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;
	default:
		return NULL;
	}
}

static bool fuse_prog_is_scalar_access(int off, int size)
{
	switch (off) {
	case offsetof(struct fuse_bpf_args, nodeid):
		return size == sizeof(((struct fuse_bpf_args *)0)->nodeid);
	case offsetof(struct fuse_bpf_args, opcode):
		return size == sizeof(((struct fuse_bpf_args *)0)->opcode);
	case offsetof(struct fuse_bpf_args, error_in):
		return size == sizeof(((struct fuse_bpf_args *)0)->error_in);
	case offsetof(struct fuse_bpf_args, in_numargs):
		return size == sizeof(((struct fuse_bpf_args *)0)->in_numargs);
	case offsetof(struct fuse_bpf_args, out_numargs):
		return size == sizeof(((struct fuse_bpf_args *)0)->out_numargs);
	case offsetof(struct fuse_bpf_args, flags):
		return size == sizeof(((struct fuse_bpf_args *)0)->flags);
	default:
		return false;
	}
}

static bool fuse_prog_is_valid_access(int off, int size,
				      enum bpf_access_type type,
				      const struct bpf_prog *prog,
				      struct bpf_insn_access_aux *info)
{
	int i;

	if (off < 0 || size <= 0 ||
	    size > (int)sizeof(struct fuse_bpf_args) ||
	    off > (int)sizeof(struct fuse_bpf_args) - size)
		return false;
	if (type != BPF_READ)
		return false;

	if (fuse_prog_is_scalar_access(off, size))
		return true;

	for (i = 0; i < FUSE_MAX_IN_ARGS; i++) {
		if (off == (int)offsetof(struct fuse_bpf_args,
					 in_args[i].size))
			return size == sizeof(((struct fuse_bpf_args *)0)->
					      in_args[0].size);
		if (off == (int)offsetof(struct fuse_bpf_args,
					 in_args[i].value)) {
			if (size != (int)sizeof(void *))
				return false;
			info->reg_type = PTR_TO_RDONLY_BUF;
			info->ctx_field_size = FUSE_BPF_COMPAT_ARG_SIZE;
			return true;
		}
		if (off == (int)offsetof(struct fuse_bpf_args,
					 in_args[i].end_offset))
			return size == (int)sizeof(void *);
	}

	for (i = 0; i < FUSE_MAX_OUT_ARGS; i++) {
		if (off == (int)offsetof(struct fuse_bpf_args,
					 out_args[i].size))
			return size == sizeof(((struct fuse_bpf_args *)0)->
					      out_args[0].size);
		if (off == (int)offsetof(struct fuse_bpf_args,
					 out_args[i].value)) {
			if (size != (int)sizeof(void *))
				return false;
			info->reg_type = PTR_TO_RDWR_BUF;
			info->ctx_field_size = FUSE_BPF_COMPAT_ARG_SIZE;
			return true;
		}
		if (off == (int)offsetof(struct fuse_bpf_args,
					 out_args[i].end_offset))
			return size == (int)sizeof(void *);
	}
	return false;
}

const struct bpf_verifier_ops fuse_verifier_ops = {
	.get_func_proto = fuse_prog_func_proto,
	.is_valid_access = fuse_prog_is_valid_access,
};

const struct bpf_prog_ops fuse_prog_ops = {
};

struct bpf_prog *fuse_get_bpf_prog(struct file *file)
{
	struct bpf_prog *prog = ERR_PTR(-EINVAL);

	if (!file || IS_ERR(file))
		return prog;

	if (file->f_op != &bpf_prog_fops)
		goto out;

	prog = file->private_data;
	if (prog->type == BPF_PROG_TYPE_FUSE)
		bpf_prog_inc(prog);
	else
		prog = ERR_PTR(-EINVAL);

out:
	fput(file);
	return prog;
}
EXPORT_SYMBOL_GPL(fuse_get_bpf_prog);
