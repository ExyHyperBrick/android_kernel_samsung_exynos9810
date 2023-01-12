// SPDX-License-Identifier: GPL-2.0
/*
 * FUSE-BPF request dispatcher
 * Copyright (c) 2021 Google LLC
 */

#include "fuse_i.h"

#include <linux/errno.h>
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
