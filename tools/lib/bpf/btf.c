// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2018 Facebook */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <linux/btf.h>
#include <linux/err.h>
#include <linux/kernel.h>

#include "btf.h"

#define BTF_MAX_NR_TYPES	65535U

#define pr_debug(fmt, ...)	do { } while (0)

static struct btf_type btf_void;

struct btf {
	union {
		struct btf_header *hdr;
		void *data;
	};
	struct btf_type **types;
	const char *strings;
	void *nohdr_data;
	__u32 nr_types;
	__u32 types_size;
	__u32 data_size;
};

static int btf_add_type(struct btf *btf, struct btf_type *t)
{
	if (btf->types_size - btf->nr_types < 2) {
		struct btf_type **new_types;
		__u32 expand_by, new_size;

		if (btf->types_size == BTF_MAX_NR_TYPES)
			return -E2BIG;

		expand_by = max(btf->types_size >> 2, 16U);
		new_size = min(BTF_MAX_NR_TYPES,
			       btf->types_size + expand_by);

		new_types = realloc(btf->types,
				    sizeof(*new_types) * new_size);
		if (!new_types)
			return -ENOMEM;

		if (!btf->nr_types)
			new_types[0] = &btf_void;

		btf->types = new_types;
		btf->types_size = new_size;
	}

	btf->types[++btf->nr_types] = t;
	return 0;
}

static int btf_parse_hdr(struct btf *btf)
{
	const struct btf_header *hdr = btf->hdr;
	__u32 meta_left;

	if (btf->data_size < sizeof(*hdr)) {
		pr_debug("BTF header not found\n");
		return -EINVAL;
	}

	if (hdr->magic != BTF_MAGIC) {
		pr_debug("invalid BTF magic: %x\n", hdr->magic);
		return -EINVAL;
	}

	if (hdr->version != BTF_VERSION) {
		pr_debug("unsupported BTF version: %u\n", hdr->version);
		return -ENOTSUP;
	}

	if (hdr->flags) {
		pr_debug("unsupported BTF flags: %x\n", hdr->flags);
		return -ENOTSUP;
	}

	if (hdr->hdr_len < sizeof(*hdr) ||
	    hdr->hdr_len > btf->data_size) {
		pr_debug("invalid BTF header length: %u\n", hdr->hdr_len);
		return -EINVAL;
	}

	meta_left = btf->data_size - hdr->hdr_len;
	if (!meta_left) {
		pr_debug("BTF has no data\n");
		return -EINVAL;
	}

	if (hdr->type_off > meta_left ||
	    hdr->type_len > meta_left - hdr->type_off) {
		pr_debug("invalid BTF type section\n");
		return -EINVAL;
	}

	if (hdr->str_off > meta_left ||
	    hdr->str_len > meta_left - hdr->str_off) {
		pr_debug("invalid BTF string section\n");
		return -EINVAL;
	}

	if (hdr->type_off + hdr->type_len > hdr->str_off) {
		pr_debug("BTF type section overlaps string section\n");
		return -EINVAL;
	}

	if (hdr->type_off & 0x3) {
		pr_debug("BTF type section is not aligned to 4 bytes\n");
		return -EINVAL;
	}

	btf->nohdr_data = (char *)btf->data + hdr->hdr_len;
	return 0;
}

static int btf_parse_str_sec(struct btf *btf)
{
	const struct btf_header *hdr = btf->hdr;
	const char *start = btf->nohdr_data + hdr->str_off;
	const char *end = start + hdr->str_len;

	if (!hdr->str_len || hdr->str_len - 1 > BTF_MAX_NAME_OFFSET ||
	    start[0] || end[-1]) {
		pr_debug("invalid BTF string section\n");
		return -EINVAL;
	}

	btf->strings = start;
	return 0;
}

static int btf_type_size(const struct btf_type *t)
{
	int base_size = sizeof(*t);
	__u16 vlen = BTF_INFO_VLEN(t->info);

	switch (BTF_INFO_KIND(t->info)) {
	case BTF_KIND_FWD:
	case BTF_KIND_CONST:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_PTR:
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_FUNC:
		return base_size;
	case BTF_KIND_INT:
		return base_size + sizeof(__u32);
	case BTF_KIND_ENUM:
		return base_size + vlen * sizeof(struct btf_enum);
	case BTF_KIND_ARRAY:
		return base_size + sizeof(struct btf_array);
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		return base_size + vlen * sizeof(struct btf_member);
	case BTF_KIND_FUNC_PROTO:
		return base_size + vlen * sizeof(struct btf_param);
	default:
		pr_debug("unsupported BTF kind: %u\n",
			 BTF_INFO_KIND(t->info));
		return -EINVAL;
	}
}

static int btf_parse_type_sec(struct btf *btf)
{
	const struct btf_header *hdr = btf->hdr;
	char *next_type = btf->nohdr_data + hdr->type_off;
	char *end_type = next_type + hdr->type_len;

	while (next_type < end_type) {
		struct btf_type *t = (struct btf_type *)next_type;
		size_t type_left = end_type - next_type;
		int type_size;
		int err;

		if (type_left < sizeof(*t))
			return -EINVAL;

		type_size = btf_type_size(t);
		if (type_size < 0 || (size_t)type_size > type_left)
			return -EINVAL;

		err = btf_add_type(btf, t);
		if (err)
			return err;

		next_type += type_size;
	}

	return next_type == end_type ? 0 : -EINVAL;
}

__u32 btf__get_nr_types(const struct btf *btf)
{
	return btf->nr_types;
}

void btf__free(struct btf *btf)
{
	if (!btf)
		return;

	free(btf->data);
	free(btf->types);
	free(btf);
}

struct btf *btf__new(const void *data, __u32 size)
{
	struct btf *btf;
	int err;

	btf = calloc(1, sizeof(*btf));
	if (!btf)
		return ERR_PTR(-ENOMEM);

	btf->data = malloc(size);
	if (!btf->data) {
		err = -ENOMEM;
		goto err_out;
	}

	memcpy(btf->data, data, size);
	btf->data_size = size;

	err = btf_parse_hdr(btf);
	if (err)
		goto err_out;

	err = btf_parse_str_sec(btf);
	if (err)
		goto err_out;

	err = btf_parse_type_sec(btf);
	if (err)
		goto err_out;

	return btf;

err_out:
	btf__free(btf);
	return ERR_PTR(err);
}

const char *btf__name_by_offset(const struct btf *btf, __u32 offset)
{
	if (offset < btf->hdr->str_len)
		return btf->strings + offset;

	return NULL;
}

const struct btf_type *btf__type_by_id(const struct btf *btf, __u32 type_id)
{
	if (type_id > btf->nr_types)
		return NULL;

	return btf->types[type_id];
}
