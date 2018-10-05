/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2018 Facebook */

#ifndef __LIBBPF_BTF_H
#define __LIBBPF_BTF_H

#include <linux/btf.h>
#include <linux/types.h>

#define BTF_ELF_SEC ".BTF"

struct btf;

void btf__free(struct btf *btf);
struct btf *btf__new(const void *data, __u32 size);
const char *btf__name_by_offset(const struct btf *btf, __u32 offset);
const struct btf_type *btf__type_by_id(const struct btf *btf, __u32 id);

#endif /* __LIBBPF_BTF_H */
