/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 Facebook */

#ifndef __LIBBPF_BTF_H
#define __LIBBPF_BTF_H

#include <linux/btf.h>
#include <linux/types.h>

#define BTF_ELF_SEC ".BTF"

struct btf;

void btf__free(struct btf *btf);
struct btf *btf__new(const void *data, __u32 size);

#endif /* __LIBBPF_BTF_H */
