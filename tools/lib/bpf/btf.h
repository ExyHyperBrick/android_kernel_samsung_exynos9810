/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2018 Facebook */

#ifndef __LIBBPF_BTF_H
#define __LIBBPF_BTF_H

#include <linux/btf.h>
#include <linux/types.h>

#define BTF_ELF_SEC ".BTF"

struct btf;
struct btf_ext;

void btf__free(struct btf *btf);
struct btf *btf__new(const void *data, __u32 size);
struct btf *btf__parse_elf(const char *path, struct btf_ext **btf_ext);
__u32 btf__get_nr_types(const struct btf *btf);
const char *btf__name_by_offset(const struct btf *btf, __u32 offset);
const struct btf_type *btf__type_by_id(const struct btf *btf, __u32 id);

/*
 * A set of helpers for easier BTF types handling
 */
static inline __u16 btf_kind(const struct btf_type *t)
{
	return BTF_INFO_KIND(t->info);
}

static inline __u16 btf_vlen(const struct btf_type *t)
{
	return BTF_INFO_VLEN(t->info);
}

static inline bool btf_kflag(const struct btf_type *t)
{
	return BTF_INFO_KFLAG(t->info);
}

static inline bool btf_is_int(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_INT;
}

static inline bool btf_is_ptr(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_PTR;
}

static inline bool btf_is_array(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_ARRAY;
}

static inline bool btf_is_struct(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_STRUCT;
}

static inline bool btf_is_union(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_UNION;
}

static inline bool btf_is_composite(const struct btf_type *t)
{
	__u16 kind = btf_kind(t);

	return kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION;
}

static inline bool btf_is_enum(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_ENUM;
}

static inline bool btf_is_fwd(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_FWD;
}

static inline bool btf_is_typedef(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_TYPEDEF;
}

static inline bool btf_is_volatile(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_VOLATILE;
}

static inline bool btf_is_const(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_CONST;
}

static inline bool btf_is_restrict(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_RESTRICT;
}

static inline bool btf_is_mod(const struct btf_type *t)
{
	__u16 kind = btf_kind(t);

	return kind == BTF_KIND_VOLATILE ||
	       kind == BTF_KIND_CONST ||
	       kind == BTF_KIND_RESTRICT;
}

static inline bool btf_is_func(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_FUNC;
}

static inline bool btf_is_func_proto(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_FUNC_PROTO;
}

static inline bool btf_is_var(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_VAR;
}

static inline bool btf_is_datasec(const struct btf_type *t)
{
	return btf_kind(t) == BTF_KIND_DATASEC;
}

static inline __u8 btf_int_encoding(const struct btf_type *t)
{
	return BTF_INT_ENCODING(*(__u32 *)(t + 1));
}

static inline __u8 btf_int_offset(const struct btf_type *t)
{
	return BTF_INT_OFFSET(*(__u32 *)(t + 1));
}

static inline __u8 btf_int_bits(const struct btf_type *t)
{
	return BTF_INT_BITS(*(__u32 *)(t + 1));
}

static inline struct btf_array *btf_array(const struct btf_type *t)
{
	return (struct btf_array *)(t + 1);
}

static inline struct btf_enum *btf_enum(const struct btf_type *t)
{
	return (struct btf_enum *)(t + 1);
}

static inline struct btf_member *btf_members(const struct btf_type *t)
{
	return (struct btf_member *)(t + 1);
}

/* Get bit offset of a member with specified index. */
static inline __u32 btf_member_bit_offset(const struct btf_type *t,
					  __u32 member_idx)
{
	const struct btf_member *m = btf_members(t) + member_idx;
	bool kflag = btf_kflag(t);

	return kflag ? BTF_MEMBER_BIT_OFFSET(m->offset) : m->offset;
}

/*
 * Get bitfield size of a member, assuming t is BTF_KIND_STRUCT or
 * BTF_KIND_UNION. If member is not a bitfield, zero is returned.
 */
static inline __u32 btf_member_bitfield_size(const struct btf_type *t,
					     __u32 member_idx)
{
	const struct btf_member *m = btf_members(t) + member_idx;
	bool kflag = btf_kflag(t);

	return kflag ? BTF_MEMBER_BITFIELD_SIZE(m->offset) : 0;
}

static inline struct btf_param *btf_params(const struct btf_type *t)
{
	return (struct btf_param *)(t + 1);
}

static inline struct btf_var *btf_var(const struct btf_type *t)
{
	return (struct btf_var *)(t + 1);
}

static inline struct btf_var_secinfo *
btf_var_secinfos(const struct btf_type *t)
{
	return (struct btf_var_secinfo *)(t + 1);
}

#endif /* __LIBBPF_BTF_H */
