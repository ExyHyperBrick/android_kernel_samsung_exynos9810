/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
#include <linux/bpf.h>
#include <linux/rcupdate.h>
#include <linux/random.h>
#include <linux/smp.h>
#include <linux/topology.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <linux/uidgid.h>
#include <linux/filter.h>
#include <linux/ctype.h>
#include <linux/uaccess.h>

/* If kernel subsystem is allowing eBPF programs to call this function,
 * inside its own verifier_ops->get_func_proto() callback it should return
 * bpf_map_lookup_elem_proto, so that verifier can properly check the arguments
 *
 * Different map implementations will rely on rcu in map methods
 * lookup/update/delete, therefore eBPF programs must run under rcu lock
 * if program is allowed to access maps, so check rcu_read_lock_held in
 * all three functions.
 */
BPF_CALL_2(bpf_map_lookup_elem, struct bpf_map *, map, void *, key)
{
	WARN_ON_ONCE(!rcu_read_lock_held());
	return (unsigned long) map->ops->map_lookup_elem(map, key);
}

const struct bpf_func_proto bpf_map_lookup_elem_proto = {
	.func		= bpf_map_lookup_elem,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
};

BPF_CALL_4(bpf_map_update_elem, struct bpf_map *, map, void *, key,
	   void *, value, u64, flags)
{
	WARN_ON_ONCE(!rcu_read_lock_held());
	return map->ops->map_update_elem(map, key, value, flags);
}

const struct bpf_func_proto bpf_map_update_elem_proto = {
	.func		= bpf_map_update_elem,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
	.arg3_type	= ARG_PTR_TO_MAP_VALUE,
	.arg4_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_map_delete_elem, struct bpf_map *, map, void *, key)
{
	WARN_ON_ONCE(!rcu_read_lock_held());
	return map->ops->map_delete_elem(map, key);
}

const struct bpf_func_proto bpf_map_delete_elem_proto = {
	.func		= bpf_map_delete_elem,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
};

BPF_CALL_3(bpf_map_push_elem, struct bpf_map *, map, void *, value, u64, flags)
{
	return map->ops->map_push_elem(map, value, flags);
}

const struct bpf_func_proto bpf_map_push_elem_proto = {
	.func		= bpf_map_push_elem,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_VALUE,
	.arg3_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_map_pop_elem, struct bpf_map *, map, void *, value)
{
	return map->ops->map_pop_elem(map, value);
}

const struct bpf_func_proto bpf_map_pop_elem_proto = {
	.func		= bpf_map_pop_elem,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_UNINIT_MAP_VALUE,
};

BPF_CALL_2(bpf_map_peek_elem, struct bpf_map *, map, void *, value)
{
	return map->ops->map_peek_elem(map, value);
}

const struct bpf_func_proto bpf_map_peek_elem_proto = {
	.func		= bpf_map_peek_elem,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_UNINIT_MAP_VALUE,
};

BPF_CALL_4(bpf_for_each_map_elem, struct bpf_map *, map, void *, callback_fn,
	   void *, callback_ctx, u64, flags)
{
	return map->ops->map_for_each_callback(map, callback_fn,
					       callback_ctx, flags);
}

const struct bpf_func_proto bpf_for_each_map_elem_proto = {
	.func		= bpf_for_each_map_elem,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_FUNC,
	.arg3_type	= ARG_PTR_TO_STACK_OR_NULL,
	.arg4_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_per_cpu_ptr, const void *, ptr, u32, cpu)
{
	if (cpu >= nr_cpu_ids)
		return (unsigned long)NULL;

	return (unsigned long)per_cpu_ptr((const void __percpu *)ptr, cpu);
}

const struct bpf_func_proto bpf_per_cpu_ptr_proto = {
	.func		= bpf_per_cpu_ptr,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MEM_OR_BTF_ID_OR_NULL,
	.arg1_type	= ARG_PTR_TO_PERCPU_BTF_ID,
	.arg2_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_this_cpu_ptr, const void *, ptr)
{
	return (unsigned long)this_cpu_ptr((const void __percpu *)ptr);
}

const struct bpf_func_proto bpf_this_cpu_ptr_proto = {
	.func		= bpf_this_cpu_ptr,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MEM_OR_BTF_ID,
	.arg1_type	= ARG_PTR_TO_PERCPU_BTF_ID,
};

static int bpf_trace_copy_string(char *buf, void *unsafe_ptr, char fmt_ptype,
				 size_t bufsz)
{
	void __user *user_ptr = (__force void __user *)unsafe_ptr;

	buf[0] = '\0';

	switch (fmt_ptype) {
	case 's':
#ifdef CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE
		if ((unsigned long)unsafe_ptr < TASK_SIZE)
			return strncpy_from_user_nofault(buf, user_ptr, bufsz);
		fallthrough;
#endif
	case 'k':
		return strncpy_from_unsafe_strict(buf, unsafe_ptr, bufsz);
	case 'u':
		return strncpy_from_user_nofault(buf, user_ptr, bufsz);
	}

	return -EINVAL;
}

/* Per-CPU temporary storage for printf-like helpers using %s or %p. */
#define MAX_PRINTF_BUF_LEN	512

struct bpf_printf_buf {
	char tmp_buf[MAX_PRINTF_BUF_LEN];
};

static DEFINE_PER_CPU(struct bpf_printf_buf, bpf_printf_buf);
static DEFINE_PER_CPU(int, bpf_printf_buf_used);

static int try_get_fmt_tmp_buf(char **tmp_buf)
{
	struct bpf_printf_buf *bufs;
	int used;

	if (*tmp_buf)
		return 0;

	preempt_disable();
	used = this_cpu_inc_return(bpf_printf_buf_used);
	if (WARN_ON_ONCE(used > 1)) {
		this_cpu_dec(bpf_printf_buf_used);
		preempt_enable();
		return -EBUSY;
	}
	bufs = this_cpu_ptr(&bpf_printf_buf);
	*tmp_buf = bufs->tmp_buf;

	return 0;
}

void bpf_printf_cleanup(void)
{
	if (this_cpu_read(bpf_printf_buf_used)) {
		this_cpu_dec(bpf_printf_buf_used);
		preempt_enable();
	}
}

/*
 * bpf_printf_prepare - Generic pass on format strings for printf-like helpers
 *
 * Returns a negative value if fmt is an invalid format string or zero.
 *
 * This can be used in two ways:
 * - Format string verification only: when final_args and mod are NULL.
 * - Argument preparation: final_args receives sanitized arguments and mod
 *   describes the size of each argument for BPF_CAST_FMT_ARG().
 *
 * In argument preparation mode, bpf_printf_cleanup() must be called after a
 * successful return to release any temporary buffers.
 */
int bpf_printf_prepare(char *fmt, u32 fmt_size, const u64 *raw_args,
		       u64 *final_args, enum bpf_printf_mod_type *mod,
		       u32 num_args)
{
	char *unsafe_ptr = NULL, *tmp_buf = NULL, *fmt_end;
	size_t tmp_buf_len = MAX_PRINTF_BUF_LEN;
	int err, i, num_spec = 0, copy_size;
	enum bpf_printf_mod_type cur_mod;
	u64 cur_arg;
	char fmt_ptype;

	if (!!final_args != !!mod)
		return -EINVAL;

	fmt_end = strnchr(fmt, fmt_size, '\0');
	if (!fmt_end)
		return -EINVAL;
	fmt_size = fmt_end - fmt;

	for (i = 0; i < fmt_size; i++) {
		if ((!isprint(fmt[i]) && !isspace(fmt[i])) ||
		    !isascii(fmt[i])) {
			err = -EINVAL;
			goto cleanup;
		}

		if (fmt[i] != '%')
			continue;

		if (fmt[i + 1] == '%') {
			i++;
			continue;
		}

		if (num_spec >= num_args) {
			err = -EINVAL;
			goto cleanup;
		}

		/*
		 * The string is NUL-terminated, so fmt[i + 1] is always
		 * accessible after a non-NUL '%' character.
		 */
		i++;

		/* Skip an optional "[0 +-][num]" width field. */
		while (fmt[i] == '0' || fmt[i] == '+' || fmt[i] == '-' ||
		       fmt[i] == ' ')
			i++;
		if (fmt[i] >= '1' && fmt[i] <= '9') {
			i++;
			while (fmt[i] >= '0' && fmt[i] <= '9')
				i++;
		}

		if (fmt[i] == 'p') {
			cur_mod = BPF_PRINTF_LONG;

			if ((fmt[i + 1] == 'k' || fmt[i + 1] == 'u') &&
			    fmt[i + 2] == 's') {
				fmt_ptype = fmt[i + 1];
				i += 2;
				goto fmt_str;
			}

			if (fmt[i + 1] == '\0' || isspace(fmt[i + 1]) ||
			    ispunct(fmt[i + 1]) || fmt[i + 1] == 'K' ||
			    fmt[i + 1] == 'x' || fmt[i + 1] == 'B' ||
			    fmt[i + 1] == 's' || fmt[i + 1] == 'S') {
				if (final_args)
					cur_arg = raw_args[num_spec];
				goto fmt_next;
			}

			/* Support only %pI4, %pi4, %pI6 and %pi6. */
			if ((fmt[i + 1] != 'i' && fmt[i + 1] != 'I') ||
			    (fmt[i + 2] != '4' && fmt[i + 2] != '6')) {
				err = -EINVAL;
				goto cleanup;
			}

			i += 2;
			if (!final_args)
				goto fmt_next;

			if (try_get_fmt_tmp_buf(&tmp_buf)) {
				err = -EBUSY;
				goto out;
			}

			copy_size = fmt[i] == '4' ? 4 : 16;
			if (tmp_buf_len < copy_size) {
				err = -ENOSPC;
				goto cleanup;
			}

			unsafe_ptr = (char *)(long)raw_args[num_spec];
			err = probe_kernel_read_strict(tmp_buf, unsafe_ptr,
						       copy_size);
			if (err < 0)
				memset(tmp_buf, 0, copy_size);
			cur_arg = (u64)(long)tmp_buf;
			tmp_buf += copy_size;
			tmp_buf_len -= copy_size;

			goto fmt_next;
		} else if (fmt[i] == 's') {
			cur_mod = BPF_PRINTF_LONG;
			fmt_ptype = fmt[i];
fmt_str:
			if (fmt[i + 1] != '\0' && !isspace(fmt[i + 1]) &&
			    !ispunct(fmt[i + 1])) {
				err = -EINVAL;
				goto cleanup;
			}

			if (!final_args)
				goto fmt_next;

			if (try_get_fmt_tmp_buf(&tmp_buf)) {
				err = -EBUSY;
				goto out;
			}

			if (!tmp_buf_len) {
				err = -ENOSPC;
				goto cleanup;
			}

			unsafe_ptr = (char *)(long)raw_args[num_spec];
			err = bpf_trace_copy_string(tmp_buf, unsafe_ptr,
						    fmt_ptype, tmp_buf_len);
			if (err < 0) {
				tmp_buf[0] = '\0';
				err = 1;
			}

			cur_arg = (u64)(long)tmp_buf;
			tmp_buf += err;
			tmp_buf_len -= err;

			goto fmt_next;
		}

		cur_mod = BPF_PRINTF_INT;

		if (fmt[i] == 'l') {
			cur_mod = BPF_PRINTF_LONG;
			i++;
		}
		if (fmt[i] == 'l') {
			cur_mod = BPF_PRINTF_LONG_LONG;
			i++;
		}

		if (fmt[i] != 'i' && fmt[i] != 'd' && fmt[i] != 'u' &&
		    fmt[i] != 'x' && fmt[i] != 'X') {
			err = -EINVAL;
			goto cleanup;
		}

		if (final_args)
			cur_arg = raw_args[num_spec];
fmt_next:
		if (final_args) {
			mod[num_spec] = cur_mod;
			final_args[num_spec] = cur_arg;
		}
		num_spec++;
	}

	err = 0;
cleanup:
	if (err)
		bpf_printf_cleanup();
out:
	return err;
}

const struct bpf_func_proto bpf_get_prandom_u32_proto = {
	.func		= bpf_user_rnd_u32,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_get_smp_processor_id)
{
	return smp_processor_id();
}

const struct bpf_func_proto bpf_get_smp_processor_id_proto = {
	.func		= bpf_get_smp_processor_id,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_get_numa_node_id)
{
	return numa_node_id();
}

const struct bpf_func_proto bpf_get_numa_node_id_proto = {
	.func		= bpf_get_numa_node_id,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_ktime_get_ns)
{
	/* NMI safe access to clock monotonic */
	return ktime_get_mono_fast_ns();
}

const struct bpf_func_proto bpf_ktime_get_ns_proto = {
	.func		= bpf_ktime_get_ns,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_ktime_get_boot_ns)
{
	/* NMI safe access to clock boottime */
	return ktime_get_boot_fast_ns();
}

const struct bpf_func_proto bpf_ktime_get_boot_ns_proto = {
	.func		= bpf_ktime_get_boot_ns,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_get_current_pid_tgid)
{
	struct task_struct *task = current;

	if (unlikely(!task))
		return -EINVAL;

	return (u64) task->tgid << 32 | task->pid;
}

const struct bpf_func_proto bpf_get_current_pid_tgid_proto = {
	.func		= bpf_get_current_pid_tgid,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_get_current_uid_gid)
{
	struct task_struct *task = current;
	kuid_t uid;
	kgid_t gid;

	if (unlikely(!task))
		return -EINVAL;

	current_uid_gid(&uid, &gid);
	return (u64) from_kgid(&init_user_ns, gid) << 32 |
		     from_kuid(&init_user_ns, uid);
}

const struct bpf_func_proto bpf_get_current_uid_gid_proto = {
	.func		= bpf_get_current_uid_gid,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_2(bpf_get_current_comm, char *, buf, u32, size)
{
	struct task_struct *task = current;

	if (unlikely(!task))
		goto err_clear;

	strncpy(buf, task->comm, size);

	/* Verifier guarantees that size > 0. For task->comm exceeding
	 * size, guarantee that buf is %NUL-terminated. Unconditionally
	 * done here to save the size test.
	 */
	buf[size - 1] = 0;
	return 0;
err_clear:
	memset(buf, 0, size);
	return -EINVAL;
}

const struct bpf_func_proto bpf_get_current_comm_proto = {
	.func		= bpf_get_current_comm,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE,
};

#if defined(CONFIG_QUEUED_SPINLOCKS) || defined(CONFIG_BPF_ARCH_SPINLOCK)
static inline void __bpf_spin_lock(struct bpf_spin_lock *lock)
{
	arch_spinlock_t *l = (void *)lock;
	union {
		__u32 val;
		arch_spinlock_t lock;
	} u = { .lock = __ARCH_SPIN_LOCK_UNLOCKED };
	compiletime_assert(u.val == 0, "__ARCH_SPIN_LOCK_UNLOCKED not 0");
	BUILD_BUG_ON(sizeof(*l) != sizeof(__u32));
	BUILD_BUG_ON(sizeof(*lock) != sizeof(__u32));
	arch_spin_lock(l);
}

static inline void __bpf_spin_unlock(struct bpf_spin_lock *lock)
{
	arch_spinlock_t *l = (void *)lock;
	arch_spin_unlock(l);
}

#else
static inline void __bpf_spin_lock(struct bpf_spin_lock *lock)
{
	atomic_t *l = (void *)lock;
	BUILD_BUG_ON(sizeof(*l) != sizeof(*lock));
	do {
		atomic_cond_read_relaxed(l, !VAL);
	} while (atomic_xchg(l, 1));
}

static inline void __bpf_spin_unlock(struct bpf_spin_lock *lock)
{
	atomic_t *l = (void *)lock;
	atomic_set_release(l, 0);
}
#endif

static DEFINE_PER_CPU(unsigned long, irqsave_flags);
notrace BPF_CALL_1(bpf_spin_lock, struct bpf_spin_lock *, lock)
{
	unsigned long flags;
	local_irq_save(flags);
	__bpf_spin_lock(lock);
	__this_cpu_write(irqsave_flags, flags);
	return 0;
}

const struct bpf_func_proto bpf_spin_lock_proto = {
	.func		= bpf_spin_lock,
	.gpl_only	= false,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_SPIN_LOCK,
};

notrace BPF_CALL_1(bpf_spin_unlock, struct bpf_spin_lock *, lock)
{
	unsigned long flags;
	flags = __this_cpu_read(irqsave_flags);
	__bpf_spin_unlock(lock);
	local_irq_restore(flags);
	return 0;
}

const struct bpf_func_proto bpf_spin_unlock_proto = {
	.func		= bpf_spin_unlock,
	.gpl_only	= false,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_SPIN_LOCK,
};

void copy_map_value_locked(struct bpf_map *map, void *dst, void *src,
			   bool lock_src)
{
	struct bpf_spin_lock *lock;
	if (lock_src)
		lock = src + map->spin_lock_off;
	else
		lock = dst + map->spin_lock_off;
	preempt_disable();
	____bpf_spin_lock(lock);
	copy_map_value(map, dst, src);
	____bpf_spin_unlock(lock);
	preempt_enable();
}

#ifdef CONFIG_CGROUPS
BPF_CALL_0(bpf_get_current_cgroup_id)
{
	struct cgroup *cgrp = task_dfl_cgroup(current);
	return cgrp->kn->id.id;
}
const struct bpf_func_proto bpf_get_current_cgroup_id_proto = {
	.func		= bpf_get_current_cgroup_id,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};
#endif

#ifdef CONFIG_CGROUP_BPF
DECLARE_PER_CPU(void*, bpf_cgroup_storage[MAX_BPF_CGROUP_STORAGE_TYPE]);
BPF_CALL_2(bpf_get_local_storage, struct bpf_map *, map, u64, flags)
{
	/* flags argument is not used now,
	 * but provides an ability to extend the API.
	 * verifier checks that its value is correct.
	 */
	enum bpf_cgroup_storage_type stype = cgroup_storage_type(map);
	struct bpf_cgroup_storage *storage;
	void *ptr;

	storage = this_cpu_read(bpf_cgroup_storage[stype]);

	if (stype == BPF_CGROUP_STORAGE_SHARED)
		ptr = &READ_ONCE(storage->buf)->data[0];
	else
		ptr = this_cpu_ptr(storage->percpu_buf);
	return (unsigned long)ptr;
}
const struct bpf_func_proto bpf_get_local_storage_proto = {
	.func		= bpf_get_local_storage,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MAP_VALUE,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_ANYTHING,
};
#endif
