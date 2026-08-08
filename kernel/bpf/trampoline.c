// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2019 Facebook */
#include <linux/hash.h>
#include <linux/bpf.h>
#include <linux/filter.h>

/* dummy _ops. The verifier will operate on target program's ops. */
const struct bpf_verifier_ops bpf_extension_verifier_ops = {
};

const struct bpf_prog_ops bpf_extension_prog_ops = {
};

/* btf_vmlinux has about 22k attachable functions. A 1k table is enough. */
#define TRAMPOLINE_HASH_BITS 10
#define TRAMPOLINE_TABLE_SIZE (1 << TRAMPOLINE_HASH_BITS)

static struct hlist_head trampoline_table[TRAMPOLINE_TABLE_SIZE];

/* Serializes access to trampoline_table. */
static DEFINE_MUTEX(trampoline_mutex);

static struct bpf_trampoline *bpf_trampoline_lookup(u64 key)
{
	struct bpf_trampoline *tr = NULL;
	struct hlist_head *head;
	void *image;
	int i;

	mutex_lock(&trampoline_mutex);
	head = &trampoline_table[hash_64(key, TRAMPOLINE_HASH_BITS)];
	hlist_for_each_entry(tr, head, hlist) {
		if (tr->key == key) {
			refcount_inc(&tr->refcnt);
			goto out;
		}
	}

	tr = kzalloc(sizeof(*tr), GFP_KERNEL);
	if (!tr)
		goto out;

	/* The caller was checked for privilege before reaching this point. */
	image = bpf_jit_alloc_exec(PAGE_SIZE);
	if (!image) {
		kfree(tr);
		tr = NULL;
		goto out;
	}

	tr->key = key;
	INIT_HLIST_NODE(&tr->hlist);
	hlist_add_head(&tr->hlist, head);
	refcount_set(&tr->refcnt, 1);
	mutex_init(&tr->mutex);
	for (i = 0; i < BPF_TRAMP_MAX; i++)
		INIT_HLIST_HEAD(&tr->progs_hlist[i]);

	set_vm_flush_reset_perms(image);
	/* Keep the image writable instead of flipping it for every update. */
	set_memory_x((unsigned long)image, 1);
	tr->image = image;
out:
	mutex_unlock(&trampoline_mutex);
	return tr;
}

/* Each BPF invocation occupies about 50 bytes on x86. Keep one generated
 * trampoline within half a page so the other half remains update reserve.
 */
#define BPF_MAX_TRAMP_PROGS 40

static int bpf_trampoline_update(struct bpf_trampoline *tr)
{
	void *old_image = tr->image +
		((tr->selector + 1) & 1) * PAGE_SIZE / 2;
	void *new_image = tr->image +
		(tr->selector & 1) * PAGE_SIZE / 2;
	struct bpf_prog *progs_to_run[BPF_MAX_TRAMP_PROGS];
	int fentry_cnt = tr->progs_cnt[BPF_TRAMP_FENTRY];
	int fexit_cnt = tr->progs_cnt[BPF_TRAMP_FEXIT];
	struct bpf_prog **progs, **fentry, **fexit;
	u32 flags = BPF_TRAMP_F_RESTORE_REGS;
	struct bpf_prog_aux *aux;
	bool ip_arg = false;
	int err;

	if (fentry_cnt + fexit_cnt == 0) {
		err = bpf_arch_text_poke(tr->func.addr, BPF_MOD_CALL,
					 old_image, NULL);
		tr->selector = 0;
		goto out;
	}

	fentry = progs = progs_to_run;
	hlist_for_each_entry(aux, &tr->progs_hlist[BPF_TRAMP_FENTRY],
			     tramp_hlist) {
		ip_arg |= aux->prog->call_get_func_ip;
		*progs++ = aux->prog;
	}

	fexit = progs;
	hlist_for_each_entry(aux, &tr->progs_hlist[BPF_TRAMP_FEXIT],
			     tramp_hlist) {
		ip_arg |= aux->prog->call_get_func_ip;
		*progs++ = aux->prog;
	}

	if (fexit_cnt)
		flags = BPF_TRAMP_F_CALL_ORIG | BPF_TRAMP_F_SKIP_FRAME;
	if (ip_arg)
		flags |= BPF_TRAMP_F_IP_ARG;

	err = arch_prepare_bpf_trampoline(new_image, &tr->func.model, flags,
					  fentry, fentry_cnt,
					  fexit, fexit_cnt,
					  tr->func.addr);
	if (err)
		goto out;

	if (tr->selector)
		err = bpf_arch_text_poke(tr->func.addr, BPF_MOD_CALL,
					 old_image, new_image);
	else
		err = bpf_arch_text_poke(tr->func.addr, BPF_MOD_CALL,
					 NULL, new_image);
	if (err)
		goto out;

	tr->selector++;
out:
	return err;
}

static enum bpf_tramp_prog_type
bpf_attach_type_to_tramp(enum bpf_attach_type type)
{
	switch (type) {
	case BPF_TRACE_FENTRY:
		return BPF_TRAMP_FENTRY;
	case BPF_TRACE_FEXIT:
		return BPF_TRAMP_FEXIT;
	default:
		return BPF_TRAMP_REPLACE;
	}
}

int bpf_trampoline_link_prog(struct bpf_prog *prog,
			     struct bpf_trampoline *tr)
{
	enum bpf_tramp_prog_type kind;
	int err = 0;
	int cnt;

	kind = bpf_attach_type_to_tramp(prog->expected_attach_type);
	mutex_lock(&tr->mutex);
	if (tr->extension_prog) {
		/* cannot attach fentry/fexit if extension prog is attached.
		 * cannot overwrite extension prog either.
		 */
		err = -EBUSY;
		goto out;
	}
	cnt = tr->progs_cnt[BPF_TRAMP_FENTRY] +
	      tr->progs_cnt[BPF_TRAMP_FEXIT];
	if (kind == BPF_TRAMP_REPLACE) {
		/* Cannot attach extension if fentry/fexit are in use. */
		if (cnt) {
			err = -EBUSY;
			goto out;
		}
		tr->extension_prog = prog;
		err = bpf_arch_text_poke(tr->func.addr, BPF_MOD_JUMP, NULL,
					 prog->bpf_func);
		if (err)
			tr->extension_prog = NULL;
		goto out;
	}
	if (cnt >= BPF_MAX_TRAMP_PROGS) {
		err = -E2BIG;
		goto out;
	}
	if (!hlist_unhashed(&prog->aux->tramp_hlist)) {
		err = -EBUSY;
		goto out;
	}

	hlist_add_head(&prog->aux->tramp_hlist, &tr->progs_hlist[kind]);
	tr->progs_cnt[kind]++;
	err = bpf_trampoline_update(tr);
	if (err) {
		hlist_del_init(&prog->aux->tramp_hlist);
		tr->progs_cnt[kind]--;
	}
out:
	mutex_unlock(&tr->mutex);
	return err;
}

/* Detaching a program from a successfully installed trampoline must not fail. */
int bpf_trampoline_unlink_prog(struct bpf_prog *prog,
			       struct bpf_trampoline *tr)
{
	enum bpf_tramp_prog_type kind;
	int err;

	kind = bpf_attach_type_to_tramp(prog->expected_attach_type);
	mutex_lock(&tr->mutex);
	if (kind == BPF_TRAMP_REPLACE) {
		WARN_ON_ONCE(!tr->extension_prog);
		err = bpf_arch_text_poke(tr->func.addr, BPF_MOD_JUMP,
					 tr->extension_prog->bpf_func, NULL);
		tr->extension_prog = NULL;
		goto out;
	}
	hlist_del_init(&prog->aux->tramp_hlist);
	tr->progs_cnt[kind]--;
	err = bpf_trampoline_update(tr);
out:
	mutex_unlock(&tr->mutex);
	return err;
}


struct bpf_trampoline *bpf_trampoline_get(
	u64 key, struct bpf_attach_target_info *tgt_info)
{
	struct bpf_trampoline *tr;

	tr = bpf_trampoline_lookup(key);
	if (!tr)
		return NULL;

	mutex_lock(&tr->mutex);
	if (tr->func.addr)
		goto out;

	memcpy(&tr->func.model, &tgt_info->fmodel, sizeof(tgt_info->fmodel));
	tr->func.addr = (void *)tgt_info->tgt_addr;
out:
	mutex_unlock(&tr->mutex);
	return tr;
}

void bpf_trampoline_put(struct bpf_trampoline *tr)
{
	if (!tr)
		return;

	mutex_lock(&trampoline_mutex);
	if (!refcount_dec_and_test(&tr->refcnt))
		goto out;
	WARN_ON_ONCE(mutex_is_locked(&tr->mutex));
	if (WARN_ON_ONCE(!hlist_empty(&tr->progs_hlist[BPF_TRAMP_FENTRY])))
		goto out;
	if (WARN_ON_ONCE(!hlist_empty(&tr->progs_hlist[BPF_TRAMP_FEXIT])))
		goto out;

	bpf_jit_free_exec(tr->image);
	hlist_del(&tr->hlist);
	kfree(tr);
out:
	mutex_unlock(&trampoline_mutex);
}

/* These helpers bracket generated trampoline calls with the execution state
 * and optional per-program statistics used by normal BPF invocation paths.
 */
u64 notrace __bpf_prog_enter(void)
{
	u64 start = 0;

	rcu_read_lock();
	preempt_disable();
	if (static_branch_unlikely(&bpf_stats_enabled_key))
		start = sched_clock();
	return start;
}

void notrace __bpf_prog_exit(struct bpf_prog *prog, u64 start)
{
	struct bpf_prog_stats *stats;

	if (static_branch_unlikely(&bpf_stats_enabled_key) && start) {
		stats = this_cpu_ptr(prog->aux->stats);
		u64_stats_update_begin(&stats->syncp);
		stats->cnt++;
		stats->nsecs += sched_clock() - start;
		u64_stats_update_end(&stats->syncp);
	}
	preempt_enable();
	rcu_read_unlock();
}

int __weak
arch_prepare_bpf_trampoline(void *image, struct btf_func_model *m, u32 flags,
			    struct bpf_prog **fentry_progs, int fentry_cnt,
			    struct bpf_prog **fexit_progs, int fexit_cnt,
			    void *orig_call)
{
	return -ENOTSUPP;
}

static int __init init_trampolines(void)
{
	int i;

	for (i = 0; i < TRAMPOLINE_TABLE_SIZE; i++)
		INIT_HLIST_HEAD(&trampoline_table[i]);
	return 0;
}
late_initcall(init_trampolines);
