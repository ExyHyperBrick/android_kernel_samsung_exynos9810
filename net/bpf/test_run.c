/* Copyright (c) 2017 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <linux/bpf.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/etherdevice.h>
#include <linux/filter.h>
#include <linux/sched.h>
#include <net/bpf_sk_storage.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <linux/sock_diag.h>

static __always_inline u32 bpf_test_run_one(struct bpf_prog *prog, void *ctx)
{
	u32 ret;

	preempt_disable();
	rcu_read_lock();
	ret = bpf_prog_run(prog, ctx);
	rcu_read_unlock();
	preempt_enable();

	return ret;
}

static u32 bpf_test_run(struct bpf_prog *prog, void *ctx, u32 repeat, u32 *time)
{
	u64 time_start, time_spent = 0;
	u32 ret = 0, i;

	if (!repeat)
		repeat = 1;
	time_start = ktime_get_ns();
	for (i = 0; i < repeat; i++) {
		ret = bpf_test_run_one(prog, ctx);
		if (need_resched()) {
			if (signal_pending(current))
				break;
			time_spent += ktime_get_ns() - time_start;
			cond_resched();
			time_start = ktime_get_ns();
		}
	}
	time_spent += ktime_get_ns() - time_start;
	do_div(time_spent, repeat);
	*time = time_spent > U32_MAX ? U32_MAX : (u32)time_spent;

	return ret;
}

static int bpf_test_finish(const union bpf_attr *kattr,
			   union bpf_attr __user *uattr, const void *data,
			   u32 size, u32 retval, u32 duration)
{
	void __user *data_out = u64_to_user_ptr(kattr->test.data_out);
	int err = -EFAULT;
	u32 copy_size = size;

	/* Clamp copy if the user has provided a size hint, but copy the full
	 * buffer if not to retain old behaviour.
	 */
	if (kattr->test.data_size_out &&
	    copy_size > kattr->test.data_size_out) {
		copy_size = kattr->test.data_size_out;
		err = -ENOSPC;
	}

	if (data_out && copy_to_user(data_out, data, copy_size))
		goto out;
	if (copy_to_user(&uattr->test.data_size_out, &size, sizeof(size)))
		goto out;
	if (copy_to_user(&uattr->test.retval, &retval, sizeof(retval)))
		goto out;
	if (copy_to_user(&uattr->test.duration, &duration, sizeof(duration)))
		goto out;
	if (err != -ENOSPC)
		err = 0;
out:
	return err;
}

static void *bpf_test_init(const union bpf_attr *kattr, u32 size,
			   u32 headroom, u32 tailroom)
{
	void __user *data_in = u64_to_user_ptr(kattr->test.data_in);
	u32 user_size = size;
	void *data;

	if (user_size < ETH_HLEN)
		return ERR_PTR(-EINVAL);

	size = SKB_DATA_ALIGN(user_size);
	if (size > PAGE_SIZE - headroom - tailroom)
		return ERR_PTR(-EINVAL);

	data = kzalloc(size + headroom + tailroom, GFP_USER);
	if (!data)
		return ERR_PTR(-ENOMEM);

	if (copy_from_user(data + headroom, data_in, user_size)) {
		kfree(data);
		return ERR_PTR(-EFAULT);
	}
	return data;
}

static void *bpf_ctx_init(const union bpf_attr *kattr, u32 max_size)
{
	void __user *data_in = u64_to_user_ptr(kattr->test.ctx_in);
	void __user *data_out = u64_to_user_ptr(kattr->test.ctx_out);
	u32 size = kattr->test.ctx_size_in;
	void *data;
	int err;

	if (!data_in && !data_out)
		return NULL;

	data = kzalloc(max_size, GFP_USER);
	if (!data)
		return ERR_PTR(-ENOMEM);

	if (data_in) {
		err = bpf_check_uarg_tail_zero(data_in, max_size, size);
		if (err) {
			kfree(data);
			return ERR_PTR(err);
		}

		size = min_t(u32, max_size, size);
		if (copy_from_user(data, data_in, size)) {
			kfree(data);
			return ERR_PTR(-EFAULT);
		}
	}
	return data;
}

static int bpf_ctx_finish(const union bpf_attr *kattr,
			  union bpf_attr __user *uattr, const void *data,
			  u32 size)
{
	void __user *data_out = u64_to_user_ptr(kattr->test.ctx_out);
	int err = -EFAULT;
	u32 copy_size = size;

	if (!data || !data_out)
		return 0;

	if (copy_size > kattr->test.ctx_size_out) {
		copy_size = kattr->test.ctx_size_out;
		err = -ENOSPC;
	}

	if (copy_to_user(data_out, data, copy_size))
		goto out;
	if (copy_to_user(&uattr->test.ctx_size_out, &size, sizeof(size)))
		goto out;
	if (err != -ENOSPC)
		err = 0;
out:
	return err;
}

/**
 * range_is_zero - test whether buffer is initialized
 * @buf: buffer to check
 * @from: check from this position
 * @to: check up until (excluding) this position
 *
 * This function returns true if the there is a non-zero byte
 * in the buf in the range [from,to).
 */
static inline bool range_is_zero(void *buf, size_t from, size_t to)
{
	return !memchr_inv((u8 *)buf + from, 0, to - from);
}

static int convert___skb_to_skb(struct sk_buff *skb, struct __sk_buff *__skb)
{
	struct qdisc_skb_cb *cb = (struct qdisc_skb_cb *)skb->cb;

	if (!__skb)
		return 0;

	if (!range_is_zero(__skb, 0, offsetof(struct __sk_buff, priority)))
		return -EINVAL;

	if (!range_is_zero(__skb, offsetof(struct __sk_buff, priority) +
			   FIELD_SIZEOF(struct __sk_buff, priority),
			   offsetof(struct __sk_buff, cb)))
		return -EINVAL;

	if (!range_is_zero(__skb, offsetof(struct __sk_buff, cb) +
			   FIELD_SIZEOF(struct __sk_buff, cb),
			   sizeof(struct __sk_buff)))
		return -EINVAL;

	skb->priority = __skb->priority;
	memcpy(&cb->data, __skb->cb, QDISC_CB_PRIV_LEN);
	return 0;
}

static void convert_skb_to___skb(struct sk_buff *skb, struct __sk_buff *__skb)
{
	struct qdisc_skb_cb *cb = (struct qdisc_skb_cb *)skb->cb;

	if (!__skb)
		return;

	__skb->priority = skb->priority;
	memcpy(__skb->cb, &cb->data, QDISC_CB_PRIV_LEN);
}

int bpf_prog_test_run_skb(struct bpf_prog *prog, const union bpf_attr *kattr,
			  union bpf_attr __user *uattr)
{
	bool is_l2 = false, is_direct_pkt_access = false;
	u32 size = kattr->test.data_size_in;
	u32 repeat = kattr->test.repeat;
	struct __sk_buff *ctx = NULL;
	u32 retval, duration;
	struct sk_buff *skb;
	void *data;
	int ret;

	data = bpf_test_init(kattr, size, NET_SKB_PAD + NET_IP_ALIGN,
			     SKB_DATA_ALIGN(sizeof(struct skb_shared_info)));
	if (IS_ERR(data))
		return PTR_ERR(data);

	ctx = bpf_ctx_init(kattr, sizeof(struct __sk_buff));
	if (IS_ERR(ctx)) {
		kfree(data);
		return PTR_ERR(ctx);
	}

	switch (prog->type) {
	case BPF_PROG_TYPE_SCHED_CLS:
	case BPF_PROG_TYPE_SCHED_ACT:
		is_l2 = true;
		/* fall through */
	case BPF_PROG_TYPE_LWT_IN:
	case BPF_PROG_TYPE_LWT_OUT:
	case BPF_PROG_TYPE_LWT_XMIT:
		is_direct_pkt_access = true;
		break;
	default:
		break;
	}

	skb = build_skb(data, 0);
	if (!skb) {
		kfree(data);
		kfree(ctx);
		return -ENOMEM;
	}

	skb_reserve(skb, NET_SKB_PAD + NET_IP_ALIGN);
	__skb_put(skb, size);
	skb->protocol = eth_type_trans(skb, current->nsproxy->net_ns->loopback_dev);
	skb_reset_network_header(skb);

	if (is_l2)
		__skb_push(skb, ETH_HLEN);
	if (is_direct_pkt_access)
		bpf_compute_data_pointers(skb);
	ret = convert___skb_to_skb(skb, ctx);
	if (ret)
		goto out;
	retval = bpf_test_run(prog, skb, repeat, &duration);
	if (!is_l2) {
		if (skb_headroom(skb) < ETH_HLEN) {
			int nhead = HH_DATA_ALIGN(ETH_HLEN - skb_headroom(skb));

			if (pskb_expand_head(skb, nhead, 0, GFP_USER)) {
				ret = -ENOMEM;
				goto out;
			}
		}
		memset(__skb_push(skb, ETH_HLEN), 0, ETH_HLEN);
	}
	convert_skb_to___skb(skb, ctx);
	size = skb->len;
	/* bpf program can never convert linear skb to non-linear */
	if (WARN_ON_ONCE(skb_is_nonlinear(skb)))
		size = skb_headlen(skb);
	ret = bpf_test_finish(kattr, uattr, skb->data, size, retval, duration);
	if (!ret)
		ret = bpf_ctx_finish(kattr, uattr, ctx,
				     sizeof(struct __sk_buff));
out:
	kfree_skb(skb);
	kfree(ctx);
	return ret;
}

int bpf_prog_test_run_xdp(struct bpf_prog *prog, const union bpf_attr *kattr,
			  union bpf_attr __user *uattr)
{
	u32 size = kattr->test.data_size_in;
	u32 repeat = kattr->test.repeat;
	struct xdp_buff xdp = {};
	u32 retval, duration;
	void *data;
	int ret;

	if (prog->expected_attach_type == BPF_XDP_DEVMAP ||
	    prog->expected_attach_type == BPF_XDP_CPUMAP)
		return -EINVAL;
	if (kattr->test.ctx_in || kattr->test.ctx_out)
		return -EINVAL;

	data = bpf_test_init(kattr, size, XDP_PACKET_HEADROOM + NET_IP_ALIGN, 0);
	if (IS_ERR(data))
		return PTR_ERR(data);

	xdp.data_hard_start = data;
	xdp.data = data + XDP_PACKET_HEADROOM + NET_IP_ALIGN;
	xdp.data_meta = xdp.data;
	xdp.data_end = xdp.data + size;

	retval = bpf_test_run(prog, &xdp, repeat, &duration);
	if (xdp.data != data + XDP_PACKET_HEADROOM + NET_IP_ALIGN ||
	    xdp.data_end != xdp.data + size)
		size = xdp.data_end - xdp.data;
	ret = bpf_test_finish(kattr, uattr, xdp.data, size, retval, duration);
	kfree(data);
	return ret;
}

int bpf_prog_test_run_sk_lookup(struct bpf_prog *prog,
				const union bpf_attr *kattr,
				union bpf_attr __user *uattr)
{
	struct bpf_prog_array *progs = NULL;
	struct bpf_sk_lookup_kern ctx = {};
	u32 repeat = kattr->test.repeat;
	struct bpf_sk_lookup *user_ctx;
	u64 time_start, time_spent = 0;
	u32 retval = 0, duration;
	int ret = -EINVAL;
	u32 i;

	if (prog->type != BPF_PROG_TYPE_SK_LOOKUP)
		return -EINVAL;

	if (kattr->test.data_in || kattr->test.data_size_in ||
	    kattr->test.data_out || kattr->test.data_size_out)
		return -EINVAL;

	if (!repeat)
		repeat = 1;

	user_ctx = bpf_ctx_init(kattr, sizeof(*user_ctx));
	if (IS_ERR(user_ctx))
		return PTR_ERR(user_ctx);
	if (!user_ctx)
		return -EINVAL;
	if (user_ctx->sk)
		goto out;
	if (!range_is_zero(user_ctx,
			   offsetofend(typeof(*user_ctx), local_port),
			   sizeof(*user_ctx)))
		goto out;
	if (user_ctx->local_port > U16_MAX) {
		ret = -ERANGE;
		goto out;
	}

	ctx.family = (u16)user_ctx->family;
	ctx.protocol = (u16)user_ctx->protocol;
	ctx.dport = (u16)user_ctx->local_port;
	ctx.sport = user_ctx->remote_port;

	switch (ctx.family) {
	case AF_INET:
		ctx.v4.daddr = (__force __be32)user_ctx->local_ip4;
		ctx.v4.saddr = (__force __be32)user_ctx->remote_ip4;
		break;
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
		ctx.v6.daddr = (struct in6_addr *)user_ctx->local_ip6;
		ctx.v6.saddr = (struct in6_addr *)user_ctx->remote_ip6;
		break;
#endif
	default:
		ret = -EAFNOSUPPORT;
		goto out;
	}

	progs = bpf_prog_array_alloc(1, GFP_KERNEL);
	if (!progs) {
		ret = -ENOMEM;
		goto out;
	}
	progs->items[0].prog = prog;

	time_start = ktime_get_ns();
	for (i = 0; i < repeat; i++) {
		ctx.selected_sk = NULL;
		rcu_read_lock();
		retval = BPF_PROG_SK_LOOKUP_RUN_ARRAY(progs, &ctx,
							bpf_prog_run);
		rcu_read_unlock();

		if (signal_pending(current)) {
			ret = -EINTR;
			goto out;
		}
		if (need_resched()) {
			time_spent += ktime_get_ns() - time_start;
			cond_resched();
			time_start = ktime_get_ns();
		}
	}
	time_spent += ktime_get_ns() - time_start;
	do_div(time_spent, repeat);
	duration = time_spent > U32_MAX ? U32_MAX : (u32)time_spent;

	user_ctx->cookie = 0;
	if (ctx.selected_sk) {
		if (ctx.selected_sk->sk_reuseport && !ctx.no_reuseport) {
			ret = -EOPNOTSUPP;
			goto out;
		}
		user_ctx->cookie = sock_gen_cookie(ctx.selected_sk);
	}

	ret = bpf_test_finish(kattr, uattr, NULL, 0, retval, duration);
	if (!ret)
		ret = bpf_ctx_finish(kattr, uattr, user_ctx,
				     sizeof(*user_ctx));
out:
	bpf_prog_array_free(progs);
	kfree(user_ctx);
	return ret;
}
