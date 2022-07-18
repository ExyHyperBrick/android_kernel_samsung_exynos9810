/*
 * To speed up listener socket lookup, create an array to store all sockets
 * listening on the same port.  This allows a decision to be made after finding
 * the first socket.  An optional BPF program can also be configured for
 * selecting the socket index from the array of available sockets.
 */

#include <net/ip.h>
#include <net/sock_reuseport.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/idr.h>
#include <linux/rcupdate.h>

#define INIT_SOCKS 128

DEFINE_SPINLOCK(reuseport_lock);

#define REUSEPORT_MIN_ID 1
static DEFINE_IDA(reuseport_ida);
static int reuseport_resurrect(struct sock *sk, struct sock_reuseport *old_reuse,
			       struct sock_reuseport *reuse, bool bind_inany);

static int reuseport_sock_index(struct sock *sk,
				const struct sock_reuseport *reuse,
				bool closed)
{
	int left, right;

	if (!closed) {
		left = 0;
		right = reuse->num_socks;
	} else {
		left = reuse->max_socks - reuse->num_closed_socks;
		right = reuse->max_socks;
	}

	for (; left < right; left++)
		if (reuse->socks[left] == sk)
			return left;
	return -1;
}

static void __reuseport_add_sock(struct sock *sk,
				 struct sock_reuseport *reuse)
{
	reuse->socks[reuse->num_socks] = sk;
	/* paired with smp_rmb() in reuseport_(select|migrate)_sock() */
	smp_wmb();
	reuse->num_socks++;
}

static bool __reuseport_detach_sock(struct sock *sk,
				    struct sock_reuseport *reuse)
{
	int i = reuseport_sock_index(sk, reuse, false);

	if (i == -1)
		return false;

	reuse->socks[i] = reuse->socks[reuse->num_socks - 1];
	reuse->num_socks--;

	return true;
}

void reuseport_has_conns_set(struct sock *sk)
{
	struct sock_reuseport *reuse;

	if (!rcu_access_pointer(sk->sk_reuseport_cb))
		return;

	spin_lock_bh(&reuseport_lock);
	reuse = rcu_dereference_protected(sk->sk_reuseport_cb,
					  lockdep_is_held(&reuseport_lock));
	if (likely(reuse))
		reuse->has_conns = 1;
	spin_unlock_bh(&reuseport_lock);
}
EXPORT_SYMBOL(reuseport_has_conns_set);

int reuseport_get_id(struct sock_reuseport *reuse)
{
	int id;

	if (reuse->reuseport_id)
		return reuse->reuseport_id;

	id = ida_simple_get(&reuseport_ida, REUSEPORT_MIN_ID, 0,
			    /* Called under reuseport_lock */
			    GFP_ATOMIC);
	if (id < 0)
		return id;

	reuse->reuseport_id = id;

	return reuse->reuseport_id;
}

static void __reuseport_add_closed_sock(struct sock *sk,
					struct sock_reuseport *reuse)
{
	reuse->socks[reuse->max_socks - reuse->num_closed_socks - 1] = sk;
	/* paired with READ_ONCE() in inet_csk_bind_conflict() */
	WRITE_ONCE(reuse->num_closed_socks, reuse->num_closed_socks + 1);
}

static bool __reuseport_detach_closed_sock(struct sock *sk,
					   struct sock_reuseport *reuse)
{
	int i = reuseport_sock_index(sk, reuse, true);

	if (i == -1)
		return false;

	reuse->socks[i] = reuse->socks[reuse->max_socks - reuse->num_closed_socks];
	/* paired with READ_ONCE() in inet_csk_bind_conflict() */
	WRITE_ONCE(reuse->num_closed_socks, reuse->num_closed_socks - 1);

	return true;
}

static struct sock_reuseport *__reuseport_alloc(u16 max_socks)
{
	size_t size = sizeof(struct sock_reuseport) +
		      sizeof(struct sock *) * max_socks;
	struct sock_reuseport *reuse = kzalloc(size, GFP_ATOMIC);

	if (!reuse)
		return NULL;

	reuse->max_socks = max_socks;

	RCU_INIT_POINTER(reuse->prog, NULL);
	return reuse;
}

int reuseport_alloc(struct sock *sk, bool bind_inany)
{
	struct sock_reuseport *reuse;
	int ret = 0;

	/* bh lock used since this function call may precede hlist lock in
	 * soft irq of receive path or setsockopt from process context
	 */
	spin_lock_bh(&reuseport_lock);

	/* Allocation attempts can occur concurrently via the setsockopt path
	 * and the bind/hash path.  Nothing to do when we lose the race.
	 */
	reuse = rcu_dereference_protected(sk->sk_reuseport_cb,
					  lockdep_is_held(&reuseport_lock));
	if (reuse) {
		if (reuse->num_closed_socks) {
			/* sk was shutdown()ed before */
			ret = reuseport_resurrect(sk, reuse, NULL, bind_inany);
			goto out;
		}

		/* Only set reuse->bind_inany if the bind_inany is true.
		 * Otherwise, it will overwrite the reuse->bind_inany
		 * which was set by the bind/hash path.
		 */
		if (bind_inany)
			reuse->bind_inany = bind_inany;
		goto out;
	}

	reuse = __reuseport_alloc(INIT_SOCKS);
	if (!reuse) {
		spin_unlock_bh(&reuseport_lock);
		return -ENOMEM;
	}

	reuse->socks[0] = sk;
	reuse->num_socks = 1;
	reuse->bind_inany = bind_inany;
	rcu_assign_pointer(sk->sk_reuseport_cb, reuse);

out:
	spin_unlock_bh(&reuseport_lock);

	return ret;
}
EXPORT_SYMBOL(reuseport_alloc);

static struct sock_reuseport *reuseport_grow(struct sock_reuseport *reuse)
{
	struct sock_reuseport *more_reuse;
	u32 more_socks_size, i;

	more_socks_size = reuse->max_socks * 2U;
	if (more_socks_size > U16_MAX) {
		if (reuse->num_closed_socks) {
			/* Make room by removing a closed sk.
			 * The child has already been migrated.
			 * Only reqsk left at this point.
			 */
			struct sock *sk;

			sk = reuse->socks[reuse->max_socks - reuse->num_closed_socks];
			RCU_INIT_POINTER(sk->sk_reuseport_cb, NULL);
			__reuseport_detach_closed_sock(sk, reuse);

			return reuse;
		}

		return NULL;
	}

	more_reuse = __reuseport_alloc(more_socks_size);
	if (!more_reuse)
		return NULL;

	more_reuse->max_socks = more_socks_size;
	more_reuse->num_socks = reuse->num_socks;
	more_reuse->num_closed_socks = reuse->num_closed_socks;
	more_reuse->prog = reuse->prog;
	more_reuse->reuseport_id = reuse->reuseport_id;
	more_reuse->bind_inany = reuse->bind_inany;
	more_reuse->has_conns = reuse->has_conns;

	memcpy(more_reuse->socks, reuse->socks,
	       reuse->num_socks * sizeof(struct sock *));
	memcpy(more_reuse->socks +
	       (more_reuse->max_socks - more_reuse->num_closed_socks),
	       reuse->socks + (reuse->max_socks - reuse->num_closed_socks),
	       reuse->num_closed_socks * sizeof(struct sock *));

	for (i = 0; i < reuse->max_socks; ++i)
		rcu_assign_pointer(reuse->socks[i]->sk_reuseport_cb,
				   more_reuse);

	/* Note: we use kfree_rcu here instead of reuseport_free_rcu so
	 * that reuse and more_reuse can temporarily share a reference
	 * to prog.
	 */
	kfree_rcu(reuse, rcu);
	return more_reuse;
}

static void reuseport_free_rcu(struct rcu_head *head)
{
	struct sock_reuseport *reuse;

	reuse = container_of(head, struct sock_reuseport, rcu);
	sk_reuseport_prog_free(rcu_dereference_protected(reuse->prog, 1));
	if (reuse->reuseport_id)
		ida_simple_remove(&reuseport_ida, reuse->reuseport_id);
	kfree(reuse);
}

/**
 *  reuseport_add_sock - Add a socket to the reuseport group of another.
 *  @sk:  New socket to add to the group.
 *  @sk2: Socket belonging to the existing reuseport group.
 *  @bind_inany: Whether or not the group is bound to a local INANY address.
 *
 *  May return ENOMEM and not add socket to group under memory pressure.
 */
int reuseport_add_sock(struct sock *sk, struct sock *sk2, bool bind_inany)
{
	struct sock_reuseport *old_reuse, *reuse;

	if (!rcu_access_pointer(sk2->sk_reuseport_cb)) {
		int err = reuseport_alloc(sk2, bind_inany);

		if (err)
			return err;
	}

	spin_lock_bh(&reuseport_lock);
	reuse = rcu_dereference_protected(sk2->sk_reuseport_cb,
					  lockdep_is_held(&reuseport_lock));
	old_reuse = rcu_dereference_protected(sk->sk_reuseport_cb,
					      lockdep_is_held(&reuseport_lock));
	if (old_reuse && old_reuse->num_closed_socks) {
		/* sk was shutdown()ed before */
		int err = reuseport_resurrect(sk, old_reuse, reuse,
					    reuse->bind_inany);

		spin_unlock_bh(&reuseport_lock);
		return err;
	}

	if (old_reuse && old_reuse->num_socks != 1) {
		spin_unlock_bh(&reuseport_lock);
		return -EBUSY;
	}

	if (reuse->num_socks + reuse->num_closed_socks == reuse->max_socks) {
		reuse = reuseport_grow(reuse);
		if (!reuse) {
			spin_unlock_bh(&reuseport_lock);
			return -ENOMEM;
		}
	}

	__reuseport_add_sock(sk, reuse);
	rcu_assign_pointer(sk->sk_reuseport_cb, reuse);

	spin_unlock_bh(&reuseport_lock);

	if (old_reuse)
		call_rcu(&old_reuse->rcu, reuseport_free_rcu);
	return 0;
}

static int reuseport_resurrect(struct sock *sk,
			       struct sock_reuseport *old_reuse,
			       struct sock_reuseport *reuse, bool bind_inany)
{
	if (old_reuse == reuse) {
		/* Move sk from the closed section back to the active section. */
		__reuseport_detach_closed_sock(sk, old_reuse);
		__reuseport_add_sock(sk, old_reuse);
		return 0;
	}

	if (!reuse) {
		/* Do not carry an attached program across a new listen cycle. */
		reuse = __reuseport_alloc(INIT_SOCKS);
		if (!reuse)
			return -ENOMEM;

		reuse->bind_inany = bind_inany;
	} else if (reuse->num_socks + reuse->num_closed_socks ==
		   reuse->max_socks) {
		reuse = reuseport_grow(reuse);
		if (!reuse)
			return -ENOMEM;
	}

	__reuseport_detach_closed_sock(sk, old_reuse);
	__reuseport_add_sock(sk, reuse);
	rcu_assign_pointer(sk->sk_reuseport_cb, reuse);

	if (old_reuse->num_socks + old_reuse->num_closed_socks == 0)
		call_rcu(&old_reuse->rcu, reuseport_free_rcu);

	return 0;
}

void reuseport_detach_sock(struct sock *sk)
{
	struct sock_reuseport *reuse;

	spin_lock_bh(&reuseport_lock);
	reuse = rcu_dereference_protected(sk->sk_reuseport_cb,
					  lockdep_is_held(&reuseport_lock));

	/* reuseport_grow() may have detached a closed socket. */
	if (!reuse)
		goto out;

	/* At least one of the sk in this reuseport group is added to
	 * a bpf map.  Notify the bpf side.  The bpf map logic will
	 * remove the sk if it is indeed added to a bpf map.
	 */
	if (reuse->reuseport_id)
		bpf_sk_reuseport_detach(sk);

	rcu_assign_pointer(sk->sk_reuseport_cb, NULL);

	if (!__reuseport_detach_closed_sock(sk, reuse))
		__reuseport_detach_sock(sk, reuse);

	if (reuse->num_socks + reuse->num_closed_socks == 0)
		call_rcu(&reuse->rcu, reuseport_free_rcu);

out:
	spin_unlock_bh(&reuseport_lock);
}
EXPORT_SYMBOL(reuseport_detach_sock);

void reuseport_stop_listen_sock(struct sock *sk)
{
	if (sk->sk_protocol == IPPROTO_TCP) {
		struct sock_reuseport *reuse;
		struct bpf_prog *prog;

		spin_lock_bh(&reuseport_lock);
		reuse = rcu_dereference_protected(sk->sk_reuseport_cb,
						  lockdep_is_held(&reuseport_lock));
		prog = rcu_dereference_protected(reuse->prog,
						 lockdep_is_held(&reuseport_lock));

		if (READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_migrate_req) ||
		    (prog && prog->expected_attach_type ==
		     BPF_SK_REUSEPORT_SELECT_OR_MIGRATE)) {
			/* Keep the closed listener reachable by its requests. */
			if (reuse->reuseport_id)
				bpf_sk_reuseport_detach(sk);
			__reuseport_detach_sock(sk, reuse);
			__reuseport_add_closed_sock(sk, reuse);
			spin_unlock_bh(&reuseport_lock);
			return;
		}

		spin_unlock_bh(&reuseport_lock);
	}

	reuseport_detach_sock(sk);
}
EXPORT_SYMBOL(reuseport_stop_listen_sock);

static struct sock *run_bpf_filter(struct sock_reuseport *reuse, u16 socks,
				   struct bpf_prog *prog, struct sk_buff *skb,
				   int hdr_len)
{
	struct sk_buff *nskb = NULL;
	u32 index;

	if (skb_shared(skb)) {
		nskb = skb_clone(skb, GFP_ATOMIC);
		if (!nskb)
			return NULL;
		skb = nskb;
	}

	/* temporarily advance data past protocol header */
	if (!pskb_pull(skb, hdr_len)) {
		kfree_skb(nskb);
		return NULL;
	}
	index = bpf_prog_run_save_cb(prog, skb);
	__skb_push(skb, hdr_len);

	consume_skb(nskb);

	if (index >= socks)
		return NULL;

	return reuse->socks[index];
}

static struct sock *reuseport_select_sock_by_hash(struct sock_reuseport *reuse,
						  u32 hash, u16 num_socks)
{
	int i, j;

	i = j = reciprocal_scale(hash, num_socks);
	while (reuse->socks[i]->sk_state == TCP_ESTABLISHED) {
		i++;
		if (i >= num_socks)
			i = 0;
		if (i == j)
			return NULL;
	}

	return reuse->socks[i];
}

/**
 *  reuseport_select_sock - Select a socket from an SO_REUSEPORT group.
 *  @sk: First socket in the group.
 *  @hash: When no BPF filter is available, use this hash to select.
 *  @skb: skb to run through BPF filter.
 *  @hdr_len: BPF filter expects skb data pointer at payload data.  If
 *    the skb does not yet point at the payload, this parameter represents
 *    how far the pointer needs to advance to reach the payload.
 *  Returns a socket that should receive the packet (or NULL on error).
 */
struct sock *reuseport_select_sock(struct sock *sk,
				   u32 hash,
				   struct sk_buff *skb,
				   int hdr_len)
{
	struct sock_reuseport *reuse;
	struct bpf_prog *prog;
	struct sock *sk2 = NULL;
	u16 socks;

	rcu_read_lock();
	reuse = rcu_dereference(sk->sk_reuseport_cb);

	/* if memory allocation failed or add call is not yet complete */
	if (!reuse)
		goto out;

	prog = rcu_dereference(reuse->prog);
	socks = READ_ONCE(reuse->num_socks);
	if (likely(socks)) {
		/* paired with smp_wmb() in __reuseport_add_sock() */
		smp_rmb();

		if (!prog || !skb)
			goto select_by_hash;

		if (prog->type == BPF_PROG_TYPE_SK_REUSEPORT)
			sk2 = bpf_run_sk_reuseport(reuse, sk, prog, skb, NULL,
					  hash);
		else
			sk2 = run_bpf_filter(reuse, socks, prog, skb, hdr_len);

select_by_hash:
		if (!sk2)
			sk2 = reuseport_select_sock_by_hash(reuse, hash, socks);
	}

out:
	rcu_read_unlock();
	return sk2;
}
EXPORT_SYMBOL(reuseport_select_sock);

/**
 *  reuseport_migrate_sock - Select a socket from an SO_REUSEPORT group.
 *  @sk: close()ed or shutdown()ed socket in the group.
 *  @migrating_sk: ESTABLISHED/SYN_RECV full socket in the accept queue or
 *    NEW_SYN_RECV request socket during 3WHS.
 *  @skb: skb to run through BPF filter.
 *  Returns a socket (with sk_refcnt +1) that should accept the child socket
 *  (or NULL on error).
 */
struct sock *reuseport_migrate_sock(struct sock *sk,
				    struct sock *migrating_sk,
				    struct sk_buff *skb)
{
	struct sock_reuseport *reuse;
	struct sock *nsk = NULL;
	bool allocated = false;
	struct bpf_prog *prog;
	u16 socks;
	u32 hash;

	rcu_read_lock();
	reuse = rcu_dereference(sk->sk_reuseport_cb);
	if (!reuse)
		goto out;

	socks = READ_ONCE(reuse->num_socks);
	if (unlikely(!socks))
		goto failure;

	/* paired with smp_wmb() in __reuseport_add_sock() */
	smp_rmb();

	hash = migrating_sk->sk_hash;
	prog = rcu_dereference(reuse->prog);
	if (!prog || prog->expected_attach_type !=
	    BPF_SK_REUSEPORT_SELECT_OR_MIGRATE) {
		if (READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_migrate_req))
			goto select_by_hash;
		goto failure;
	}

	if (!skb) {
		skb = alloc_skb(0, GFP_ATOMIC);
		if (!skb)
			goto failure;
		allocated = true;
	}

	nsk = bpf_run_sk_reuseport(reuse, sk, prog, skb, migrating_sk, hash);

	if (allocated)
		kfree_skb(skb);

select_by_hash:
	if (!nsk)
		nsk = reuseport_select_sock_by_hash(reuse, hash, socks);

	if (IS_ERR_OR_NULL(nsk) ||
	    unlikely(!atomic_inc_not_zero(&nsk->sk_refcnt))) {
		nsk = NULL;
		goto failure;
	}

out:
	rcu_read_unlock();
	return nsk;

failure:
	__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPMIGRATEREQFAILURE);
	goto out;
}
EXPORT_SYMBOL(reuseport_migrate_sock);

int reuseport_attach_prog(struct sock *sk, struct bpf_prog *prog)
{
	struct sock_reuseport *reuse;
	struct bpf_prog *old_prog;

	if (sk_unhashed(sk)) {
		int err;

		if (!sk->sk_reuseport)
			return -EINVAL;

		err = reuseport_alloc(sk, false);
		if (err)
			return err;
	} else if (!rcu_access_pointer(sk->sk_reuseport_cb)) {
		return -EINVAL;
	}

	spin_lock_bh(&reuseport_lock);
	reuse = rcu_dereference_protected(sk->sk_reuseport_cb,
					  lockdep_is_held(&reuseport_lock));
	old_prog = rcu_dereference_protected(reuse->prog,
					     lockdep_is_held(&reuseport_lock));
	rcu_assign_pointer(reuse->prog, prog);
	spin_unlock_bh(&reuseport_lock);

	sk_reuseport_prog_free(old_prog);
	return 0;
}
EXPORT_SYMBOL(reuseport_attach_prog);
