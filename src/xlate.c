#include "xlate.h"
#include <linux/hashtable.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include "common.h"

#define XLATE_BITS 10

struct xlate_table {
	__u32 vip_start;
	unsigned int vip_number;
	unsigned long *vip_bitmap;
	unsigned int vip_unused_idx;
	unsigned int vip_expire;
	spinlock_t vip_lock;

	DECLARE_HASHTABLE(ipport_head, XLATE_BITS);
	DECLARE_HASHTABLE(vip_head, XLATE_BITS);
	spinlock_t lock;
};

struct xlate_entry {
	struct xlate_table *xt;
	__be32 ip;
	__be16 port;
	__be16 user;
	__be32 vip;
	struct hlist_node ipport_node;
	struct hlist_node vip_node;
	struct timer_list timer;
	struct rcu_head rcu;
};

__be32 apply_vip(struct xlate_table *xt)
{
	__u32 vip;

	spin_lock_bh(&xt->vip_lock);
	xt->vip_unused_idx = find_next_zero_bit(xt->vip_bitmap, xt->vip_number,
			xt->vip_unused_idx);
	if (xt->vip_unused_idx == xt->vip_number) {
		spin_unlock_bh(&xt->vip_lock);
		return 0;
	}
	set_bit(xt->vip_unused_idx, xt->vip_bitmap);
	vip = xt->vip_start + xt->vip_unused_idx;
	spin_unlock_bh(&xt->vip_lock);

	return htonl(vip);
}

void release_vip(struct xlate_table *xt, __be32 vip)
{
	__u32 idx;

	spin_lock_bh(&xt->vip_lock);
	idx = ntohl(vip) - xt->vip_start;
	clear_bit(idx, xt->vip_bitmap);
	if (idx < xt->vip_unused_idx)
		xt->vip_unused_idx = idx;
	spin_unlock_bh(&xt->vip_lock);
}

struct xlate_table *xlate_table_init(__u32 vip_start, unsigned int vip_number,
		unsigned int vip_expire)
{
	struct xlate_table *xt = kzalloc(sizeof *xt, GFP_KERNEL);
	if (!xt) {
		LOG_ERROR("failed to alloc xlate table");
		return NULL;
	}

	xt->vip_start = vip_start;
	xt->vip_number = vip_number;
	xt->vip_bitmap = kzalloc(BITS_TO_LONGS(vip_number) * sizeof(long),
			GFP_KERNEL);
	if (!xt->vip_bitmap) {
		LOG_ERROR("failed to alloc vip bitmap: %d", -ENOMEM);
		kfree(xt);
		return NULL;
	}

	xt->vip_unused_idx = 0;
	xt->vip_expire = vip_expire;
	spin_lock_init(&xt->vip_lock);
	hash_init(xt->ipport_head);
	hash_init(xt->vip_head);
	spin_lock_init(&xt->lock);

	return xt;
}

static void xlate_entry_release(struct xlate_entry *xe)
{
	LOG_INFO("xlate_entry_release: %p", xe);
	del_timer(&xe->timer);
	hash_del_rcu(&xe->ipport_node);
	hash_del_rcu(&xe->vip_node);
	release_vip(xe->xt, xe->vip);
	kfree_rcu(xe, rcu);
}

void xlate_table_uninit(struct xlate_table *xt)
{
	int bkt;
	struct hlist_node *tmp;
	struct xlate_entry *xe;

	spin_lock_bh(&xt->lock);
	hash_for_each_safe(xt->ipport_head, bkt, tmp, xe, ipport_node) {
		xlate_entry_release(xe);
	}
	spin_unlock_bh(&xt->lock);

	kfree(xt->vip_bitmap);
	kfree(xt);
}

int xlate_table_find_entry_by_vip(const struct xlate_table *xt, __be32 vip,
		__be32 *ip, __be16 *port, __be16 *user)
{
	struct xlate_entry *xe;

	rcu_read_lock();
	hash_for_each_possible_rcu(xt->vip_head, xe, vip_node, vip)
		if (xe->vip == vip) {
			if (ip)
				*ip = xe->ip;
			if (port)
				*port = xe->port;
			if (user)
				*user = xe->user;
			rcu_read_unlock();
			return 0;
		}
	rcu_read_unlock();

	return -ENOENT;
}

static void xlate_entry_timer_cb(unsigned long data)
{
	struct xlate_entry *xe = (struct xlate_entry *)data;
	LOG_INFO("xlate_entry_timer_cb 1: %lx", data);
	LOG_INFO("xlate_entry_timer_cb 2: %p", xe);
	spin_lock(&xe->xt->lock);
	xlate_entry_release(xe);
	spin_unlock(&xe->xt->lock);
}

int xlate_table_lookup_vip(struct xlate_table *xt, __be32 ip, __be16 port,
		__be16 user, __be32 *xvip)
{
	struct xlate_entry *xe;
	__be32 vip;

	__be64 key = ((__be64)port << 32) + ip;

	rcu_read_lock();
	hash_for_each_possible_rcu(xt->ipport_head, xe, ipport_node, key)
		if (xe->ip == ip && xe->port == port) {
			if (xvip)
				*xvip = xe->vip;
			rcu_read_unlock();
			return 0;
		}
	rcu_read_unlock();

	LOG_DEBUG("no ip %pI4 port %u entry, creating...", &ip, port);
	xe = kzalloc(sizeof *xe, GFP_ATOMIC);
	if (xe == NULL) {
		LOG_ERROR("failed to alloc xlate entry memory");
		return -ENOMEM;
	}
	xe->xt = xt;
	xe->ip = ip;
	xe->port = port;
	xe->user = user;
	vip = apply_vip(xt);
	if (vip == 0) {
		LOG_ERROR("failed to apply vip");
		kfree(xe);
		return -ENOENT;
	}
	xe->vip = vip;
	if (xvip)
		*xvip = vip;
	setup_timer(&xe->timer, xlate_entry_timer_cb, (unsigned long)xe);

	spin_lock_bh(&xt->lock);
	hash_add_rcu(xt->ipport_head, &xe->ipport_node, key);
	hash_add_rcu(xt->vip_head, &xe->vip_node, vip);
	if (xt->vip_expire)
		mod_timer(&xe->timer, jiffies + xt->vip_expire * HZ);
	spin_unlock_bh(&xt->lock);

	return 0;
}
