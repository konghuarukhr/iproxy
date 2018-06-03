#ifndef _KGENL_H_
#define _KGENL_H_

#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/genetlink.h>
#include "route.h"
#include "ugenl.h"

static struct route_table *route_table;
static struct genl_family iproxy_genl_family;

static int reply_ok(struct genl_info *info)
{
	int err;
	struct sk_buff *skb_out;
	void *msg_head;

	skb_out = genlmsg_new(nla_total_size(0), GFP_KERNEL);
	if (!skb_out)
		return -ENOMEM;

	msg_head = genlmsg_put(skb_out, 0, info->snd_seq,
			&iproxy_genl_family, 0, IPR_CMD_REPLY);
	if (!msg_head) {
		err = -EMSGSIZE;
		goto genlmsg_put_err;
	}

	err = nla_put_flag(skb_out, IPR_ATTR_OK);
	if (err)
		goto nla_put_mask_err;

	genlmsg_end(skb_out, msg_head);

	genlmsg_reply(skb_out, info);

	return 0;

nla_put_mask_err:
genlmsg_put_err:
	nlmsg_free(skb_out);
	return err;
}

static int add_route(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *ip_attr = info->attrs[IPR_ATTR_IP];
	struct nlattr *mask_attr = info->attrs[IPR_ATTR_MASK];
	if (ip_attr && mask_attr) {
		__be32 ip = nla_get_in_addr(ip_attr);
		__u8 mask = nla_get_u8(mask_attr);
		int err = route_table_add(route_table, ip, mask);
		return err ? err : reply_ok(info);
	}
	return -EINVAL;
}

static int delete_route(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *ip_attr = info->attrs[IPR_ATTR_IP];
	struct nlattr *mask_attr = info->attrs[IPR_ATTR_MASK];
	if (ip_attr && mask_attr) {
		__be32 ip = nla_get_in_addr(ip_attr);
		__u8 mask = nla_get_u8(mask_attr);
		int err = route_table_delete(route_table, ip, mask);
		return err ? err : reply_ok(info);
	}
	return -EINVAL;
}

static int delete_route_match(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *ip_attr = info->attrs[IPR_ATTR_IP];
	if (ip_attr) {
		__be32 ip = nla_get_in_addr(ip_attr);
		int err = route_table_delete_match(route_table, ip);
		return err ? err : reply_ok(info);
	}
	return -EINVAL;
}

static int find_route(struct sk_buff *skb, struct genl_info *info)
{
	int err;
	struct nlattr *ip_attr;
	__be32 ip;
	__u8 mask;
	struct sk_buff *skb_out;
	void *msg_head;

	ip_attr = info->attrs[IPR_ATTR_IP];
	if (!ip_attr)
		return -EINVAL;

	ip = nla_get_in_addr(ip_attr);
	mask = route_table_find(route_table, ip);

	skb_out = genlmsg_new(nla_total_size(sizeof(__u8)),
			GFP_KERNEL);
	if (!skb_out)
		return -ENOMEM;

	msg_head = genlmsg_put(skb_out, 0, info->snd_seq,
			&iproxy_genl_family, 0, IPR_CMD_REPLY);
	if (!msg_head) {
		err = -EMSGSIZE;
		goto genlmsg_put_err;
	}

	err = nla_put_u8(skb_out, IPR_ATTR_MASK, mask);
	if (err)
		goto nla_put_mask_err;

	genlmsg_end(skb_out, msg_head);

	genlmsg_reply(skb_out, info);

	return 0;

nla_put_mask_err:
genlmsg_put_err:
	nlmsg_free(skb_out);
	return err;
}

static int clear_route(struct sk_buff *skb, struct genl_info *info)
{
	int err = route_table_clear(route_table);
	return err ? err : reply_ok(info);
}

static int cb_show_func(void *data, __be32 network, __u8 mask)
{
	struct sk_buff *skb = (struct sk_buff *)data;

	if (skb_tailroom(skb) < nla_total_size(sizeof(__be32)) +
		nla_total_size(sizeof(__u8)))
		return -EMSGSIZE;

	nla_put_in_addr(skb, IPR_ATTR_IP, network);
	nla_put_u8(skb, IPR_ATTR_MASK, mask);

	return 0;
}

static int show_route(struct sk_buff *skb, struct netlink_callback *cb)
{
	void *msg_head;

	LOG_DEBUG("in: offset %ld", cb->args[0]);

	msg_head = genlmsg_put(skb, 0, cb->nlh->nlmsg_seq,
			&iproxy_genl_family, NLM_F_MULTI, IPR_CMD_REPLY);
	if (!msg_head) {
		LOG_DEBUG("out with err");
		return -EMSGSIZE;
	}

	route_table_cb(route_table, cb_show_func, skb, &cb->args[0]);

	genlmsg_end(skb, msg_head);

	LOG_DEBUG("out: offset %ld len %d", cb->args[0], skb->len -
			(int)GENL_HDRLEN - NLMSG_HDRLEN);
	return skb->len - GENL_HDRLEN - NLMSG_HDRLEN;
}

static const struct nla_policy iproxy_genl_policy[IPR_ATTR_MAX + 1] = {
	[IPR_ATTR_OK] = {.type = NLA_FLAG},
	[IPR_ATTR_IP] = {.type = NLA_U32},
	[IPR_ATTR_MASK] = {.type = NLA_U8},
};

#ifdef DEBUG
static int pre_doit(const struct genl_ops *ops, struct sk_buff *skb,
		struct genl_info *info)
{
	LOG_DEBUG("GENL CMD %u begin", ops->cmd);
	return 0;
}

static void post_doit(const struct genl_ops *ops, struct sk_buff *skb,
		struct genl_info *info)
{
	LOG_DEBUG("GENL CMD %u end", ops->cmd);
}

/*
static int start(struct netlink_callback *cb)
{
	LOG_DEBUG("GENL DUMP begin");
	return 0;
}
*/

static int done(struct netlink_callback *cb)
{
	LOG_DEBUG("GENL DUMP end");
	return 0;
}
#endif

static const struct genl_ops iproxy_genl_ops[] = {
	{
		.cmd = IPR_CMD_ADD_ROUTE,
		.doit = add_route,
		.policy = iproxy_genl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = IPR_CMD_DELETE_ROUTE,
		.doit = delete_route,
		.policy = iproxy_genl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = IPR_CMD_DELETE_MATCH_ROUTE,
		.doit = delete_route_match,
		.policy = iproxy_genl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = IPR_CMD_FIND_ROUTE,
		.doit = find_route,
		.policy = iproxy_genl_policy,
	},
	{
		.cmd = IPR_CMD_CLEAR_ROUTE,
		.doit = clear_route,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = IPR_CMD_SHOW_ROUTE,
		.dumpit = show_route,
#ifdef DEBUG
		/*.start = start,*/
		.done = done,
#endif
	},
};

static struct genl_family iproxy_genl_family = {
	.name = IPR_GENL_NAME,
	.version = 0x02,
	.maxattr = IPR_ATTR_MAX,
	.netnsok = true,
	.ops = iproxy_genl_ops,
	.n_ops = ARRAY_SIZE(iproxy_genl_ops),
	.module = THIS_MODULE,
#ifdef DEBUG
	.pre_doit = pre_doit,
	.post_doit = post_doit,
#endif
};

#endif
