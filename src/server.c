#include "common.h"
#include "kgenl.h"

#define VIP_EXPIRE 5000

static struct xlate_table *xlate_table = NULL;

static char *local_ip = NULL;
module_param(local_ip, charp, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(local_ip, "local IP for receiving packets from client");
static __be32 _local_ip = 0;

static unsigned short local_port = 0;
module_param(local_port, ushort, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(local_port, "UDP port used and reserved");
static __be16 _local_port = 0;

static char *vip_start = NULL;
module_param(vip_start, charp, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(vip_start, "virtual and unreachable client IP range from");
static __u32 _vip_start = 0;

static unsigned int vip_number = 0;
module_param(vip_number, uint, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(vip_number, "virtual and unreachable client IP total number");
static __u32 _vip_end = 0;


static inline __be32 get_local_ip(void)
{
	return _local_ip;
}

static inline bool is_local_ip(__be32 ip)
{
	return ip == _local_ip;
}

static inline __be16 get_local_port(void)
{
	return _local_port;
}

static inline bool is_local_port(__be16 port)
{
	return port == _local_port;
}

static inline __u32 get_vip_start(void)
{
	return _vip_start;
}

static inline unsigned int get_vip_number(void)
{
	return vip_number;
}

static inline bool is_in_vip_range(__u32 ip)
{
	return ip >= _vip_start && ip < _vip_end;
}

static inline unsigned long get_password(__be16 user)
{
	return 0;
}

static int params_init(void)
{
	if (local_ip != NULL)
		_local_ip = in_aton(local_ip);
	if (_local_ip == 0) {
		LOG_ERROR("local_ip param error");
		return -EINVAL;
	}

	if (local_port != 0)
		_local_port = htons(local_port);
	if (_local_port == 0) {
		LOG_ERROR("local_port param error");
		return -EINVAL;
	}

	if (vip_start != NULL)
		_vip_start = ntohl(in_aton(vip_start));
	if (_vip_start == 0) {
		LOG_ERROR("vip_start param error");
		return -EINVAL;
	}

	if (!vip_number) {
		LOG_ERROR("vip_number param error");
		return -EINVAL;
	}
	_vip_end = _vip_start + vip_number;

	return 0;
}

static void params_uninit(void)
{
}

static int custom_init(void)
{
	int err;

	err = params_init();
	if (err) {
		LOG_ERROR("failed to init input params: %d", err);
		goto params_init_err;
	}

	route_table = route_table_init();
	if (!route_table) {
		err = -ENOMEM;
		LOG_ERROR("failed to init route table");
		goto route_table_init_err;
	}

	xlate_table = xlate_table_init(get_vip_start(), get_vip_number(),
			VIP_EXPIRE);
	if (!xlate_table) {
		err = -ENOMEM;
		LOG_ERROR("failed to init xlate table");
		goto xlate_table_init_err;
	}

	return 0;

xlate_table_init_err:
	route_table_uninit(route_table);

route_table_init_err:
	params_uninit();

params_init_err:
	return err;
}

static void custom_uninit(void)
{
	xlate_table_uninit(xlate_table);
	route_table_uninit(route_table);
	params_uninit();
}

static bool need_server_decap(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct udphdr *udph;
	struct iprhdr *iprh;

	iph = ip_hdr(skb);
	if (!is_local_ip(iph->daddr))
		return false;
	if (iph->protocol != IPPROTO_UDP)
		return false;

	if (!pskb_may_pull_iprhdr(skb))
		return false;

	udph = udp_hdr(skb);
	if (!is_local_port(udph->dest))
		return false;

	iprh = ipr_hdr(skb);
	if (!is_ipr_cs(iprh))
		return false;

	LOG_DEBUG("%pI4:%u:%u -> %pI4: yes",
			&ip_hdr(skb)->saddr, ntohs(udph->source),
			ntohs(iprh->user), &ip_hdr(skb)->daddr);
	return true;
}

static int do_server_decap(struct sk_buff *skb)
{
	int err;
	int nhl;
	__be32 sip;
	__be32 dip;
	__be16 sport;
	__be32 rip;
	__be16 user;
	__be32 vip;
	struct iphdr *iph, *niph;
	struct udphdr *udph;
	struct iprhdr *iprh;
	struct tcphdr *tcph;
	struct dccp_hdr *dccph;
	__u16 udplitecov;
	__wsum csum;

#ifdef DEBUG
	volatile long begin = jiffies;
#endif

	nhl = skb_network_header_len(skb);

	iprh = ipr_hdr(skb);
	user = iprh->user;

	__skb_pull(skb, nhl + CAPL);
	demasq_data(skb, get_password(user));
	__skb_push(skb, nhl + CAPL);

	iph = ip_hdr(skb);
	udph = udp_hdr(skb);
	iprh = ipr_hdr(skb);
	sip = iph->saddr;
	dip = iph->daddr;
	sport = udph->source;
	rip = iprh->ip;
	LOG_DEBUG("%pI4:%u:%u -> %pI4: decap",
			&sip, ntohs(sport), ntohs(user), &dip);

	err = xlate_table_lookup_vip(xlate_table, sip, sport, user, &vip);
	if (err) {
		LOG_ERROR("%pI4:%u:%u -> %pI4: failed to find xlate vip: %d",
				&sip, ntohs(sport), ntohs(user), &dip, err);
		return err;
	}
	LOG_DEBUG("%pI4:%u:%u -> %pI4: found xlate vip %pI4",
			&sip, ntohs(sport), ntohs(user), &dip, &vip);

	iph->protocol = iprh->protocol;
	iph->saddr = vip;
	iph->daddr = rip;
	iph->tot_len = htons(ntohs(iph->tot_len) - CAPL);
	ip_send_check(iph);

	niph = (struct iphdr *)__skb_pull(skb, CAPL);
	memmove(niph, iph, nhl);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, nhl);

	switch (niph->protocol) {
		case IPPROTO_UDP:
			if (!pskb_may_pull(skb, nhl + sizeof(struct udphdr))) {
				LOG_ERROR("%pI4:%u -> %pI4: UDP too short",
						&sip, ntohs(sport), &dip);
				return -ETOOSMALL;
			}
			udph = udp_hdr(skb);
			/*
			LOG_DEBUG("XXZ 0x%04x", udph->check);
			LOG_DEBUG("XXY %pI4 %pI4 %u", &vip, &rip, udph->len);
			LOG_DEBUG("XXY %pI4 %pI4 %u", &vip, &rip, ntohs(udph->len));
			LOG_DEBUG("XXX %u %u", skb->csum_start, skb->csum_offset);
			*/
			udph->check = ~csum_tcpudp_magic(vip, rip, ntohs(udph->len),
					IPPROTO_UDP, 0);
			skb->ip_summed = CHECKSUM_PARTIAL;
			skb->csum_start = skb_transport_header(skb) - skb->head;
			skb->csum_offset = offsetof(struct udphdr, check);
			//LOG_DEBUG("XXY 0x%04x", udph->check);
			//LOG_DEBUG("XXX %u %u", skb->csum_start, skb->csum_offset);
			break;
		case IPPROTO_UDPLITE:
			if (!pskb_may_pull(skb, nhl + sizeof(struct udphdr))) {
				LOG_ERROR("%pI4:%u -> %pI4: UDPLITE too short",
						&sip, ntohs(sport), &dip);
				return -ETOOSMALL;
			}
			udph = udp_hdr(skb);
			udplitecov = ntohs(udph->len);
			if (!udplitecov)
				udplitecov = skb->len -
					skb_transport_offset(skb);
			else if (udplitecov > skb->len -
					skb_transport_offset(skb)) {
				LOG_ERROR("%pI4 -> %pI4: UDPLITE coverage error",
						&vip, &rip);
				return -EFAULT;
			}
			csum = skb_checksum(skb, skb_transport_offset(skb),
					udplitecov, 0);
			udph->check = csum_tcpudp_magic(vip, rip, udph->len,
					IPPROTO_UDP, csum);
			if (!udph->check)
				udph->check = CSUM_MANGLED_0;
			skb->ip_summed = CHECKSUM_NONE;
			break;
		case IPPROTO_TCP:
			if (!pskb_may_pull(skb, nhl + sizeof(struct tcphdr))) {
				LOG_ERROR("%pI4:%u -> %pI4: TCP too short",
						&sip, ntohs(sport), &dip);
				return -ETOOSMALL;
			}
			tcph = tcp_hdr(skb);
			tcph->check = ~csum_tcpudp_magic(vip, rip, skb->len -
					skb_transport_offset(skb), IPPROTO_TCP,
					0);
			skb->ip_summed = CHECKSUM_PARTIAL;
			skb->csum_start = skb_transport_header(skb) - skb->head;
			skb->csum_offset = offsetof(struct tcphdr, check);
			break;
		case IPPROTO_DCCP:
			if (!pskb_may_pull(skb, nhl + sizeof(struct dccp_hdr))) {
				LOG_ERROR("%pI4:%u -> %pI4: DCCP too short",
						&sip, ntohs(sport), &dip);
				return -ETOOSMALL;
			}
			dccph = dccp_hdr(skb);
			csum_replace4(&dccph->dccph_checksum, 0, vip);
			skb->ip_summed = CHECKSUM_NONE;
			break;
	}

	LOG_DEBUG("%pI4:%u:%u -> %pI4: go to server: %pI4 -> %pI4",
			&sip, ntohs(sport), ntohs(user), &dip, &vip, &rip);
#ifdef DEBUG
	LOG_DEBUG("%pI4:%u:%u -> %pI4: cost %ld",
			&sip, ntohs(sport), ntohs(user), &dip, jiffies - begin);
#endif
	return 0;
}

static bool need_server_encap(struct sk_buff *skb)
{
	struct iphdr *iph;

	iph = ip_hdr(skb);
	if (!is_in_vip_range(ntohl(iph->daddr)))
		return false;

	LOG_DEBUG("%pI4 <- %pI4: yes", &iph->daddr, &iph->saddr);
	return true;
}

static int do_server_encap(struct sk_buff *skb)
{
	int err;
	int nhl;
	__be32 sip;
	__be32 dip;
	__u16 nlen;
	struct iphdr *iph, *niph;
	struct udphdr *udph;
	struct iprhdr *iprh;
	__be32 xip;
	__be16 xport;
	__be16 xuser;
	__be32 lip;

#ifdef DEBUG
	volatile long begin = jiffies;
#endif

	lip = get_local_ip();
	nhl = skb_network_header_len(skb);

	iph = ip_hdr(skb);
	sip = iph->saddr;
	dip = iph->daddr;
	nlen = ntohs(iph->tot_len) + CAPL;
	LOG_DEBUG("%pI4 <- %pI4: encap", &dip, &sip);
	if (unlikely(nlen < CAPL)) {
		/* packet length overflow after encap */
		LOG_ERROR("%pI4 <- %pI4: packet too large", &dip, &sip);
		return -EMSGSIZE;
	}

	err = xlate_table_find_entry_by_vip(xlate_table, dip, &xip, &xport,
			&xuser);
	if (err) {
		LOG_ERROR("%pI4 <- %pI4: failed to find xlate entry by vip: %d",
				&dip, &sip, err);
		return err;
	}
	LOG_DEBUG("%pI4 <- %pI4: found xlate ip %pI4 port %u user %u",
			&dip, &sip, &xip, ntohs(xport), ntohs(xuser));

	err = skb_cow(skb, CAPL);
	if (err) {
		LOG_ERROR("%pI4 <- %pI4: failed to do skb_cow: %d",
				&dip, &sip, err);
		return err;
	}

	iph = ip_hdr(skb);
	niph = (struct iphdr *)__skb_push(skb, CAPL);
	memmove(niph, iph, nhl);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, nhl);

	iprh = ipr_hdr(skb);
	set_ipr_sc(iprh, niph->protocol, route_table_find(route_table, sip),
			sip);

	udph = udp_hdr(skb);
	udph->source = get_local_port();
	udph->dest = xport;
	udph->len = htons(nlen - nhl);
	udph->check = 0;
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	niph->protocol = IPPROTO_UDP;
	niph->saddr = lip;
	niph->daddr = xip;
	niph->tot_len = htons(nlen);
	ip_send_check(niph);

	__skb_pull(skb, nhl + CAPL);
	masq_data(skb, get_password(xuser));
	__skb_push(skb, nhl + CAPL);

	LOG_DEBUG("%pI4 <- %pI4: go to client: %pI4:%u <- %pI4",
			&dip, &sip, &xip, ntohs(xport), &lip);
#ifdef DEBUG
	LOG_DEBUG("%pI4 <- %pI4: cost %ld", &dip, &sip, jiffies - begin);
#endif
	return 0;
}

static unsigned int server_decap(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	int err;

	if (!need_server_decap(skb))
		return NF_ACCEPT;

	err = do_server_decap(skb);
	if (err) {
		LOG_ERROR("failed to do server decap, drop packet: %d", err);
		return NF_DROP;
	}

	return NF_ACCEPT;
}

static unsigned int server_encap(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	int err;

	if (!need_server_encap(skb))
		return NF_ACCEPT;

	err = do_server_encap(skb);
	if (err) {
		LOG_ERROR("failed to do server encap, drop packet: %d", err);
		return NF_DROP;
	}

	return NF_ACCEPT;
}

static const struct nf_hook_ops iproxy_nf_ops[] = {
	{
		.hook = server_decap,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK_DEFRAG + 1,
	},
	{
		.hook = server_encap,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST,
	},
};


#include "module.h"
