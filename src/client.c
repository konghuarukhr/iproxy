#include "common.h"
#include "kgenl.h"

#define ROUTE_EXPIRE 3600

static char *server_ip = NULL;
module_param(server_ip, charp, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(server_ip, "server IP");
static __be32 _server_ip = 0;

static unsigned short server_port = 0;
module_param(server_port, ushort, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(server_port, "server UDP port");
static __be16 _server_port = 0;

static unsigned short local_port = 0;
module_param(local_port, ushort, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(local_port, "local UDP port (default server_port)");
static __be16 _local_port = 0;

static unsigned short user = 0;
module_param(user, ushort, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(user, "user (default 0)");
static __be16 _user = 0;

static unsigned long password = 0;
module_param(password, ulong, 0);
MODULE_PARM_DESC(password, "password (default 0)");

static bool route_learn = 0;
module_param(route_learn, bool, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(route_learn, "0: route learn from server; 1: route static (default 0)");

static bool disable = 0;
module_param(disable, bool, S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(disable, "0: enabled; 1: disabled (default 0)");


/**
 * TODO: supports multi proxies
 */
static inline __be32 get_server_ip(void)
{
	return _server_ip;
}

static inline bool is_server_ip(__be32 ip)
{
	return ip == _server_ip;
}

static inline __be16 get_server_port(void)
{
	return _server_port;
}

static inline bool is_server_port(__be16 port)
{
	return port == _server_port;
}

static inline __be16 get_local_port(void)
{
	return _local_port;
}

static inline bool is_local_port(__be16 port)
{
	return port == _local_port;
}

static inline __be16 my_get_user(void)
{
	return _user;
}

static inline unsigned long get_password(void)
{
	return password;
}

static inline bool is_route_learn(void)
{
	return route_learn == 0;
}


static int params_init(void)
{
	if (server_ip)
		_server_ip = in_aton(server_ip);
	if (!_server_ip) {
		LOG_ERROR("server_ip param error");
		return -EINVAL;
	}

	_server_port = htons(server_port);
	if (!_server_port) {
		LOG_ERROR("server_port param error");
		return -EINVAL;
	}

	_local_port = htons(local_port);
	if (!_local_port) {
		_local_port = _server_port;
	}

	_user = htons(user);

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
		LOG_ERROR("failed to init params: %d", err);
		goto params_init_err;
	}

	route_table = route_table_init();
	if (!route_table) {
		err = -ENOMEM;
		LOG_ERROR("failed to init route table: %d", err);
		goto route_table_init_err;
	}

	return 0;

route_table_init_err:
	params_uninit();

params_init_err:
	return err;
}

static void custom_uninit(void)
{
	route_table_uninit(route_table);
	params_uninit();
}


static bool need_client_encap(struct sk_buff *skb)
{
	struct iphdr *iph;
	__be32 dip;

	if (disable)
		return false;

	iph = ip_hdr(skb);
	dip = iph->daddr;

	/* Do we need this? */
	if (is_server_ip(dip))
		return false;

	if (is_private_ip(dip))
		return false;

	if (route_table_find(route_table, dip))
		return false;

	LOG_DEBUG("%pI4 -> %pI4: yes", &iph->saddr, &dip);
	return true;
}

static int do_client_encap(struct sk_buff *skb)
{
	int err;
	int nhl;
	__be32 sip;
	__be32 dip;
	__u16 nlen;
	struct iphdr *iph, *niph;
	struct udphdr *udph;
	struct iprhdr *iprh;
	__be32 pip;

#ifdef DEBUG
	volatile long begin = jiffies;
#endif

	pip = get_server_ip();
	nhl = skb_network_header_len(skb);

	iph = ip_hdr(skb);
	sip = iph->saddr;
	dip = iph->daddr;
	nlen = ntohs(iph->tot_len) + CAPL;
	LOG_DEBUG("%pI4 -> %pI4: encap", &sip, &dip);
	if (unlikely(nlen < CAPL)) {
		/* packet length overflow after encap */
		LOG_ERROR("%pI4 -> %pI4: packet too large", &sip, &dip);
		return -EMSGSIZE;
	}

	err = skb_cow(skb, CAPL);
	if (err) {
		LOG_ERROR("%pI4 -> %pI4: failed to do skb_cow: %d",
				&sip, &dip, err);
		return err;
	}

	iph = ip_hdr(skb);
	niph = (struct iphdr *)__skb_push(skb, CAPL);
	memmove(niph, iph, nhl);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, nhl);

	iprh = ipr_hdr(skb);
	set_ipr_cs(iprh, niph->protocol, my_get_user(), dip);

	udph = udp_hdr(skb);
	udph->source = get_local_port();
	udph->dest = get_server_port();
	udph->len = htons(nlen - nhl);
	udph->check = 0;
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	niph->protocol = IPPROTO_UDP;
	niph->daddr = pip;
	niph->tot_len = htons(nlen);
	ip_send_check(niph);

	__skb_pull(skb, nhl + CAPL);
	masq_data(skb, get_password());
	__skb_push(skb, nhl + CAPL);

	LOG_DEBUG("%pI4 -> %pI4: go to proxy: %pI4",
			&sip, &dip, &pip);
#ifdef DEBUG
	LOG_DEBUG("%pI4 -> %pI4: cost %ld",
			&sip, &dip, jiffies - begin);
#endif
	return 0;
}

static bool need_client_decap(struct sk_buff *skb) {
	struct iphdr *iph;
	struct udphdr *udph;
	struct iprhdr *iprh;

	iph = ip_hdr(skb);
	if (!is_server_ip(iph->saddr))
		return false;
	if (iph->protocol != IPPROTO_UDP)
		return false;

	if (!pskb_may_pull_iprhdr(skb))
		return false;

	udph = udp_hdr(skb);
	if (!is_server_port(udph->source))
		return false;
	if (!is_local_port(udph->dest))
		return false;

	iprh = ipr_hdr(skb);
	if (!is_ipr_sc(iprh))
		return false;

	LOG_DEBUG("%pI4 <- %pI4: yes", &ip_hdr(skb)->daddr,
			&ip_hdr(skb)->saddr);
	return true;
}

static unsigned int do_client_decap(struct sk_buff *skb)
{
	int err;
	int nhl;
	__be32 sip;
	__be32 dip;
	__be32 rip;
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

	__skb_pull(skb, nhl + CAPL);
	demasq_data(skb, get_password());
	__skb_push(skb, nhl + CAPL);

	iph = ip_hdr(skb);
	iprh = ipr_hdr(skb);
	sip = iph->saddr;
	dip = iph->daddr;
	rip = iprh->ip;
	LOG_DEBUG("%pI4 <- %pI4: decap", &dip, &sip);

	if (is_route_learn() && iprh->mask) {
		__u8 mask = iprh->mask;
		LOG_INFO("%pI4 <- %pI4: add route %pI4/%u",
				&dip, &sip, &rip, mask);
		err = route_table_add_expire(route_table, rip, mask,
				ROUTE_EXPIRE);
		if (err)
			LOG_WARN("%pI4 <- %pI4: failed to add route %pI4/%u",
					&dip, &sip, &rip, mask);
	}

	iph->protocol = iprh->protocol;
	iph->saddr = rip;
	iph->tot_len = htons(ntohs(iph->tot_len) - CAPL);
	ip_send_check(iph);

	niph = (struct iphdr *)__skb_pull(skb, CAPL);
	memmove(niph, iph, nhl);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, nhl);

	//skb->ip_summed = CHECKSUM_COMPLETE;
	switch (niph->protocol) {
		case IPPROTO_UDP:
			if (!pskb_may_pull(skb, nhl + sizeof(struct udphdr))) {
				LOG_ERROR("%pI4 <- %pI4: UDP too short",
						&dip, &sip);
				return -ETOOSMALL;
			}
			udph = udp_hdr(skb);
			/*
			LOG_DEBUG("XXZ 0x%04x", udph->check);
			LOG_DEBUG("XXY %pI4 %pI4 %u", &vip, &rip, udph->len);
			LOG_DEBUG("XXY %pI4 %pI4 %u", &vip, &rip, ntohs(udph->len));
			LOG_DEBUG("XXX %u %u", skb->csum_start, skb->csum_offset);
			*/
			udph->check = ~csum_tcpudp_magic(rip, dip, ntohs(udph->len),
					IPPROTO_UDP, 0);
			skb->ip_summed = CHECKSUM_PARTIAL;
			skb->csum_start = skb_transport_header(skb) - skb->head;
			skb->csum_offset = offsetof(struct udphdr, check);
			//LOG_DEBUG("XXY 0x%04x", udph->check);
			//LOG_DEBUG("XXX %u %u", skb->csum_start, skb->csum_offset);
			break;
		case IPPROTO_UDPLITE:
			if (!pskb_may_pull(skb, nhl + sizeof(struct udphdr))) {
				LOG_ERROR("%pI4 <- %pI4: UDPLITE too short",
						&dip, &sip);
				return -ETOOSMALL;
			}
			udph = udp_hdr(skb);
			udplitecov = ntohs(udph->len);
			if (!udplitecov)
				udplitecov = skb->len -
					skb_transport_offset(skb);
			else if (udplitecov > skb->len -
					skb_transport_offset(skb)) {
				LOG_ERROR("%pI4 <- %pI4: UDPLITE coverage error",
						&dip, &sip);
				return -EFAULT;
			}
			csum = skb_checksum(skb, skb_transport_offset(skb),
					udplitecov, 0);
			udph->check = csum_tcpudp_magic(rip, dip, udph->len,
					IPPROTO_UDP, csum);
			if (!udph->check)
				udph->check = CSUM_MANGLED_0;
			skb->ip_summed = CHECKSUM_NONE;
			break;
		case IPPROTO_TCP:
			if (!pskb_may_pull(skb, nhl + sizeof(struct tcphdr))) {
				LOG_ERROR("%pI4 <- %pI4: TCP too short",
						&dip, &sip);
				return -ETOOSMALL;
			}
			tcph = tcp_hdr(skb);
			tcph->check = ~csum_tcpudp_magic(rip, dip, skb->len -
					skb_transport_offset(skb), IPPROTO_TCP,
					0);
			skb->ip_summed = CHECKSUM_PARTIAL;
			skb->csum_start = skb_transport_header(skb) - skb->head;
			skb->csum_offset = offsetof(struct tcphdr, check);
			break;
		case IPPROTO_DCCP:
			if (!pskb_may_pull(skb, nhl + sizeof(struct dccp_hdr))) {
				LOG_ERROR("%pI4 <- %pI4: DCCP too short",
						&dip, &sip);
				return -ETOOSMALL;
			}
			dccph = dccp_hdr(skb);
			csum_replace4(&dccph->dccph_checksum, 0, rip);
			skb->ip_summed = CHECKSUM_NONE;
			break;
	}

	LOG_DEBUG("%pI4 <- %pI4: from remote: %pI4",
			&dip, &sip, &rip);
#ifdef DEBUG
	LOG_DEBUG("%pI4 <- %pI4: cost %ld",
			&dip, &sip, jiffies - begin);
#endif
	return 0;
}

static unsigned int client_encap(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	int err;

	if (!need_client_encap(skb))
		return NF_ACCEPT;

	err = do_client_encap(skb);
	if (err) {
		LOG_ERROR("failed to do client encap, drop packet: %d", err);
		return NF_DROP;
	}

	return NF_ACCEPT;
}

static unsigned int client_decap(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	int err;

	if (!need_client_decap(skb))
		return NF_ACCEPT;

	err = do_client_decap(skb);
	if (err) {
		LOG_ERROR("failed to do client decap, drop packet: %d", err);
		return NF_DROP;
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops iproxy_nf_ops[] = {
	{
		.hook = client_encap,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST,
	},
	{
		.hook = client_decap,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK_DEFRAG + 1,
	},
};


#include "module.h"
