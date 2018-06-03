#ifndef _IPR_H_
#define _IPR_H_

#include <linux/skbuff.h>
#include <linux/udp.h>

/**
 * User can change the sequence of these fields to fool the dector.
 * But make sure that sizeof(struct iprhdr) == 8.
 * If you change this size, you should change MSS in set-iptables.sh.
 */
struct iprhdr {
	__u8 type;
	__u8 protocol;
	union {
		__be16 user;
		__u8 mask;
	};
	__be32 ip;
};

#define CAPL (sizeof(struct udphdr) + sizeof(struct iprhdr))

enum {
	IPR_C_S, /* Client -> Server */
	IPR_S_C, /* Server -> Client */
};

static inline bool is_ipr_cs(const struct iprhdr *iprh)
{
	return iprh->type == IPR_C_S;
}

static inline void set_ipr_cs(struct iprhdr *iprh, __u8 protocol,
		__be16 user, __be32 ip)
{
	iprh->type = IPR_C_S;
	iprh->protocol = protocol;
	iprh->user = user;
	iprh->ip = ip;
}

static inline bool is_ipr_sc(const struct iprhdr *iprh)
{
	return iprh->type == IPR_S_C;
}

static inline void set_ipr_sc(struct iprhdr *iprh, __u8 protocol,
		__u8 mask, __be32 ip)
{
	iprh->type = IPR_S_C;
	iprh->protocol = protocol;
	iprh->mask = mask;
	iprh->ip = ip;
}


static inline int pskb_may_pull_iprhdr(struct sk_buff *skb)
{
	return pskb_may_pull(skb, skb_network_header_len(skb) + CAPL);
}

static inline int pskb_may_pull_iprhdr_ext(struct sk_buff *skb, int ext)
{
	return pskb_may_pull(skb, skb_network_header_len(skb) + CAPL + ext);
}

static inline struct iprhdr *ipr_hdr(const struct sk_buff *skb)
{
	return (struct iprhdr *)(skb_transport_header(skb) +
			sizeof(struct udphdr));
}

/**
 * https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
 */
static inline bool is_private_ip(__be32 ip)
{
	__be32 network;

	/* 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8 */
	network = ip & __constant_htonl(0xFF000000U);
	switch (network) {
		case __constant_htonl(0x00000000U):
			return true;
		case __constant_htonl(0x0A000000U):
			return true;
		case __constant_htonl(0x7F000000U):
			return true;
	}

	/* 100.64.0.0/10 */
	network = ip & __constant_htonl(0xFFC00000U);
	if (network == __constant_htonl(0x64400000U))
		return true;

	/* 172.16.0.0/12 */
	network = ip & __constant_htonl(0xFFF00000U);
	if (network == __constant_htonl(0xAC100000U))
		return true;

	/* 192.168.0.0/16 */
	network = ip & __constant_htonl(0xFFFF0000U);
	if (network == __constant_htonl(0xC0A80000U))
		return true;

	return false;
}

#endif
