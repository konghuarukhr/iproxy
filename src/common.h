#ifndef _COMMON_H_
#define _COMMON_H_

#define LICENSE "GPL"
#define VERSION "1.0"
#define AUTHOR "Dustin Zheng <konghuarukhr@gmail.com>"

#ifdef _IPR_CLIENT
#define IPR_GENL_NAME "IPROXY_CLIENT"
#define ALIAS "iproxy_client"
#define DESCRIPTION "An IP proxy client"
#else /* SERVER */
#define IPR_GENL_NAME "IPROXY_SERVER"
#define ALIAS "iproxy_server"
#define DESCRIPTION "An IP proxy server"
#endif

//#define LINE(msg) (msg "\n")
#define LINE(msg) msg "\n"
#define LOG_DEBUG(msg, ...) pr_debug(ALIAS ": " "%s: " LINE(msg), __func__, ##__VA_ARGS__)
#define LOG_INFO(msg, ...) pr_info(ALIAS ": " "%s: " LINE(msg), __func__, ##__VA_ARGS__)
//#define LOG_INFO pr_info
#define LOG_WARN(msg, ...) pr_warn(ALIAS ": " "%s: " LINE(msg), __func__, ##__VA_ARGS__)
#define LOG_ERROR(msg, ...) pr_err(ALIAS ": " "%s: " LINE(msg), __func__, ##__VA_ARGS__)
//#define LOG_ERROR(msg, ...) pr_err(msg, ##__VA_ARGS__)
//#define LOG_ERROR pr_err

#define DNS_PORT __constant_htons(53)

#include "masq.h"
#include "xlate.h"
#include "ipr.h"
#include <net/net_namespace.h>
#include <net/sock.h>
//#include <linux/kernel.h>
#include <linux/bitops.h>
#include <linux/moduleparam.h>
#include <linux/module.h>
#include <linux/inet.h>
#include <linux/printk.h>
#include <linux/hashtable.h>
#include <linux/dccp.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/netfilter_ipv4.h>
#include <net/ip.h>
#include <net/genetlink.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#include <generated/uapi/linux/version.h>

#include "route.h"
#include "ugenl.h"


#endif
