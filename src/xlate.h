#ifndef _XLATE_H_
#define _XLATE_H_

#include <linux/types.h>

struct xlate_table;

struct xlate_table *xlate_table_init(__u32 vip_start, unsigned int vip_number,
		unsigned int vip_expire);
void xlate_table_uninit(struct xlate_table *xt);

int xlate_table_lookup_vip(struct xlate_table *xt, __be32 ip, __be16 port,
		__be16 user, __be32 *vip);
int xlate_table_find_entry_by_vip(const struct xlate_table *xt, __be32 vip,
		__be32 *ip, __be16 *port, __be16 *user);

#endif
