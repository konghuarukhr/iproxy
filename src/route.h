#ifndef _ROUTE_H_
#define _ROUTE_H_

#include <linux/types.h>

struct route_table;

struct route_table *route_table_init(void);
void route_table_uninit(struct route_table *rt);

int route_table_add(struct route_table *rt, __be32 network, __u8 mask);
int route_table_add_expire(struct route_table *rt, __be32 network, __u8 mask,
		int secs);
int route_table_delete(struct route_table *rt, __be32 network, __u8 mask);
int route_table_delete_match(struct route_table *rt, __be32 network);
__u8 route_table_find(struct route_table *rt, __be32 ip);
int route_table_clear(struct route_table *rt);
int route_table_cb(struct route_table *rt, int (*cb_func)(void *, __be32, __u8),
		void *data, long *last);

#endif
