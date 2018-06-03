#ifndef _MASQ_H_
#define _MASQ_H_

#include <linux/skbuff.h>

__be32 masq_data(struct sk_buff *skb, unsigned int passwd);
__be32 demasq_data(struct sk_buff *skb, unsigned int passwd);

#endif
