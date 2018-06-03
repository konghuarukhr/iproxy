#include "masq.h"
#include <generated/uapi/linux/version.h>
#include <linux/highmem.h>
#include <linux/skbuff.h>
#include "user-defined-masq.h"

static __be32 process_data(struct sk_buff *skb,
		__be32 (*do_process)(void *, int, unsigned int),
				unsigned int passwd)
{
	__be32 csum;
	int i;
	int start;

	start = skb_headlen(skb);
	csum = do_process(skb->data, start, passwd);

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *f = &skb_shinfo(skb)->frags[i];
		u32 f_len = skb_frag_size(f);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
		{
			void *vaddr = kmap_atomic(skb_frag_page(f));
			csum += do_process(vaddr + f->page_offset, f_len, passwd);
			kunmap_atomic(vaddr);
		}
#else
		{
			u32 p_off, p_len, copied;
			struct page *p;
			skb_frag_foreach_page(f,
					f->page_offset,
					f_len, p, p_off, p_len, copied) {
				void *vaddr = kmap_atomic(p);
				csum += do_process(vaddr + p_off, p_len, passwd);
				kunmap_atomic(vaddr);
			}
		}
#endif
	}
	{
		struct sk_buff *frag_iter;
		skb_walk_frags(skb, frag_iter) {
			csum += process_data(frag_iter, do_process, passwd);
		}
	}

	return csum;
}

__be32 masq_data(struct sk_buff *skb, unsigned int passwd)
{
	return process_data(skb, masq_bytes, passwd);
}

__be32 demasq_data(struct sk_buff *skb, unsigned int passwd)
{
	return process_data(skb, demasq_bytes, passwd);
}
