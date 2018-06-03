#ifndef _UGENL_HELPER_H_
#define _UGENL_HELPER_H_

#include <linux/genetlink.h>
#include <stdint.h>

#define GENLMSG_DATA(nlh) (void *)((char *)NLMSG_DATA(nlh) + GENL_HDRLEN)
#define NLA_OK(nla, len) ((len) >= (int)sizeof(struct nlattr) && \
		(nla)->nla_len >= sizeof(struct nlattr) && \
		(len) >= (nla)->nla_len)
#define NLA_NEXT(nla, len) ((len) -= NLA_ALIGN((nla)->nla_len), \
		(struct nlattr *)((char *)(nla) + NLA_ALIGN((nla)->nla_len)))
#define NLA_DATA(nla) (void *)((char *)(nla) + NLA_HDRLEN)
#define NLA_LEN(nla) ((nla)->nla_len - NLA_HDRLEN)

struct genlsk;

struct genlsk *open_genl_socket(const char *name);
void close_genl_socket(struct genlsk *genlsk);

void put_hdr(struct genlsk *genlsk, uint8_t cmd);
void put_hdr_dump(struct genlsk *genlsk, uint8_t cmd);
int add_nl_attr(struct genlsk *genlsk, uint16_t type, const void *data,
		int len);

int send_nl_cmd(const struct genlsk *genlsk);
int recv_nl_resp(struct genlsk *genlsk);

struct nlmsghdr *resp_buf(const struct genlsk *genlsk);

#endif
