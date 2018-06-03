#include <arpa/inet.h>
#include <linux/genetlink.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "ugenl-helper.h"

#define BUF_SIZE 4096

struct genlsk {
	char buf[BUF_SIZE];
	char *cur;
	int fd;
	uint16_t faid;
	uint32_t seq;
	uint32_t pid;
};

struct nlmsghdr *resp_buf(const struct genlsk *genlsk)
{
	return (struct nlmsghdr *)genlsk->buf;
}

static inline void update_nl_hdr_len(struct genlsk *genlsk)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)genlsk->buf;
	nlh->nlmsg_len = genlsk->cur - genlsk->buf;
}

static void put_nl_hdr(struct genlsk *genlsk, uint16_t flags)
{
	genlsk->cur = genlsk->buf;
	struct nlmsghdr *nlh = (struct nlmsghdr *)genlsk->cur;
	nlh->nlmsg_type = genlsk->faid;
	nlh->nlmsg_flags = flags;
	nlh->nlmsg_seq = ++genlsk->seq;
	nlh->nlmsg_pid = genlsk->pid;
	genlsk->cur += NLMSG_HDRLEN;
	update_nl_hdr_len(genlsk);
}

static void put_genl_hdr(struct genlsk *genlsk, uint8_t cmd)
{
	struct genlmsghdr *genlh = (struct genlmsghdr *)genlsk->cur;
	genlh->cmd = cmd;
	genlh->version = 0x01;
	genlsk->cur += GENL_HDRLEN;
	update_nl_hdr_len(genlsk);
}

void put_hdr(struct genlsk *genlsk, uint8_t cmd)
{
	put_nl_hdr(genlsk, NLM_F_REQUEST);
	put_genl_hdr(genlsk, cmd);
}

void put_hdr_dump(struct genlsk *genlsk, uint8_t cmd)
{
	put_nl_hdr(genlsk, NLM_F_REQUEST | NLM_F_DUMP);
	put_genl_hdr(genlsk, cmd);
}

static inline bool nl_buf_is_enough(struct genlsk *genlsk, int len)
{
	if (genlsk->cur + len > genlsk->buf + BUF_SIZE)
		return false;
	return true;
}

int add_nl_attr(struct genlsk *genlsk, uint16_t type, const void *data,
		int len)
{
	if (!nl_buf_is_enough(genlsk, len))
		return -1;

	struct nlattr *nla = (struct nlattr *)genlsk->cur;
	nla->nla_len = NLA_HDRLEN + len;
	nla->nla_type = type;
	memcpy((char *)nla + NLA_HDRLEN, data, len);
	genlsk->cur += NLA_ALIGN(nla->nla_len);
	update_nl_hdr_len(genlsk);
	return 0;
}

int send_nl_cmd(const struct genlsk *genlsk)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)genlsk->buf;
	int tot_len = nlh->nlmsg_len;
	int off = 0;
	while (off < tot_len) {
		int len = send(genlsk->fd, genlsk->buf + off, tot_len - off, 0);
		if (len < 0) {
			return -1;
		}
		off += len;
	}
	return off;
}

int recv_nl_resp(struct genlsk *genlsk)
{
	int len = recv(genlsk->fd, genlsk->buf, sizeof genlsk->buf, 0);
	if (len < 0) {
		return -1;
	}

	struct nlmsghdr *nlh = (struct nlmsghdr *)genlsk->buf;
	if (!NLMSG_OK(nlh, len)) {
		return -1;
	}
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		return -1;
	}

	return len;
}

struct genlsk *open_genl_socket(const char *name)
{
	struct genlsk *genlsk = malloc(sizeof *genlsk);
	if (!genlsk)
		return NULL;

	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (fd < 0)
		goto free_genlsk;

	struct timeval timeout = {.tv_sec = 1, .tv_usec = 0};
	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
				sizeof(timeout)) < 0)
		goto close_genlsk;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
				sizeof(timeout)) < 0)
		goto close_genlsk;

	//bind first?
	struct sockaddr_nl src;
	memset(&src, 0, sizeof src);
	src.nl_family = AF_NETLINK;
	src.nl_pid = getpid();
	if (bind(fd, (struct sockaddr *)&src, sizeof src) < 0)
		goto close_genlsk;

	struct sockaddr_nl dst;
	memset(&dst, 0, sizeof dst);
	dst.nl_family = AF_NETLINK;
	if (connect(fd, (struct sockaddr *)&dst, sizeof dst) < 0)
		goto close_genlsk;

	genlsk->fd = fd;
	genlsk->faid = GENL_ID_CTRL;
	genlsk->seq = 0;
	genlsk->pid = getpid();

	put_hdr(genlsk, CTRL_CMD_GETFAMILY);
	add_nl_attr(genlsk, CTRL_ATTR_FAMILY_NAME, name, strlen(name) + 1);

	if (send_nl_cmd(genlsk) < 0)
		goto close_genlsk;

	if (recv_nl_resp(genlsk) < 0)
		goto close_genlsk;

	struct nlmsghdr *nlh = (struct nlmsghdr *)genlsk->buf;
	int len = NLMSG_PAYLOAD(nlh, GENL_HDRLEN);
	struct nlattr *nla = (struct nlattr *)GENLMSG_DATA(nlh);
	if (len < sizeof NLA_HDRLEN || len < nla->nla_len)
		goto close_genlsk;
	len -= NLA_ALIGN(nla->nla_len);
	nla = (struct nlattr *)((char *)nla + NLA_ALIGN(nla->nla_len));
	if (len < sizeof NLA_HDRLEN || len < nla->nla_len)
		goto close_genlsk;
	if (nla->nla_type != CTRL_ATTR_FAMILY_ID || nla->nla_len - NLA_HDRLEN
			< 2)
		goto close_genlsk;

	genlsk->faid = *(uint16_t *)((char *)nla + NLA_HDRLEN);

	return genlsk;

close_genlsk:
	close(fd);
free_genlsk:
	free(genlsk);

	return NULL;
}

void close_genl_socket(struct genlsk *genlsk)
{
	close(genlsk->fd);
	free(genlsk);
}
