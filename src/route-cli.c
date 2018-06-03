#include <arpa/inet.h>
#include <errno.h>
#include <linux/genetlink.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "ugenl.h"
#include "ugenl-helper.h"

#ifdef _IPR_CLIENT
#define IPR_GENL_NAME "IPROXY_CLIENT"
#else
#define IPR_GENL_NAME "IPROXY_SERVER"
#endif


struct route_entry {
	uint32_t network;
	uint8_t mask;
};

struct route_table {
	struct route_entry *entries;
	int size;
	int capacity;
};

static struct route_table *create_route_table(void)
{
	struct route_table *rt_tbl = calloc(1, sizeof *rt_tbl);
	if (!rt_tbl)
		return NULL;

	rt_tbl->capacity = 1;
	rt_tbl->entries = calloc(rt_tbl->capacity, sizeof *rt_tbl->entries);
	if (!rt_tbl->entries) {
		free(rt_tbl);
		return NULL;
	}

	return rt_tbl;
}

static bool route_table_need_expand(struct route_table *rt_tbl)
{
	return rt_tbl->size >= rt_tbl->capacity;
}

static int expand_route_table(struct route_table *rt_tbl)
{
	int expand = rt_tbl->capacity * 2;
	struct route_entry *tmp = realloc(rt_tbl->entries,
			expand * sizeof *rt_tbl->entries);
	if (!tmp)
		return -1;

	rt_tbl->entries = tmp;
	rt_tbl->capacity = expand;

	return 0;
}

static void fill_route_table(struct route_table *rt_tbl, uint32_t network,
		uint8_t mask)
{
	rt_tbl->entries[rt_tbl->size].network = network;
	rt_tbl->entries[rt_tbl->size].mask = mask;
	rt_tbl->size++;
}

static void destroy_route_table(struct route_table *rt_tbl)
{
	free(rt_tbl->entries);
	free(rt_tbl);
}

static inline char *preparse(char *cidr)
{
	char *sep = strchr(cidr, '/');
	if (!sep)
		return NULL;
	*sep = 0;
	return sep + 1;
}

static struct route_table *load_route_table(const char *file)
{
	struct route_table *rt_tbl = create_route_table();
	if (!rt_tbl) {
		fprintf(stderr, "failed to alloc route table\n");
		return NULL;
	}

	FILE *fp = fopen(file, "r");
	if (!fp) {
		fprintf(stderr, "failed to open file %s: %s\n", file,
				strerror(errno));
		return rt_tbl;
	}

	char line[32];
	int i = 0;
	while (fscanf(fp, "%s\n", line) == 1) {
		i++;

		char *sep = preparse(line);
		if (!sep) {
			fprintf(stderr, "failed to parse on line %d\n", i);
			continue;
		}

		struct in_addr ip;
		if (!inet_aton(line, &ip)) {
			fprintf(stderr, "failed to convert on line %d\n", i);
			continue;
		}
		int mask = atoi(sep);
		if (mask <= 0) {
			fprintf(stderr, "failed to convert on line %d\n", i);
			continue;
		}

		if (route_table_need_expand(rt_tbl) &&
				expand_route_table(rt_tbl)) {
			fprintf(stderr, "failed to expand route table: %d\n", rt_tbl->capacity);
			return rt_tbl;
		}

		fill_route_table(rt_tbl, ip.s_addr, mask);
	}

	if (fclose(fp)) {
		fprintf(stderr, "failed to close file %s: %s\n",
			file, strerror(errno));
	}

	return rt_tbl;
}

static void unload_route_table(struct route_table *rt_tbl)
{
	destroy_route_table(rt_tbl);
}

static int check_reply_ok(const struct genlsk *genlsk)
{
	struct nlmsghdr *nlh = resp_buf(genlsk);
	int len = NLMSG_PAYLOAD(nlh, GENL_HDRLEN);
	struct nlattr *nla = (struct nlattr *)GENLMSG_DATA(nlh);
	if (NLA_OK(nla, len) && nla->nla_type == IPR_ATTR_OK &&
			NLA_LEN(nla) == 0) {
		return 0;
	}
	return -1;
}

static int add_kernel_route(struct genlsk *genlsk, uint32_t network,
		uint8_t mask)
{
	put_hdr(genlsk, IPR_CMD_ADD_ROUTE);

	if (add_nl_attr(genlsk, IPR_ATTR_IP, &network, sizeof network))
		return -1;

	if (add_nl_attr(genlsk, IPR_ATTR_MASK, &mask, sizeof mask))
		return -1;

	if (send_nl_cmd(genlsk) < 0)
		return -1;

	if (recv_nl_resp(genlsk) < 0)
		return -1;

	return check_reply_ok(genlsk);
}

static int delete_kernel_route(struct genlsk *genlsk, uint32_t network,
		uint8_t mask)
{
	put_hdr(genlsk, IPR_CMD_DELETE_ROUTE);

	if (add_nl_attr(genlsk, IPR_ATTR_IP, &network, sizeof network))
		return -1;

	if (add_nl_attr(genlsk, IPR_ATTR_MASK, &mask, sizeof mask))
		return -1;

	if (send_nl_cmd(genlsk) < 0)
		return -1;

	if (recv_nl_resp(genlsk) < 0)
		return -1;

	return check_reply_ok(genlsk);
}

static int delete_match_kernel_route(struct genlsk *genlsk, uint32_t network)
{
	put_hdr(genlsk, IPR_CMD_DELETE_MATCH_ROUTE);

	if (add_nl_attr(genlsk, IPR_ATTR_IP, &network, sizeof network))
		return -1;

	if (send_nl_cmd(genlsk) < 0)
		return -1;

	if (recv_nl_resp(genlsk) < 0)
		return -1;

	return check_reply_ok(genlsk);
}

static int find_kernel_route(struct genlsk *genlsk, uint32_t ip)
{
	put_hdr(genlsk, IPR_CMD_FIND_ROUTE);

	if (add_nl_attr(genlsk, IPR_ATTR_IP, &ip, sizeof ip))
		return -1;

	if (send_nl_cmd(genlsk) < 0)
		return -1;

	if (recv_nl_resp(genlsk) < 0)
		return -1;

	struct nlmsghdr *nlh = resp_buf(genlsk);
	int len = NLMSG_PAYLOAD(nlh, GENL_HDRLEN);
	struct nlattr *nla = (struct nlattr *)GENLMSG_DATA(nlh);
	if (NLA_OK(nla, len) && nla->nla_type == IPR_ATTR_MASK &&
			NLA_LEN(nla) == 1) {
		return *(uint8_t *)NLA_DATA(nla);
	}

	return -1;
}

static int clear_kernel_route(struct genlsk *genlsk)
{
	put_hdr(genlsk, IPR_CMD_CLEAR_ROUTE);

	if (send_nl_cmd(genlsk) < 0)
		return -1;

	if (recv_nl_resp(genlsk) < 0)
		return -1;

	return check_reply_ok(genlsk);
}

static char *show_kernel_route(struct genlsk *genlsk)
{
	put_hdr_dump(genlsk, IPR_CMD_SHOW_ROUTE);

	if (send_nl_cmd(genlsk) < 0)
		return NULL;

	int total = 1024;
	int used = 0;
	char *rst = malloc(total);
	if (!rst)
		return NULL;
	*rst = 0;

	while (1) {
		if (recv_nl_resp(genlsk) < 0)
			break;

		struct nlmsghdr *nlh = resp_buf(genlsk);
		int len = NLMSG_PAYLOAD(nlh, GENL_HDRLEN);
		if (len <= 0 || nlh->nlmsg_type == NLMSG_DONE)
			return rst;

		struct nlattr *nla = (struct nlattr *)GENLMSG_DATA(nlh);
		while (1) {
			struct in_addr ip;
			if (NLA_OK(nla, len) && nla->nla_type == IPR_ATTR_IP &&
					NLA_LEN(nla) == 4) {
				ip.s_addr = *(uint32_t *)NLA_DATA(nla);
			} else
				break;

			nla = NLA_NEXT(nla, len);
			uint8_t mask;
			if (NLA_OK(nla, len) && nla->nla_type == IPR_ATTR_MASK &&
					NLA_LEN(nla) == 1) {
				mask = *(uint8_t *)NLA_DATA(nla);
			} else
				break;

			// 255.255.255.255/32: 18 + \n + \0 = 20
			if (used + 20 > total) {
				char *tmp = realloc(rst, total * 2);
				if (!tmp)
					goto fin;
				total *= 2;
				rst = tmp;
			}

			// inet_ntoa() thread unsafe
			int added = snprintf(rst + used, total - used, "%s/%u\n",
					inet_ntoa(ip), mask);
			if (added < 0 || added >= total - used)
				goto fin;

			used += added;

			nla = NLA_NEXT(nla, len);
		}
	};

fin:
	if (!used) {
		free(rst);
		return NULL;
	}

	return rst;
}

static int add(const char *genl_name, const char *network_str,
		const char *mask_str)
{
	struct genlsk *genlsk = open_genl_socket(genl_name);
	if (!genlsk)
		return -1;

	struct in_addr network;
	if (!inet_aton(network_str, &network))
		return -1;

	int mask = atoi(mask_str);
	if (mask <= 0)
		return -1;

	int err = add_kernel_route(genlsk, network.s_addr, mask);

	close_genl_socket(genlsk);

	return err;
}

static int delete(const char *genl_name, const char *network_str,
		const char *mask_str)
{
	struct genlsk *genlsk = open_genl_socket(genl_name);
	if (!genlsk)
		return -1;

	struct in_addr network;
	if (!inet_aton(network_str, &network))
		return -1;

	int mask = atoi(mask_str);
	if (mask <= 0)
		return -1;

	int err = delete_kernel_route(genlsk, network.s_addr, mask);

	close_genl_socket(genlsk);

	return err;
}

static int delete_match(const char *genl_name, const char *ip_str)
{
	struct genlsk *genlsk = open_genl_socket(genl_name);
	if (!genlsk)
		return -1;

	struct in_addr ip;
	if (!inet_aton(ip_str, &ip))
		return -1;

	int err = delete_match_kernel_route(genlsk, ip.s_addr);

	close_genl_socket(genlsk);

	return err;
}

static char *find(const char *genl_name, const char *ip_str)
{
	struct genlsk *genlsk = open_genl_socket(genl_name);
	if (!genlsk)
		return NULL;

	struct in_addr ip;
	if (!inet_aton(ip_str, &ip))
		goto close_genl_socket;

	int mask = find_kernel_route(genlsk, ip.s_addr);
	if (mask >= 0) {
		char *rst = malloc(3);
		if (!rst)
			goto close_genl_socket;

		if (snprintf(rst, 3, "%d", mask) < 0) {
			free(rst);
			goto close_genl_socket;
		}
		return rst;
	}

close_genl_socket:
	close_genl_socket(genlsk);

	return NULL;
}

static int clear(const char *genl_name)
{
	struct genlsk *genlsk = open_genl_socket(genl_name);
	if (!genlsk)
		return -1;

	int err = clear_kernel_route(genlsk);

	close_genl_socket(genlsk);

	return err;
}

static char *show(const char *genl_name)
{
	struct genlsk *genlsk = open_genl_socket(genl_name);
	if (!genlsk)
		return NULL;

	char *rst = show_kernel_route(genlsk);

	close_genl_socket(genlsk);

	return rst;
}

static int restore(const char *genl_name, struct route_table *rt_tbl)
{
	struct genlsk *genlsk = open_genl_socket(genl_name);
	if (!genlsk)
		return -1;

	for (int i = 0; i < rt_tbl->size; i++) {
		struct route_entry *re = &rt_tbl->entries[i];
		if (add_kernel_route(genlsk, re->network, re->mask) < 0) {
			close_genl_socket(genlsk);
			return -1;
		}
	}

	close_genl_socket(genlsk);

	return 0;
}

static int load(const char *genl_name, const char *file)
{
	struct route_table *rt_tbl = load_route_table(file);
	if (!rt_tbl)
		return -1;

	if (clear(genl_name))
		goto clear_kernel_route_table_err;

	if (restore(genl_name, rt_tbl))
		goto restore_kernel_route_table_err;

	unload_route_table(rt_tbl);

	return 0;

restore_kernel_route_table_err:
	fprintf(stderr, "warning: kernel route table is cleared, but not restored\n");

clear_kernel_route_table_err:
	unload_route_table(rt_tbl);

	return -1;
}

static void usage(const char *pgm)
{
	fprintf(stderr, "usage:\n");
	fprintf(stderr, "    add one: %s add <a.b.c.d/e>\n", pgm);
	fprintf(stderr, "    delete one: %s delete <a.b.c.d/e>\n", pgm);
	fprintf(stderr, "    delete match: %s delete <a.b.c.d>\n", pgm);
	fprintf(stderr, "    find one: %s find <a.b.c.d>\n", pgm);
	fprintf(stderr, "    clear all: %s clear\n", pgm);
	fprintf(stderr, "    show all: %s show\n", pgm);
	fprintf(stderr, "    load: %s load <path-to-file>\n", pgm);
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		usage(argv[0]);
		return -1;
	}

	if (!strcmp(argv[1], "add")) {
		if (argc < 3) {
			usage(argv[0]);
			return -1;
		}
		char *mask = preparse(argv[2]);
		if (!mask) {
			usage(argv[0]);
			return -1;
		}
		if (add(IPR_GENL_NAME, argv[2], mask)) {
			fprintf(stderr, "failed to add %s/%s: %s\n",
				argv[2], mask, strerror(errno));
			return -1;
		}
	} else if (!strcmp(argv[1], "delete")) {
		if (argc < 3) {
			usage(argv[0]);
			return -1;
		}
		char *mask = preparse(argv[2]);
		if (!mask) {
			if (delete_match(IPR_GENL_NAME, argv[2])) {
				fprintf(stderr, "failed to delete match %s: %s\n",
						argv[2], strerror(errno));
				return -1;
			}
		} else {
			if (delete(IPR_GENL_NAME, argv[2], mask)) {
				fprintf(stderr, "failed to delete %s/%s: %s\n",
						argv[2], mask, strerror(errno));
				return -1;
			}
		}
	} else if (!strcmp(argv[1], "clear")) {
		if (clear(IPR_GENL_NAME)) {
			fprintf(stderr, "failed to clear: %s\n",
				strerror(errno));
			return -1;
		}
	} else if (!strcmp(argv[1], "find")) {
		if (argc < 3) {
			usage(argv[0]);
			return -1;
		}
		char *rst;
		if (!(rst = find(IPR_GENL_NAME, argv[2]))) {
			fprintf(stderr, "failed to find %s: %s\n",
				argv[2], strerror(errno));
			return -1;
		}
		printf("%s\n", rst);
		free(rst);
	} else if (!strcmp(argv[1], "show")) {
		char *rst;
		if (!(rst = show(IPR_GENL_NAME))) {
			fprintf(stderr, "failed to show: %s\n",
				strerror(errno));
			return -1;
		}
		printf("%s", rst);
		free(rst);
	} else if (!strcmp(argv[1], "load")) {
		if (argc < 3) {
			usage(argv[0]);
			return -1;
		}
		if (load(IPR_GENL_NAME, argv[2])) {
			fprintf(stderr, "failed to load %s: %s\n",
				argv[2], strerror(errno));
			return -1;
		}
	} else {
		usage(argv[0]);
		return -1;
	}

	return 0;
}
