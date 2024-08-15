/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2021 iQIYI (www.iqiyi.com).
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include "dpip.h"
#include "conf/ipset.h"
#include "sockopt.h"

#define HEADER_LEN  1024
#define MEMBER_LEN  1024

typedef int (*sort_compare_func)
    (int af, const struct ipset_member *m1, const struct ipset_member *m2);

struct ipset_type {
    char *name;
    int (* parse)(char *arg);
    int (* check)(void);
    void (* dump_header)(char *buf, struct ipset_info *info);
    int (* dump_member)(char *buf, struct ipset_member *m, int af);
    sort_compare_func sort_compare;
};

// All supported ipset types
#define MAX_TYPE_NUM    64
struct ipset_type types[MAX_TYPE_NUM];

static struct ipset_param param;

static char *query_str;

static inline bool
ipv6_addr_any(const struct in6_addr *a)
{
    return !(a->s6_addr32[0] | a->s6_addr32[1] |
            a->s6_addr32[2] | a->s6_addr32[3]);
}

static inline bool
ipv6_addr_equal(const struct in6_addr *a1, const struct in6_addr *a2)
{
    return !((a1->s6_addr32[0] ^ a2->s6_addr32[0]) &&
        (a1->s6_addr32[1] ^ a2->s6_addr32[1]) &&
        (a1->s6_addr32[2] ^ a2->s6_addr32[2]) &&
        (a1->s6_addr32[3] ^ a2->s6_addr32[3]));
}

static inline int
is_zero_mac_addr(const uint8_t *mac)
{
    const uint16_t *w = (const uint16_t *)mac;

    return !(w[0] | w[1] | w[2]);
}

static int
types_string(char buf[], size_t bufsiz, int tokens_per_line, const char *prompt)
{
    int i, j;
    int indent, typelen, linelen, totallen;

    indent = strlen(prompt);
    if (tokens_per_line < 2 * indent || bufsiz < tokens_per_line)
        return EDPVS_INVAL;
    linelen = indent;
    totallen = snprintf(buf, bufsiz, "%s", prompt);
    if (totallen >= bufsiz)
        return EDPVS_NOMEM;

    for (i = 0; i < NELEMS(types); i++) {
        if (!types[i].name)
            break;
        typelen = snprintf(&buf[totallen], bufsiz - totallen - 1,
                i > 0 ? " | %s" : "%s", types[i].name);
        totallen += typelen;
        if (totallen >= bufsiz)
            return EDPVS_NOMEM;
        linelen += typelen;
        if (linelen < tokens_per_line)
            continue;

        if (totallen + indent + 1 >= bufsiz)
            return EDPVS_NOMEM;
        buf[totallen++] = '\n';
        for (j = 0; j < indent; j++)
            buf[totallen++] = ' ';
        linelen = indent;
    }
    snprintf(&buf[totallen], bufsiz - totallen - 1, "%s", " }");

    return EDPVS_OK;
}

static void
ipset_help(void)
{
    char type_names[1024];
    if (types_string(type_names, sizeof(type_names), 80, "    TYPE      := { ") != EDPVS_OK)
        fprintf(stderr, "Warn: Failed to get all ipset types.");
    fprintf(stderr,
                    "Usage:\n"
                    "    dpip ipset create SETNAME TYPE [ OPTIONS ]\n"
                    "    dpip ipset destroy SETNAME\n"
                    "    dpip ipset { add | del | test } SETNAME ENTRY [ ADTOPTS ]\n"
                    "    dpip ipset { show | flush } [ SETNAME ]\n"
                    "Parameters:\n"
                    "%s\n"
                    "    ENTRY     := combinations of one or more comma seperated tokens below,\n"
                    "                 { { IP | NET } | PORT | MAC | IFACE }\n"
                    "    IP        := ipv4 or ipv6 string literal\n"
                    "    NET       := \"{ IP/prefix | IP(range from)[-IP(range end)] }\"\n"
                    "    MAC       := 6 bytes MAC address string literal\n"
                    "    PORT      := \"[{ tcp | udp | icmp | icmp6 }:]port1[-port2]\"\n"
                    "    OPTIONS   := { comment | range NET | hashsize NUM | maxelem NUM }\n"
                    "    ADTOPTS   := { comment STRING | nomatch (for add only) }\n"
                    "    flag      := { -F(--force) | { -4 | -6 } | -v }\n"
                    "Examples:\n"
                    "    dpip ipset create foo bitmap:ip range 192.168.0.0/16 comment\n"
                    "    dpip ipset add foo 192.168.0.1-192.168.0.5 comment \"test entry\"\n"
                    "    dpip ipset show foo\n"
                    "    dpip ipset flush foo\n"
                    "    dpip ipset destroy foo\n"
                    "    dpip -6 ipset create bar hash:net,port,iface hashsize 300 maxelem 1000\n"
                    "    dpip ipset add bar 2001:beef::/64,udp:100,dpdk0\n"
                    "    dpip -v ipset test bar 2001:beef::abcd,udp:100,dpdk0\n"
                    "    dpip ipset del bar 2001:beef::/64,udp:100,dpdk0\n"
                    "    dpip ipset destroy bar\n", type_names
    );
}

/* ========================== parse =========================== */
/* { ip1-ip2 | ip/cidr } */
static int
addr_arg_parse(char *arg, struct inet_addr_range *range, uint8_t *cidr)
{
    char *ip1, *ip2, *sep;
    uint8_t *af = &param.option.family;

    /* ip/cidr */
    if (cidr && (sep = strstr(arg, "/"))) {
        *sep++ = '\0';
        *cidr = atoi(sep);

        if (inet_pton(AF_INET6, arg, &range->min_addr.in6) <= 0) {
            if (inet_pton(AF_INET, arg, &range->min_addr.in) <= 0)
                return EDPVS_INVAL;
            *af = AF_INET;
        } else {
            *af = AF_INET6;
        }

        range->max_addr = range->min_addr;
        return EDPVS_OK;
    }

    /* ip1-ip2 */
    ip1 = arg;
    ip2 = strrchr(arg, '-');
    if (ip2)
        *ip2++ = '\0';
    if (strlen(ip1) && inet_pton(AF_INET6, ip1, &range->min_addr.in6) > 0) {
        if (ip2 && strlen(ip2)) {
            if (inet_pton(AF_INET6, ip2, &range->max_addr.in6) <= 0)
                return EDPVS_INVAL;
        } else {
            range->max_addr = range->min_addr;
        }
        *af = AF_INET6;
    } else {
        if (strlen(ip1) && inet_pton(AF_INET, ip1, &range->min_addr.in) <= 0)
            return EDPVS_INVAL;
        if (ip2 && strlen(ip2)) {
            if (inet_pton(AF_INET, ip2, &range->max_addr.in) <= 0)
                return EDPVS_INVAL;
            if (ntohl(range->max_addr.in.s_addr) < ntohl(range->min_addr.in.s_addr))
                range->max_addr = range->min_addr;
        } else {
            range->max_addr = range->min_addr;
        }
        *af = AF_INET;
    }

    return EDPVS_OK;
}

/* [ {tcp | udp | icmp | icmp6 }: ]port1[-port2] */
static int
port_arg_parse(char *arg, struct inet_addr_range *range)
{
    char *proto = arg, *sep, *port1, *port2;
    int portval;

    if (!strncmp(proto, "tcp", 3))
        param.proto = IPPROTO_TCP;
    else if (!strncmp(proto, "udp", 3))
        param.proto = IPPROTO_UDP;
    else if (!strncmp(proto, "icmp", 4))
        param.proto = IPPROTO_ICMP;
    else if (!strncmp(proto, "icmp6", 5))
        param.proto = IPPROTO_ICMPV6;
    else
        param.proto = 0;

    if ((sep = strchr(arg, ':')) != NULL) {
        *sep++ = '\0';
        arg = sep;
    }

    port1 = arg;
    portval = atoi(port1);
    if (portval < 0 || portval > 65535)
        return EDPVS_INVAL;
    range->max_port = range->min_port = portval;

    sep = strchr(arg, '-');
    if (sep) {
        *sep++ = '\0';
        port2 = sep;
        portval = atoi(port2);
        if (portval < range->min_port || portval > 65535)
            return EDPVS_INVAL;
        range->max_port = portval;
    }

    return EDPVS_OK;
}

/* option parse */
static inline int
create_opt_parse(struct dpip_conf *conf)
{
    struct ipset_option *opt = &param.option;
    opt->family = (conf->af == AF_INET6) ? AF_INET6 : AF_INET;

    while (conf->argc > 0) {
        /* bitmap type MUST specify range */
        if (!strcmp(CURRARG(conf), "range")) {
            NEXTARG_CHECK(conf, CURRARG(conf));
            if (strstr(param.type, "ip")) {
                if (addr_arg_parse(CURRARG(conf), &param.range, &param.cidr) < 0)
                    return EDPVS_INVAL;
            } else if (strstr(param.type, "port"))
                if (port_arg_parse(CURRARG(conf), &param.range) < 0)
                    return EDPVS_INVAL;
       } else if (!strcmp(CURRARG(conf), "comment")) {
            opt->create.comment = true;
        } else if (!strcmp(CURRARG(conf), "hashsize")) {
            NEXTARG_CHECK(conf, CURRARG(conf));
            opt->create.hashsize = atoi(CURRARG(conf));
        } else if (!strcmp(CURRARG(conf), "maxelem")) {
            NEXTARG_CHECK(conf, CURRARG(conf));
            opt->create.maxelem = atoi(CURRARG(conf));
        } else {
            return EDPVS_NOTSUPP;
        }
        NEXTARG(conf);
    }
    return EDPVS_OK;
}

static inline int
add_del_opt_parse(struct dpip_conf *conf)
{
    while(conf->argc > 0) {
        if (strcmp(CURRARG(conf), "comment") == 0) {
            NEXTARG_CHECK(conf, CURRARG(conf));
            strncpy(param.comment, CURRARG(conf), IPSET_MAXCOMLEN);
        } else if (strcmp(CURRARG(conf), "nomatch") == 0) {
            param.option.add.nomatch = true;
        }else {
            return EDPVS_NOTSUPP;
        }
        NEXTARG(conf);
    }

    if (conf->force)
        param.flag |= IPSET_F_FORCE;

    return EDPVS_OK;
}

static int
net_parse(char *arg)
{
    return addr_arg_parse(arg, &param.range, &param.cidr);
}

static inline int
seg_parse(char *params, int maxsegs, int *segnum, char **segs)
{
    int i = 0;
    char *start, *sp, *arg;

    for (start = params; (arg = strtok_r(start, ",", &sp)); start = NULL) {
        segs[i] = arg;
        i++;
    }

    if (i > maxsegs)
        return EDPVS_INVAL;
    if (segnum)
        *segnum = i;

    return EDPVS_OK;
}

/* ip, mac */
static int
ipmac_parse(char *arg)
{
    int i, segnum;
    char *segs[2];
    unsigned int mac[6] = { 0 };

    if (seg_parse(arg, 2, &segnum, segs) < 0)
        return EDPVS_INVAL;

    if (net_parse(segs[0]) < 0)
        return EDPVS_INVAL;

    if (segnum > 1 && sscanf(segs[1], "%02X:%02X:%02X:%02X:%02X:%02X",
        &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) < 0)
        return EDPVS_INVAL;

    for (i = 0; i < 6; i++)
        param.mac[i] = mac[i];

    return EDPVS_OK;
}

static int
port_parse(char *arg)
{
    if (port_arg_parse(arg, &param.range) < 0)
        return EDPVS_INVAL;

    // bitmap:port supports protocol tcp, udp only
    if (param.proto != IPPROTO_TCP &&
            param.proto != IPPROTO_UDP) {
        fprintf(stderr, "bitmap:port should specified protocol tcp or udp\n");
        return EDPVS_INVAL;
    }

    return EDPVS_OK;
}

static int
netport_parse(char *arg)
{
    int segnum;
    char *segs[2];

    if (seg_parse(arg, 2, &segnum, segs) < 0)
        return EDPVS_INVAL;
    if (segnum != 2)
        return EDPVS_INVAL;

    if (addr_arg_parse(segs[0], &param.range, &param.cidr) < 0)
        return EDPVS_INVAL;

    if (port_arg_parse(segs[1], &param.range) < 0)
        return EDPVS_INVAL;

    return EDPVS_OK;
}

/* net, port, iface */
static int
netportiface_parse(char *arg)
{
    int segnum;
    char *segs[3];

    if (seg_parse(arg, 3, &segnum, segs) < 0)
        return EDPVS_INVAL;
    if (segnum != 3)
        return EDPVS_INVAL;

    if (addr_arg_parse(segs[0], &param.range, &param.cidr) < 0)
        return EDPVS_INVAL;

    if (port_arg_parse(segs[1], &param.range) < 0)
        return EDPVS_INVAL;

    strncpy(param.iface, segs[2], IFNAMSIZ);

    return EDPVS_OK;
}

static int
ipport_parse(char *arg)
{
    int segnum;
    char *segs[2];

    if (seg_parse(arg, 2, &segnum, segs) < 0)
        return EDPVS_INVAL;

    if (addr_arg_parse(segs[0], &param.range, &param.cidr) < 0)
        return EDPVS_INVAL;

    if (segnum > 1 && port_arg_parse(segs[1], &param.range) < 0)
        return EDPVS_INVAL;

    return EDPVS_OK;
}

static int
ipportip_parse(char *arg)
{
    int segnum;
    char *segs[3];

    if (seg_parse(arg, 3, &segnum, segs) < 0)
        return EDPVS_INVAL;
    if (segnum != 3)
        return EDPVS_INVAL;

    if (addr_arg_parse(segs[0], &param.range, &param.cidr) < 0)
        return EDPVS_INVAL;

    if (port_arg_parse(segs[1], &param.range) < 0)
        return EDPVS_INVAL;

    if (addr_arg_parse(segs[2], &param.range2, &param.cidr2) < 0)
        return EDPVS_INVAL;

    return EDPVS_OK;
}

static int
ipportnet_parse(char *arg)
{
    int segnum;
    char *segs[3];

    if (seg_parse(arg, 3, &segnum, segs) < 0)
        return EDPVS_INVAL;
    if (segnum != 3)
        return EDPVS_INVAL;

    if (addr_arg_parse(segs[2], &param.range, &param.cidr) < 0)
        return EDPVS_INVAL;

    if (port_arg_parse(segs[1], &param.range) < 0)
        return EDPVS_INVAL;

    if (addr_arg_parse(segs[0], &param.range2, &param.cidr2) < 0)
        return EDPVS_INVAL;

    return EDPVS_OK;
}

static int
netportnetport_parse(char *arg)
{
    uint8_t proto;
    int segnum;
    char *segs[4];

    if (seg_parse(arg, 4, &segnum, segs) < 0)
        return EDPVS_INVAL;
    if (segnum != 4)
        return EDPVS_INVAL;

    if (addr_arg_parse(segs[0], &param.range, &param.cidr) < 0)
        return EDPVS_INVAL;

    if (port_arg_parse(segs[1], &param.range) < 0)
        return EDPVS_INVAL;
    proto = param.proto;

    if (addr_arg_parse(segs[2], &param.range2, &param.cidr2) < 0)
        return EDPVS_INVAL;

    if (port_arg_parse(segs[3], &param.range2) < 0)
        return EDPVS_INVAL;

    if (param.proto != proto) {
        fprintf(stderr, "Error: port protocol doesn't match\n");
        return EDPVS_INVAL;
    }

    return EDPVS_OK;
}

static int
get_info_array(struct ipset_info_array **array)
{
    size_t size;

    int err = dpvs_getsockopt(SOCKOPT_GET_IPSET_LIST, &param, sizeof(param),
                        (void **)array, &size);
    if (err != 0)
        return EDPVS_INVAL;

    if (size < 0) {
        fprintf(stderr, "corrupted response.\n");
        dpvs_sockopt_msg_free(*array);
        return EDPVS_INVAL;
    }

    return EDPVS_OK;
}

static inline int
get_type_idx_from_type(char *type)
{
    int i;

    for (i = 0; i < NELEMS(types); i++) {
        if (!types[i].name)
            break;
        if (!strcmp(types[i].name, type))
            return i;
    }

    return EDPVS_NOTSUPP;
}

static int
get_type_idx_remote(void)
{
    static int tyidx = -1;
    struct ipset_info *info;
    struct ipset_info_array *array;

    if (tyidx >= 0)
        return tyidx;

    if (get_info_array(&array) < 0) {
        return EDPVS_NOTEXIST;
    }
    info = &array->infos[0];

    tyidx = get_type_idx_from_type(info->type);
    dpvs_sockopt_msg_free(array);

    return tyidx;
}

static int
get_type_idx(void)
{
    if (param.opcode == IPSET_OP_CREATE)
        return get_type_idx_from_type(param.type);
    return get_type_idx_remote();
}

static int
ipset_parse(struct dpip_obj *obj, struct dpip_conf *conf)
{
    int type_idx;

    switch (conf->cmd) {
        case DPIP_CMD_CREATE:
            param.opcode = IPSET_OP_CREATE;
            break;
        case DPIP_CMD_DESTROY:
            param.opcode = IPSET_OP_DESTROY;
            break;
        case DPIP_CMD_ADD:
            param.opcode = IPSET_OP_ADD;
            break;
        case DPIP_CMD_DEL:
            param.opcode = IPSET_OP_DEL;
            break;
        case DPIP_CMD_FLUSH:
            param.opcode = IPSET_OP_FLUSH;
            break;
        case DPIP_CMD_SHOW:
            param.opcode = IPSET_OP_LIST;
            break;
        case DPIP_CMD_TEST:
            param.opcode = IPSET_OP_TEST;
            break;
        default:
            param.opcode = IPSET_OP_MAX;
            break;
    }

    /* list all sets */
    if (conf->argc == 0) {
        if (conf->cmd == DPIP_CMD_SHOW)
            return EDPVS_OK;
        return EDPVS_INVAL;
    }

    /* operate on specific set */
    sprintf(param.name, "%s", CURRARG(conf));
    NEXTARG(conf);
    switch (conf->cmd) {
        case DPIP_CMD_FLUSH:
        case DPIP_CMD_DESTROY:
        case DPIP_CMD_SHOW:
            if (conf->argc == 0)
                return EDPVS_OK;
            return EDPVS_INVAL;
        case DPIP_CMD_CREATE:
            if (conf->argc < 1)
                return EDPVS_INVAL;
            sprintf(param.type, "%s", CURRARG(conf));
            NEXTARG(conf);
            if (create_opt_parse(conf) < 0)
                return EDPVS_INVAL;
            return EDPVS_OK;
        case DPIP_CMD_ADD:
        case DPIP_CMD_DEL:
        case DPIP_CMD_TEST:
            if ((conf->argc < 1))
                return EDPVS_INVAL;
            type_idx = get_type_idx();
            if (type_idx < 0)
                return EDPVS_INVAL;
            if (conf->verbose) {
                query_str = malloc(strlen(CURRARG(conf) + 1));
                strcpy(query_str, CURRARG(conf));
            }
            /* type specific arg parsing */
            if (types[type_idx].parse &&
                    (types[type_idx].parse(CURRARG(conf)) < 0))
                return EDPVS_INVAL;
            if (conf->cmd == DPIP_CMD_TEST)
                return EDPVS_OK;
            NEXTARG(conf);
            return add_del_opt_parse(conf);
        default:
            return EDPVS_INVAL;
    }
    return EDPVS_NOTSUPP;
}

/* =========================== check ============================ */

static int
bitmap_check(void)
{
    if (param.option.family == AF_INET6) {
        fprintf(stderr, "bitmap doesn't support ipv6\n");
        return EDPVS_NOTSUPP;
    }

    if (param.opcode != IPSET_OP_CREATE)
        return EDPVS_OK;

    if (strstr(param.type, "ip")) {
        if (ntohl(param.range.min_addr.in.s_addr) > ntohl(param.range.max_addr.in.s_addr) ||
                param.range.max_addr.in.s_addr == 0) {
            fprintf(stderr, "bitmap's IP range MUST be specified\n");
            return EDPVS_INVAL;
        }
    }
    if (strstr(param.type, "port")) {
        if (param.range.min_port > param.range.max_port ||
                param.range.max_port == 0) {
            fprintf(stderr, "bitmap's port range MUST be specified\n");
            return EDPVS_INVAL;
        }
    }

    return EDPVS_OK;
}

static int
hash_ip_check(void)
{
    if (param.opcode != IPSET_OP_ADD && param.opcode != IPSET_OP_DEL)
        return EDPVS_OK;

    if (param.option.family == AF_INET6) {
        if (param.cidr || param.cidr2) {
            fprintf(stderr, "ipv6 cidr is not supported by the set type\n");
            return EDPVS_INVAL;
        }
    } else if (param.option.family == AF_INET) {
        if ((param.cidr > 0 && param.cidr < 16) ||
                (param.cidr2 > 0 && param.cidr2 < 16)) {
            fprintf(stderr, "ipv4 cidr shouldn't be less than 16\n");
            return EDPVS_INVAL;
        }
        if (ntohl(param.range.max_addr.in.s_addr) != 0) {
            if (ntohl(param.range.max_addr.in.s_addr) <
                    ntohl(param.range.min_addr.in.s_addr)) {
                fprintf(stderr, "invalid ipv4 range\n");
                return EDPVS_INVAL;
            }
            if (ntohl(param.range.max_addr.in.s_addr) -
                    ntohl(param.range.min_addr.in.s_addr) > 65536) {
                fprintf(stderr, "ip range shouldn't be greater than 65536\n");
                return EDPVS_INVAL;
            }
        }
        if (ntohl(param.range2.max_addr.in.s_addr) != 0) {
            if (ntohl(param.range2.max_addr.in.s_addr) <
                    ntohl(param.range2.min_addr.in.s_addr)) {
                fprintf(stderr, "invalid ipv4 range\n");
                return EDPVS_INVAL;
            }
            if (ntohl(param.range2.max_addr.in.s_addr) -
                    ntohl(param.range2.min_addr.in.s_addr) > 65536) {
                fprintf(stderr, "ip range shouldn't be greater than 65536\n");
                return EDPVS_INVAL;
            }
        }
    }

    return EDPVS_OK;
}

static int
hash_net_check(void)
{
    if (param.opcode != IPSET_OP_ADD && param.opcode != IPSET_OP_DEL)
        return EDPVS_OK;

    if (param.option.family == AF_INET) {
        if (ntohl(param.range.max_addr.in.s_addr) != 0) {
            if (ntohl(param.range.max_addr.in.s_addr) <
                    ntohl(param.range.min_addr.in.s_addr)) {
                fprintf(stderr, "invalid ipv4 range\n");
                return EDPVS_INVAL;
            }
        }
        if (ntohl(param.range2.max_addr.in.s_addr) != 0) {
            if (ntohl(param.range2.max_addr.in.s_addr) <
                    ntohl(param.range2.min_addr.in.s_addr)) {
                fprintf(stderr, "invalid ipv4 range\n");
                return EDPVS_INVAL;
            }
        }
    }

    return EDPVS_OK;
}

static int
hash_ipnet_check(void)
{
    if (param.opcode != IPSET_OP_ADD && param.opcode != IPSET_OP_DEL)
        return EDPVS_OK;

    if (param.option.family == AF_INET6) {
        if (param.cidr2) {
            fprintf(stderr, "hash:ip,port doesn't support ipv6 cidr\n");
            return EDPVS_INVAL;
        }
    } else if (param.option.family == AF_INET) {
        if (param.cidr > 0 && param.cidr < 16) {
            fprintf(stderr, "ipv4 cidr shouldn't be less than 16\n");
            return EDPVS_INVAL;
        }
        if (ntohl(param.range.max_addr.in.s_addr) != 0) {
            if (ntohl(param.range.max_addr.in.s_addr) <
                    ntohl(param.range.min_addr.in.s_addr)) {
                fprintf(stderr, "invalid ipv4 range\n");
                return EDPVS_INVAL;
            }
            if (ntohl(param.range.max_addr.in.s_addr) -
                    ntohl(param.range.min_addr.in.s_addr) > 65536) {
                fprintf(stderr, "ipv6 range shouldn't be greater than 65536\n");
                return EDPVS_INVAL;
            }
        }
    }

    return EDPVS_OK;
}

static int
ipset_check(const struct dpip_obj *obj, dpip_cmd_t cmd)
{
    int type_idx;

    if (param.opcode == IPSET_OP_TEST) {
        if (param.cidr || param.cidr2) {
            fprintf(stderr, "Warning: ignore cidr settings for ipset test\n");
            param.cidr = param.cidr2 = 0;
        }
    }

    if (param.option.family == AF_INET6) {
        if ((!ipv6_addr_any(&param.range.max_addr.in6) &&
                !ipv6_addr_equal(&param.range.min_addr.in6, &param.range.max_addr.in6)) ||
                (!ipv6_addr_any(&param.range2.min_addr.in6) &&
                !(ipv6_addr_equal(&param.range2.min_addr.in6, &param.range2.max_addr.in6)))) {
            fprintf(stderr, "ipv6 range is not supported\n");
            return EDPVS_INVAL;
        }
    }

    type_idx = get_type_idx();
    if (type_idx < 0) {
        if (param.opcode == IPSET_OP_LIST)
            return EDPVS_OK;
        return EDPVS_INVAL;
    }

    /* type specific check */
    if (types[type_idx].check)
        return types[type_idx].check();

    return EDPVS_OK;
}

/* =========================== dump ============================ */

static void
bitmap_dump_header(char *buf, struct ipset_info *info)
{
    char range[128];
    char addr[INET6_ADDRSTRLEN], addr2[INET6_ADDRSTRLEN];

    if (info->bitmap.cidr) {
        inet_ntop(AF_INET, &info->bitmap.range.min_addr,
                addr, INET_ADDRSTRLEN);
        sprintf(range, "%s/%d", addr, info->bitmap.cidr);
    } else {
        if (!strcmp(info->type, "bitmap:ip")) {
            inet_ntop(AF_INET, &info->bitmap.range.min_addr,
                    addr, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &info->bitmap.range.max_addr,
                    addr2, INET_ADDRSTRLEN);
            sprintf(range, "%s-%s", addr, addr2);
        }
        if (!strcmp(info->type, "bitmap:port")) {
            sprintf(range, "tcp|udp:%d-%d", info->bitmap.range.min_port,
                        info->bitmap.range.max_port);
        }
    }
    sprintf(buf, "range %s  %s", range, info->comment? "comment" : "");
}

static void
hash_dump_header(char *buf, struct ipset_info *info)
{
    sprintf(buf, "family %s  hashsize %d  maxelem %d  %s",
            info->af == AF_INET? "inet" : "inet6",
            info->hash.hashsize, info->hash.maxelem,
            info->comment? "comment" : "");
}

static inline int
dump_comment(char *buf, char *comment)
{
    int n;

    if (strlen(comment)) {
        n = sprintf(buf, "comment \"%s\"\n", comment);
    } else {
        n = sprintf(buf, "\n");
    }
    return n;
}

static const char*
proto_string(uint8_t proto)
{
    switch(proto) {
        case IPPROTO_TCP:
            return "tcp";
        case IPPROTO_UDP:
            return "udp";
        case IPPROTO_ICMP:
            return "icmp";
        case IPPROTO_ICMPV6:
            return "icmp6";
        default:
            return "unspec";
    }
}

static int
net_dump_member(char *buf, struct ipset_member *member, int af)
{
    int n = 0;
    char addr[INET6_ADDRSTRLEN];

    inet_ntop(af, &member->addr.in6, addr, INET6_ADDRSTRLEN);
    if (member->cidr) {
        n = sprintf(buf, "%s/%d ", addr, member->cidr);
    } else {
        n = sprintf(buf, "%s ", addr);
    }

    if (member->nomatch)
        n += sprintf(buf + n, "nomatch ");
    n += sprintf(buf + n , " ");

    n += dump_comment(buf + n, member->comment);

    return n;
}

static int
ipmac_dump_member(char *buf, struct ipset_member *member, int af)
{
    int n;
    char addr[INET_ADDRSTRLEN];
    uint8_t *mac = member->mac;

    inet_ntop(AF_INET, &member->addr.in, addr, INET_ADDRSTRLEN);
    if (!is_zero_mac_addr(mac)) {
        n = sprintf(buf, "%s,%02X:%02X:%02X:%02X:%02X:%02X  ", addr,
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else {
        n = sprintf(buf, "%s", addr);
    }

    n += dump_comment(buf + n, member->comment);

    return n;
}

static int
port_dump_member(char *buf, struct ipset_member *member, int af)
{
    int n;

    n = sprintf(buf, "%s:%d  ", proto_string(member->proto), member->port);

    n += dump_comment(buf + n, member->comment);

    return n;
}

static int
ipport_dump_member(char *buf, struct ipset_member *member, int af)
{
    int n;
    char addr[INET6_ADDRSTRLEN];

    inet_ntop(af, &member->addr, addr, INET6_ADDRSTRLEN);

    n = sprintf(buf, "%s,%s:%d  ", addr, proto_string(member->proto), member->port);

    n += dump_comment(buf + n, member->comment);

    return n;
}

static int
netport_dump_member(char *buf, struct ipset_member *member, int af)
{
    int n;
    char addr[INET6_ADDRSTRLEN];

    inet_ntop(af, &member->addr, addr, INET6_ADDRSTRLEN);

    n = sprintf(buf, "%s/%d,%s:%d ", addr, member->cidr,
                proto_string(member->proto), member->port);

    if (member->nomatch)
        n += sprintf(buf + n, "nomatch ");
    n += sprintf(buf + n , " ");

    n += dump_comment(buf + n, member->comment);

    return n;
}

static int
netportiface_dump_member(char *buf, struct ipset_member *member, int af)
{
    int n;
    char addr[INET6_ADDRSTRLEN];

    inet_ntop(af, &member->addr, addr, INET6_ADDRSTRLEN);

    n = sprintf(buf, "%s/%d,%s:%d,%s ", addr, member->cidr,
                proto_string(member->proto),
                member->port, member->iface);

    if (member->nomatch)
        n += sprintf(buf + n, "nomatch ");
    n += sprintf(buf + n , " ");

    n += dump_comment(buf + n, member->comment);

    return n;
}

static int
ipportip_dump_member(char *buf, struct ipset_member *member, int af)
{
    int n;
    char addr[INET6_ADDRSTRLEN], addr2[INET6_ADDRSTRLEN];

    inet_ntop(af, &member->addr, addr, INET6_ADDRSTRLEN);
    inet_ntop(af, &member->addr2, addr2, INET6_ADDRSTRLEN);

    n = sprintf(buf, "%s,%s:%d,%s  ", addr,
            proto_string(member->proto), member->port, addr2);

    n += dump_comment(buf + n, member->comment);

    return n;
}

static int
ipportnet_dump_member(char *buf, struct ipset_member *member, int af)
{
    int n;
    char addr[INET6_ADDRSTRLEN], addr2[INET6_ADDRSTRLEN];

    inet_ntop(af, &member->addr, addr, INET6_ADDRSTRLEN);
    inet_ntop(af, &member->addr2, addr2, INET6_ADDRSTRLEN);

    n = sprintf(buf, "%s,%s:%d,%s/%d ", addr2,
            proto_string(member->proto), member->port, addr, member->cidr);

    if (member->nomatch)
        n += sprintf(buf + n, "nomatch ");
    n += sprintf(buf + n , " ");

    n += dump_comment(buf + n, member->comment);

    return n;
}

static int
netportnet_dump_member(char *buf, struct ipset_member *member, int af)
{
    int n;
    char addr[INET6_ADDRSTRLEN], addr2[INET6_ADDRSTRLEN];

    inet_ntop(af, &member->addr, addr, INET6_ADDRSTRLEN);
    inet_ntop(af, &member->addr2, addr2, INET6_ADDRSTRLEN);

    n = sprintf(buf, "%s/%d,%s:%d,%s/%d ", addr, member->cidr,
            proto_string(member->proto), member->port, addr2, member->cidr2);

    if (member->nomatch)
        n += sprintf(buf + n, "nomatch ");
    n += sprintf(buf + n , " ");

    n += dump_comment(buf + n, member->comment);

    return n;
}

static int
netportnetport_dump_member(char *buf, struct ipset_member *member, int af)
{
    int n;
    char addr[INET6_ADDRSTRLEN], addr2[INET6_ADDRSTRLEN];

    inet_ntop(af, &member->addr, addr, INET6_ADDRSTRLEN);
    inet_ntop(af, &member->addr2, addr2, INET6_ADDRSTRLEN);

    n = sprintf(buf, "%s/%d,%s:%d,%s/%d,%s:%d ", addr, member->cidr,
            proto_string(member->proto), member->port,
            addr2, member->cidr2,
            proto_string(member->proto), member->port2);

    if (member->nomatch)
        n += sprintf(buf + n, "nomatch ");
    n += sprintf(buf + n , " ");

    n += dump_comment(buf + n, member->comment);

    return n;
}

static void
ipset_info_dump(struct ipset_info *info, bool sort)
{
    int i, type, n = 0;
    struct ipset_member *member;
    char header[HEADER_LEN], *members;

    type = get_type_idx_from_type(info->type);
    if (type < 0) {
        fprintf(stderr, "unsupported ipset type %s\n", info->type);
        return;
    }

    /* header */
    types[type].dump_header(header, info);

    /* members */
    if (info->entries)
        members = malloc(info->entries * MEMBER_LEN);
    else
        members = "";

    if (sort && types[type].sort_compare) {
        // sort the ipset
        int i, j, min;
        struct ipset_member swap;
        struct ipset_member *members = (struct ipset_member*)info->members;
        sort_compare_func sort_compare = types[type].sort_compare;

        for (i = 0; i + 1 < info->entries; i++) {
            min = i;
            for (j = i + 1; j < info->entries; j++) {
                if (sort_compare(info->af, &members[min], &members[j]) > 0)
                    min = j;
            }
            if (min != i) {
                memcpy(&swap, &members[min], sizeof(struct ipset_member));
                memcpy(&members[min], &members[i], sizeof(struct ipset_member));
                memcpy(&members[i], &swap, sizeof(struct ipset_member));
            }
        }
    }

    member = info->members;
    for (i = 0; i < info->entries; i++) {
        n += types[type].dump_member(members + n, member, info->af);
        member++;
    }

    fprintf(stdout,
            "Name: %s\n"
            "Type: %s\n"
            "Header: %s\n"
            "Size in memory: %d\n"
            "References: %d\n"
            "Number of entries: %d\n"
            "Members:\n%s",
            info->name, info->type, header, (int)info->size,
            info->references, info->entries, members);

    if (info->entries)
        free(members);

    return;
}

static void
ipset_sockopt_msg_dump(struct ipset_info_array *array, bool sort)
{
    int i;
    void *ptr;
    struct ipset_info *info;

    ptr = (void *)array + sizeof(*array) + array->nipset * sizeof(*info);
    for (i = 0; i < array->nipset; i++) {
        info = &array->infos[i];
        info->members = ptr;

        ipset_info_dump(info, sort);
        fprintf(stdout, "\n");

        ptr += info->entries * sizeof(struct ipset_member);
    }
}

static int
ipset_do_cmd(struct dpip_obj *obj, dpip_cmd_t cmd, struct dpip_conf *conf)
{
    int err;

    switch (cmd) {
        case DPIP_CMD_CREATE:
        case DPIP_CMD_DESTROY:
        case DPIP_CMD_ADD:
        case DPIP_CMD_DEL:
        case DPIP_CMD_FLUSH:
            return dpvs_setsockopt(SOCKOPT_SET_IPSET, &param, sizeof(param));
        case DPIP_CMD_TEST:
        {
            int *result;
            size_t len;
            err = dpvs_getsockopt(SOCKOPT_GET_IPSET_TEST, &param, sizeof(param), (void **)&result, &len);
            if (err != EDPVS_OK || len != sizeof(*result) || *result < 0) {
                fprintf(stderr, "set test failed\n");
                return err ? err : EDPVS_INVAL;
            }
            if (conf->verbose) {
                if (*result)
                    fprintf(stdout, "%s is in set %s\n", query_str, param.name);
                else
                    fprintf(stdout, "%s is NOT in set %s\n", query_str, param.name);
                free(query_str);
            } else {
                if (*result)
                    fprintf(stdout, "true\n");
                else
                    fprintf(stdout, "false\n");
            }
            dpvs_sockopt_msg_free(result);
            return EDPVS_OK;
        }
        case DPIP_CMD_SHOW:
        {
            struct ipset_info_array *array;
            if (get_info_array(&array) < 0)
                return EDPVS_INVAL;
            ipset_sockopt_msg_dump(array, !!conf->verbose);
            dpvs_sockopt_msg_free(array);
            return EDPVS_OK;
        }
        default:
            return EDPVS_NOTSUPP;
    }
}

/* =========================== sort ============================ */

static int
cidr_compare(const uint8_t cidr1, const uint8_t cidr2)
{
    if (cidr1 > cidr2)
        return 1;
    if (cidr1 < cidr2)
        return -1;
    return 0;
}

static int
ip_addr_compare(int af, const union inet_addr *addr1, const union inet_addr *addr2)
{
    if (af == AF_INET) {
        if (ntohl(addr1->in.s_addr) > ntohl(addr2->in.s_addr))
            return 1;
        if (ntohl(addr1->in.s_addr) < ntohl(addr2->in.s_addr))
            return -1;
        return 0;
    }
    if (af == AF_INET6) {
        int i;
        for (i = 0; i < 16; i++) {
            if (addr1->in6.s6_addr[i] > addr2->in6.s6_addr[i])
                return 1;
            if (addr1->in6.s6_addr[i] < addr2->in6.s6_addr[i])
                return -1;
        }
        return 0;
    }
    return 0;
}

static int
port_compare(const __be16 port1, const __be16 port2)
{
    if (port1 == port2)
        return 0;
    if (port1 < port2)
        return -1;
    return 1;
}

static int
ip_sort_compare(int af, const struct ipset_member *m1, const struct ipset_member *m2)
{
    return ip_addr_compare(af, &m1->addr, &m2->addr);
}

static int
net_sort_compare(int af, const struct ipset_member *m1, const struct ipset_member *m2)
{
    int res;

    res = cidr_compare(m1->cidr, m2->cidr);
    if (res)
        return -1 * res;

    return ip_addr_compare(af, &m1->addr, &m2->addr);
}

static int
ipport_sort_compare(int af, const struct ipset_member *m1, const struct ipset_member *m2)
{
    int res;

    res = ip_sort_compare(af, m1, m2);
    if (res)
        return res;

    return port_compare(m1->port, m2->port);
}

static int
ipportip_sort_compare(int af, const struct ipset_member *m1, const struct ipset_member *m2)
{
    int res;

    res = ip_addr_compare(af, &m1->addr, &m2->addr);
    if (res)
        return res;

    res = port_compare(m1->port, m2->port);
    if (res)
        return res;

    return ip_addr_compare(af, &m1->addr2, &m2->addr2);
}

static int
netport_sort_compare(int af, const struct ipset_member *m1, const struct ipset_member *m2)
{
    int res;

    res = cidr_compare(m1->cidr, m2->cidr);
    if (res)
        return -1 * res;

    res = ip_addr_compare(af, &m1->addr, &m2->addr);
    if (res)
        return res;

    return port_compare(m1->port, m2->port);
}

static int
netportiface_sort_compare(int af, const struct ipset_member *m1, const struct ipset_member *m2)
{
    int res;

    res = cidr_compare(m1->cidr, m2->cidr);
    if (res)
        return -1 * res;

    res = ip_addr_compare(af, &m1->addr, &m2->addr);
    if (res)
        return res;

    res = port_compare(m1->port, m2->port);
    if (res)
        return res;

    return strncmp(m1->iface, m2->iface, IFNAMSIZ);
}

static int
ipportnet_sort_compare(int af, const struct ipset_member *m1, const struct ipset_member *m2)
{
    int res;

    res = ip_addr_compare(af, &m1->addr2, &m2->addr2);
    if (res)
        return res;

    res = cidr_compare(m1->cidr, m2->cidr);
    if (res)
        return -1 * res;

    res = ip_addr_compare(af, &m1->addr, &m2->addr);
    if (res)
        return res;

    return port_compare(m1->port, m2->port);
}

static int
netportnet_sort_compare(int af, const struct ipset_member *m1, const struct ipset_member *m2)
{
    int res;

    res = cidr_compare(m1->cidr, m2->cidr);
    if (res)
        return -1 * res;

    res = cidr_compare(m1->cidr2, m2->cidr2);
    if (res)
        return -1 * res;

    res = ip_addr_compare(af, &m1->addr, &m2->addr);
    if (res)
        return res;

    res = ip_addr_compare(af, &m1->addr2, &m2->addr2);
    if (res)
        return res;

    return port_compare(m1->port, m2->port);
}

static int
netportnetport_sort_compare(int af, const struct ipset_member *m1, const struct ipset_member *m2)
{
    int res;

    res = cidr_compare(m1->cidr, m2->cidr);
    if (res)
        return -1 * res;

    res = cidr_compare(m1->cidr2, m2->cidr2);
    if (res)
        return -1 * res;

    res = ip_addr_compare(af, &m1->addr, &m2->addr);
    if (res)
        return res;

    res = ip_addr_compare(af, &m1->addr2, &m2->addr2);
    if (res)
        return res;

    res = port_compare(m1->port, m2->port);
    if (res)
        return res;

    return port_compare(m1->port2, m2->port2);
}

struct ipset_type types[MAX_TYPE_NUM] = {
    {
        .name = "bitmap:ip",
        .parse = net_parse,
        .check = bitmap_check,
        .dump_header = bitmap_dump_header,
        .dump_member = net_dump_member
    },
    {
        .name = "bitmap:ip,mac",
        .parse = ipmac_parse,
        .check = bitmap_check,
        .dump_header = bitmap_dump_header,
        .dump_member = ipmac_dump_member
    },
    {
        .name = "bitmap:port",
        .parse = port_parse,
        .check = bitmap_check,
        .dump_header = bitmap_dump_header,
        .dump_member = port_dump_member
    },
    {
        .name = "hash:ip",
        .parse = net_parse,
        .check = hash_ip_check,
        .dump_header = hash_dump_header,
        .dump_member = net_dump_member,
        .sort_compare = ip_sort_compare
    },
    {
        .name = "hash:net",
        .parse = net_parse,
        .check = hash_net_check,
        .dump_header = hash_dump_header,
        .dump_member = net_dump_member,
        .sort_compare = net_sort_compare
    },
    {
        .name = "hash:ip,port",
        .parse = ipport_parse,
        .check = hash_ip_check,
        .dump_header = hash_dump_header,
        .dump_member = ipport_dump_member,
        .sort_compare = ipport_sort_compare
    },
    {
        .name = "hash:net,port",
        .parse = netport_parse,
        .check = hash_net_check,
        .dump_header = hash_dump_header,
        .dump_member = netport_dump_member,
        .sort_compare = netport_sort_compare
    },
    {
        .name = "hash:net,port,iface",
        .parse = netportiface_parse,
        .check = hash_net_check,
        .dump_header = hash_dump_header,
        .dump_member = netportiface_dump_member,
        .sort_compare = netportiface_sort_compare
    },
    {
        .name = "hash:ip,port,ip",
        .parse = ipportip_parse,
        .check = hash_ip_check,
        .dump_header = hash_dump_header,
        .dump_member = ipportip_dump_member,
        .sort_compare = ipportip_sort_compare
    },
    {
        .name = "hash:ip,port,net",
        .parse = ipportnet_parse,
        .check = hash_ipnet_check,
        .dump_header = hash_dump_header,
        .dump_member = ipportnet_dump_member,
        .sort_compare = ipportnet_sort_compare
    },
    {
        .name = "hash:net,port,net",
        .parse = ipportip_parse,
        .check = hash_net_check,
        .dump_header = hash_dump_header,
        .dump_member = netportnet_dump_member,
        .sort_compare = netportnet_sort_compare
    },
    {
        .name = "hash:net,port,net,port",
        .parse = netportnetport_parse,
        .check = hash_net_check,
        .dump_header = hash_dump_header,
        .dump_member = netportnetport_dump_member,
        .sort_compare = netportnetport_sort_compare
    }
};

struct dpip_obj dpip_ipset = {
    .name   = "ipset",
    .param  = &param,
    .help   = ipset_help,
    .parse  = ipset_parse,
    .check  = ipset_check,
    .do_cmd = ipset_do_cmd,
};

static void __init dpip_ipset_init(void)
{
    dpip_register_obj(&dpip_ipset);
}

static void __exit dpip_ipset_exit(void)
{
    dpip_unregister_obj(&dpip_ipset);
}
