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

#define HEADER_LEN  100
#define MEMBER_LEN  120 

struct ipset_type {
    char *name;
    int (* parse)(char *arg);
    void (* dump_header)(char *buf, struct ipset_info *info);
    int (* dump_member)(char *buf, struct ipset_member *m, int af);
};

// All supported ipset types
#define TYPES   9
struct ipset_type types[TYPES];

static struct ipset_param param;

static char *query_str;

static char *
types_string(void)
{
    char *string;
    int i, len = 0, n = 0;

    for (i = 0; i < NELEMS(types); i++) {
        len += strlen(types[i].name) + strlen(" | ");
    }
    string = malloc(len);
    for (i = 0; i < NELEMS(types); i++) {
        n += sprintf(string + n, "%s | ", types[i].name);
    }
    memset(string + n - 3, 0, 3);

    return string;
}

static void 
ipset_help(void)
{
    char *types = types_string();
    fprintf(stdout, 
                    "Usage:\n"
                    "    dpip ipset { add | del | test } SETNAME ENTRY [ OPTIONS ]\n"
                    "    dpip ipset add SETNAME TYPE [ OPTIONS ]\n"
                    "    dpip ipset del SETNAME -D\n"
                    "    dpip ipset { list | flush } [ SETNAME ]\n"
                    "Parameters:\n"
                    "    TYPE      := { %s }\n"
                    "    ENTRY     := comma seperated of tokens below depending on type,\n"
                    "                 { IP | NET | MAC | PORT | IFACE }\n"
                    "    NET       := \"{ ADDR/CIDR | ADDR[-ADDR] }\"\n"
                    "    MAC       := \"XX:XX:XX:XX:XX:XX\"\n"
                    "    PORT      := \"[tcp|udp:]port[-port2]\"\n"
                    "    OPTIONS   := { comment | range NET | hashsize | maxelem | flag }\n"
                    "    flag      := { -D(--destroy) | -F(--force) | -4|-6 | -v }\n"
                    "Examples:\n"
                    "    dpip ipset add foo bitmap:ip range 192.168.0.0/16 comment\n"
                    "    dpip ipset add foo 192.168.0.1-192.168.0.5 comment \"test entry\"\n"
                    "    dpip ipset add bar hash:net,iface -6 hashsize 300 maxelem 1000\n"
                    "    dpip ipset add bar 2001::beef::/64,udp:100,dpdk0\n"
                    "    dpip ipset test bar 2001:beef::abcd,udp:100,dpdk0 -v\n"
                    "    dpip ipset list [ foo | bar ]\n"
                    "    dpip ipset del foo 192.168.1.1\n"
                    "    dpip ipset del bar -D\n"
                    "    dpip ipset flush foo\n",
                    types
    );
    free(types);
}

/* ========================== parse =========================== */
/* { ip1-ip2 | ip/cidr } */
static int
addr_arg_parse(char *arg, struct inet_addr_range *range, uint8_t *cidr)
{
    char *ip1, *ip2, *sep;
    int *af = &param.option.family;

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
            if (range->max_addr.in.s_addr < range->min_addr.in.s_addr)
                range->max_addr = range->min_addr;
        } else {
            range->max_addr = range->min_addr;
        }
        *af = AF_INET;
    }

    return EDPVS_OK;
}

/* [ tcp | udp | icmp: ]port1[-port2] */
static void
port_arg_parse(char *arg, struct inet_addr_range *range)
{
    char *proto = arg, *sep, *port1, *port2;

    param.proto = IPPROTO_TCP;
    if ((sep = strchr(arg, ':')) != NULL) {
        *sep++ = '\0';
        arg = sep;
        if (!strcmp(proto, "tcp")) {}
        else if (!strcmp(proto, "udp")) {
            param.proto = IPPROTO_UDP;
        } else if (!strcmp(proto, "icmp")) {
            param.proto = IPPROTO_ICMP;
            return;
        }
        else if (!strcmp(proto, "icmp6")) {
            param.proto = IPPROTO_ICMPV6;
            return;
        }
        else {
            fprintf(stderr, "protocol not supported\n");
            exit(1);
        }
    }

    port1 = arg;
    range->max_port = range->min_port = atoi(port1);

    sep = strchr(arg, '-');
    if (sep) {
        *sep++ = '\0';
        port2 = sep;
        range->max_port = atoi(port2);
    }
}

/* option parse */
static inline int 
create_opt_parse(struct dpip_conf *conf)
{
    struct ipset_create_option *opt = &param.option;
    opt->family = conf->af == AF_INET6? AF_INET6 : AF_INET;

    while (conf->argc > 0) {
        /* bitmap type MUST specify range */
        if (!strcmp(CURRARG(conf), "range")) {
            NEXTARG_CHECK(conf, CURRARG(conf));
            if (strstr(param.type, "ip")) {
                if (addr_arg_parse(CURRARG(conf), &param.range, &param.cidr) < 0)
                    return EDPVS_INVAL;
            } else if (strstr(param.type, "port"))
                port_arg_parse(CURRARG(conf), &param.range);
       } else if (!strcmp(CURRARG(conf), "comment")) {
            opt->comment = true;
        } else if (!strcmp(CURRARG(conf), "hashsize")) {
            NEXTARG_CHECK(conf, CURRARG(conf));
            opt->hashsize = atoi(CURRARG(conf));
        } else if (!strcmp(CURRARG(conf), "maxelem")) {
            NEXTARG_CHECK(conf, CURRARG(conf));
            opt->maxelem = atoi(CURRARG(conf));
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
        } else {
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
seg_parse(char *params, int segnum, char **segs)
{
    int i = 0;
    char *start, *sp, *arg;

    for (start = params; (arg = strtok_r(start, ",", &sp)); start = NULL) {
        segs[i] = arg;
        i++;
    }

    if (i != segnum)
        return EDPVS_INVAL;

    return EDPVS_OK;
}

/* ip, mac */
static int
ipmac_parse(char *arg)
{
    int i;
    char *segs[2];
    unsigned int mac[6];

    if (seg_parse(arg, 2, segs) < 0)
        return EDPVS_INVAL;

    if (net_parse(segs[0]) < 0)
        return EDPVS_INVAL;
    
    if (sscanf(segs[1], "%02X:%02X:%02X:%02X:%02X:%02X", 
        &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) < 0) 
        return EDPVS_INVAL;
    
    for (i = 0; i < 6; i++)
        param.mac[i] = mac[i];

    return EDPVS_OK;
}

static int
port_parse(char *arg)
{
    port_arg_parse(arg, &param.range);

    return EDPVS_OK;
}

/* net, port, iface */
static int
netiface_parse(char *arg)
{
    char *segs[3];

    if (seg_parse(arg, 3, segs) < 0)
        return EDPVS_INVAL;
    
    if (addr_arg_parse(segs[0], &param.range, &param.cidr) < 0)
        return EDPVS_INVAL;
    
    port_arg_parse(segs[1], &param.range);

    strncpy(param.iface, segs[2], IFNAMSIZ);

    return EDPVS_OK;
}

static int
ipport_parse(char *arg)
{
    char *segs[2];

    if (seg_parse(arg, 2, segs) < 0)
        return EDPVS_INVAL;
    
    if (addr_arg_parse(segs[0], &param.range, NULL) < 0)
        return EDPVS_INVAL;
    
    port_arg_parse(segs[1], &param.range);

    return EDPVS_OK;
}

static int
ipportip_parse(char *arg)
{
    char *segs[3];

    if (seg_parse(arg, 3, segs) < 0)
        return EDPVS_INVAL;

    if (addr_arg_parse(segs[0], &param.range, NULL) < 0)
        return EDPVS_INVAL;

    port_arg_parse(segs[1], &param.range);

    if (addr_arg_parse(segs[2], &param.range2, NULL) < 0)
        return EDPVS_INVAL;
    
    return EDPVS_OK;
}

static int
netnet_parse(char *arg)
{
    char *segs[4];

    if (seg_parse(arg, 4, segs) < 0)
        return EDPVS_INVAL;

    if (addr_arg_parse(segs[0], &param.range, &param.cidr) < 0)
        return EDPVS_INVAL;

    port_arg_parse(segs[1], &param.range);

    if (addr_arg_parse(segs[2], &param.range2, &param.cidr2) < 0)
        return EDPVS_INVAL;
    
    port_arg_parse(segs[3], &param.range2);

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
get_type_idx(char *type)
{
    int i;

    for (i = 0; i < NELEMS(types); i++) {
        if (!strcmp(types[i].name, type))
            return i;
    }

    return EDPVS_NOTSUPP;
}

static int
get_set_type(void)
{
    struct ipset_info *info;
    struct ipset_info_array *array;

    if (get_info_array(&array) < 0) {
        return EDPVS_NOTEXIST;
    }
    info = &array->infos[0];

    return get_type_idx(info->type);
}

static int 
ipset_parse(struct dpip_obj *obj, struct dpip_conf *conf)
{
    int type_idx;

    /* list all sets */
    if (conf->argc == 0) {
        if (conf->cmd == DPIP_CMD_SHOW)
            return EDPVS_OK;
        else
            return EDPVS_INVAL;
    }

    sprintf(param.name, "%s", CURRARG(conf));
    NEXTARG(conf);

    if (conf->argc == 0) {
        switch (conf->cmd) {
        case DPIP_CMD_FLUSH:
            param.opcode = DPIP_CMD_FLUSH;
            return EDPVS_OK;
        case DPIP_CMD_DEL:
            if (conf->destroy)
                param.opcode = IPSET_OP_DESTROY;
            return EDPVS_OK;
        case DPIP_CMD_SHOW:
            return EDPVS_OK;
        default:
            return EDPVS_INVAL;
        }
    }

    if (get_type_idx(CURRARG(conf)) >= 0)
        goto create;

    /* add/delete/test */
    if ((type_idx = get_set_type()) < 0)
        return EDPVS_INVAL;

    if (conf->verbose) {
        query_str = malloc(strlen(CURRARG(conf) + 1));
        strcpy(query_str, CURRARG(conf));
    }

    /* type specific arg parsing */
    if (types[type_idx].parse(CURRARG(conf)) < 0)
        return EDPVS_INVAL;

    if (conf->cmd == DPIP_CMD_TEST) {
        param.opcode = IPSET_OP_TEST;
        return EDPVS_OK;
    }
    param.opcode = conf->cmd == DPIP_CMD_ADD? IPSET_OP_ADD : IPSET_OP_DEL;

    NEXTARG(conf);

    return add_del_opt_parse(conf);

    /* create */
    create:
        param.opcode = IPSET_OP_CREATE;
        sprintf(param.type, "%s", CURRARG(conf));
        NEXTARG(conf);

        if (create_opt_parse(conf) < 0)
            return EDPVS_INVAL;

    return EDPVS_OK;
}

/* =========================== dump ============================ */

static void
bitmap_dump_header(char *buf, struct ipset_info *info)
{
    char range[50];
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
            sprintf(range, "%d-%d", info->bitmap.range.min_port,
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

static int
net_dump_member(char *buf, struct ipset_member *member, int af)
{
    int n = 0;
    char addr[INET6_ADDRSTRLEN];
    
    inet_ntop(af, &member->addr.in6, addr, INET6_ADDRSTRLEN);
   
    if (member->cidr) {
        n = sprintf(buf, "%s/%d  ", addr, member->cidr);
    } else {
        n = sprintf(buf, "%s  ", addr);
    }

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
   
    n = sprintf(buf, "%s  %02X:%02X:%02X:%02X:%02X:%02X  ", addr,
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    n += dump_comment(buf + n, member->comment);

    return n;
}

static int
port_dump_member(char *buf, struct ipset_member *member, int af)
{
    int n;

    n = sprintf(buf, "%s:%d  ", member->proto == IPPROTO_TCP?
                "tcp" : "udp", member->port);

    n += dump_comment(buf + n, member->comment);

    return n;
}

static int
ipport_dump_member(char *buf, struct ipset_member *member, int af)
{
    int n;
    char addr[INET6_ADDRSTRLEN];

    inet_ntop(af, &member->addr, addr, INET6_ADDRSTRLEN);

    n = sprintf(buf, "%s,%s:%d  ", addr, member->proto == IPPROTO_TCP? 
                "tcp" : "udp", member->port);

    n += dump_comment(buf + n, member->comment);

    return n;
}


static int
netiface_dump_member(char *buf, struct ipset_member *member, int af)
{
    int n;
    char addr[INET6_ADDRSTRLEN], *proto;
    
    inet_ntop(af, &member->addr, addr, INET6_ADDRSTRLEN);

    switch(member->proto) {
        case IPPROTO_TCP:
            proto = "tcp";
            break;
        case IPPROTO_UDP:
            proto = "udp";
            break;
        case IPPROTO_ICMP:
            proto = "icmp";
            break;
        case IPPROTO_ICMPV6:
            proto = "icmp6";
            break;
    }
   
    n = sprintf(buf, "%s/%d,%s:%d,%s  ", addr, member->cidr,
                proto, member->port, member->iface);

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

    n = sprintf(buf, "%s,%s:%d,%s  ", addr, member->proto == IPPROTO_TCP? 
                "tcp" : "udp", member->port, addr2);

    n += dump_comment(buf + n, member->comment);

    return n;
}

static int
netnet_dump_member(char *buf, struct ipset_member *member, int af)
{
    int n;
    char addr[INET6_ADDRSTRLEN], addr2[INET6_ADDRSTRLEN];

    inet_ntop(af, &member->addr, addr, INET6_ADDRSTRLEN);
    inet_ntop(af, &member->addr2, addr2, INET6_ADDRSTRLEN);

    n = sprintf(buf, "%s/%d,%d,%s/%d,%d  ", addr, member->cidr, 
            member->port, addr2, member->cidr2, member->port2);

    n += dump_comment(buf + n, member->comment);

    return n;
}

static void
ipset_info_dump(struct ipset_info *info)
{
    int i, type, n = 0;
    struct ipset_member *member;
    char header[HEADER_LEN], *members; 

    type = get_type_idx(info->type);

    /* header */
    types[type].dump_header(header, info);

    /* members */
    if (info->entries)
        members = malloc(info->entries * MEMBER_LEN);
    else
        members = "";

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
ipset_sockopt_msg_dump(struct ipset_info_array *array)
{
    int i;
    void *ptr;
    struct ipset_info *info;

    ptr = (void *)array + sizeof(*array) + array->nipset * sizeof(*info);
    for (i = 0; i < array->nipset; i++) {
        info = &array->infos[i];
        info->members = ptr;

        ipset_info_dump(info);
        fprintf(stdout, "\n");

        ptr += info->entries * sizeof(struct ipset_member);
    }
}

static int 
ipset_do_cmd(struct dpip_obj *obj, dpip_cmd_t cmd, struct dpip_conf *conf)
{
    int err;

    switch (cmd) {
    case DPIP_CMD_ADD:
    case DPIP_CMD_DEL:
    case DPIP_CMD_FLUSH:
        return dpvs_setsockopt(SOCKOPT_SET_IPSET, &param, sizeof(param));

    case DPIP_CMD_TEST:
        err = dpvs_setsockopt(SOCKOPT_SET_IPSET, &param, sizeof(param));
        if (conf->verbose) {
            if (err < 0)
                fprintf(stdout, "%s is NOT in set %s\n", query_str, param.name);
            else
                fprintf(stdout, "%s is in set %s\n", query_str, param.name);
            free(query_str);
        } else {
            if (err < 0)
                fprintf(stdout, "false\n");
            else
                fprintf(stdout, "true\n");
        }

        return EDPVS_OK;

    case DPIP_CMD_SHOW: {
        struct ipset_info_array *array;

        if (get_info_array(&array) < 0) 
            return EDPVS_INVAL;

        ipset_sockopt_msg_dump(array);

        dpvs_sockopt_msg_free(array);

        return EDPVS_OK;
    }

    default:
        return EDPVS_NOTSUPP;
    }
}

struct ipset_type types[TYPES] = {
    {
        .name = "bitmap:ip",
        .parse = net_parse,
        .dump_header = bitmap_dump_header,
        .dump_member = net_dump_member
    },
    {
        .name = "bitmap:ip,mac",
        .parse = ipmac_parse,
        .dump_header = bitmap_dump_header,
        .dump_member = ipmac_dump_member
    },
    {
        .name = "bitmap:port",
        .parse = port_parse,
        .dump_header = bitmap_dump_header,
        .dump_member = port_dump_member
    },
    {
        .name = "hash:ip",
        .parse = net_parse,
        .dump_header = hash_dump_header,
        .dump_member = net_dump_member
    },
    {
        .name = "hash:net",
        .parse = net_parse,
        .dump_header = hash_dump_header,
        .dump_member = net_dump_member
    },
    {
        .name = "hash:ip,port",
        .parse = ipport_parse,
        .dump_header = hash_dump_header,
        .dump_member = ipport_dump_member
    },
    {
        .name = "hash:net,iface",
        .parse = netiface_parse,
        .dump_header = hash_dump_header,
        .dump_member = netiface_dump_member      
    },
    {
        .name = "hash:ip,port,ip",
        .parse = ipportip_parse,
        .dump_header = hash_dump_header,
        .dump_member = ipportip_dump_member
    },
    {
        .name = "hash:net,net",
        .parse = netnet_parse,
        .dump_header = hash_dump_header,
        .dump_member = netnet_dump_member
    }
};

static int
ipset_check(const struct dpip_obj *obj, dpip_cmd_t cmd)
{
    if (strstr(param.type, "bitmap")) {
        if (strstr(param.type, "ip")) {
            if (param.range.min_addr.in.s_addr == 0 ||
                param.range.max_addr.in.s_addr == 0) {
                fprintf(stderr, "bitmap's IP range MUST be specified\n");
                return EDPVS_INVAL;
            }
        }
        if (strstr(param.type, "port")) {
            if ((param.range.min_port & param.range.max_port) == 0) {
                fprintf(stderr, "bitmap's port range MUST be specified\n");
                return EDPVS_INVAL;
            }
        }
    }
    return EDPVS_OK;
}

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
