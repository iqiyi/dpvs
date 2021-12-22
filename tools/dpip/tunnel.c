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
/*
 * ip-tunnel control for dpip tool.
 * see iproute2 "ip tunnel".
 *
 * raychen@qiyi.com, Jan 2018, initial.
 */
#include <arpa/inet.h>
#include "conf/common.h"
#include "dpip.h"
#include "sockopt.h"
#include "conf/ip_tunnel.h"

static int addr_atoi(const char *addr, __be32 *ip)
{
    if (strcmp(addr, "any") == 0)
        *ip = htonl(INADDR_ANY);
    else if (inet_pton(AF_INET, addr, ip) <= 0)
        return EDPVS_INVAL;

    return EDPVS_OK;
}

static int ttl_atoi(const char *ttl)
{
    if (strcmp(ttl, "inherit") == 0)
        return 0;
    else
        return atoi(ttl);
}

static uint8_t tos_atoi(const char *tos)
{
    if (strcmp(tos, "inherit") == 0)
        return 0x1;
    else
        return (uint8_t)atoi(tos);
}

static __be32 key_atoi(const char *key)
{
    __be32 k;

    /* DOTTED_QUAD */
    if (inet_pton(AF_INET, key, &k) > 0)
        return k;

    /* NUMBER */
    k = htonl(atoi(key));
    return k;
}

static void tnl_dump_param(const struct ip_tunnel_param *param)
{
    char sip[64], dip[64];

    inet_ntop(AF_INET, &param->iph.saddr, sip, sizeof(sip));
    inet_ntop(AF_INET, &param->iph.daddr, dip, sizeof(dip));

    printf("%s: %4s remote %s local %s ",
           param->ifname, param->kind, dip, sip);

    if (strlen(param->link))
        printf("dev %s ", param->link);

    if (param->iph.ttl)
        printf("ttl %d ", param->iph.ttl);
    else
        printf("ttl inherit ");

    if (param->iph.tos)
        printf("tos 0x%x ", param->iph.tos);

    if (param->i_flags)
        printf("i_flags 0x%x ", ntohs(param->i_flags));
    if (param->o_flags)
        printf("o_flags 0x%x ", ntohs(param->o_flags));
    if (param->i_key)
        printf("i_key 0x%x ", ntohl(param->i_key));
    if (param->o_key)
        printf("o_key 0x%x ", ntohl(param->o_key));

    printf("\n");
}

static void tnl_help(void)
{
    fprintf(stderr,
        "Usage:\n"
        "    dpip tunnel { add | change | del | show } [ NAME ]\n"
        "         [ mode { ipip | gre } ] [ remote ADDR ] [ local ADDR ]\n"
        "         [ [i|o]seq ] [ [i|o]key KEY ] [ [i|o]csum ]\n"
        "         [ ttl TTL ] [ tos TOS ] [ dev PHYS_DEV ]\n"
        "Parameters:\n"
        "    NAME    := STRING\n"
        "    ADDR    := { IP_ADDRESS | any }\n"
        "    TOS     := { 0..255 | inherit }\n"
        "    TTL     := { 1..255 | inherit }\n"
        "    KEY     := { DOTTED_QUAD | NUMBER }\n"
        );
}

static int tnl_parse(struct dpip_obj *obj, struct dpip_conf *cf)
{
    struct ip_tunnel_param *param = obj->param;

    memset(param, 0, sizeof(*param));

    while (cf->argc > 0) {
        if (strcmp(CURRARG(cf), "mode") == 0 ||
            strcmp(CURRARG(cf), "type") == 0 ||
            strcmp(CURRARG(cf), "kind") == 0) {
            NEXTARG_CHECK(cf, CURRARG(cf));
            snprintf(param->kind, sizeof(param->kind), "%s", CURRARG(cf));
        } else if (strcmp(CURRARG(cf), "remote") == 0) {
            NEXTARG_CHECK(cf, CURRARG(cf));
            if (addr_atoi(CURRARG(cf), &param->iph.daddr) != EDPVS_OK) {
                fprintf(stderr, "invalid remote address: `%s'\n", CURRARG(cf));
                return EDPVS_INVAL;
            }
        } else if (strcmp(CURRARG(cf), "local") == 0) {
            NEXTARG_CHECK(cf, CURRARG(cf));
            if (addr_atoi(CURRARG(cf), &param->iph.saddr) != EDPVS_OK) {
                fprintf(stderr, "invalid local address: `%s'\n", CURRARG(cf));
                return EDPVS_INVAL;
            }
        } else if (strcmp(CURRARG(cf), "iseq") == 0) {
            param->i_flags |= TUNNEL_F_SEQ;
        } else if (strcmp(CURRARG(cf), "oseq") == 0) {
            param->o_flags |= TUNNEL_F_SEQ;
        } else if (strcmp(CURRARG(cf), "seq") == 0) {
            param->i_flags |= TUNNEL_F_SEQ;
            param->o_flags |= TUNNEL_F_SEQ;
        } else if (strcmp(CURRARG(cf), "ikey") == 0) {
            NEXTARG_CHECK(cf, CURRARG(cf));
            param->i_flags |= TUNNEL_F_KEY;
            param->i_key = key_atoi(CURRARG(cf));
        } else if (strcmp(CURRARG(cf), "okey") == 0) {
            NEXTARG_CHECK(cf, CURRARG(cf));
            param->o_flags |= TUNNEL_F_KEY;
            param->o_key = key_atoi(CURRARG(cf));
        } else if (strcmp(CURRARG(cf), "key") == 0) {
            NEXTARG_CHECK(cf, CURRARG(cf));
            param->i_flags |= TUNNEL_F_KEY;
            param->o_flags |= TUNNEL_F_KEY;
            param->i_key = param->o_key = key_atoi(CURRARG(cf));
        } else if (strcmp(CURRARG(cf), "icsum") == 0) {
            param->i_flags |= TUNNEL_F_CSUM;
        } else if (strcmp(CURRARG(cf), "ocsum") == 0) {
            param->o_flags |= TUNNEL_F_CSUM;
        } else if (strcmp(CURRARG(cf), "csum") == 0) {
            param->i_flags |= TUNNEL_F_CSUM;
            param->o_flags |= TUNNEL_F_CSUM;
        } else if (strcmp(CURRARG(cf), "ttl") == 0) {
            NEXTARG_CHECK(cf, CURRARG(cf));
            param->iph.ttl = ttl_atoi(CURRARG(cf));
        } else if (strcmp(CURRARG(cf), "tos") == 0) {
            NEXTARG_CHECK(cf, CURRARG(cf));
            param->iph.tos = tos_atoi(CURRARG(cf));
        } else if (strcmp(CURRARG(cf), "dev") == 0) {
            NEXTARG_CHECK(cf, CURRARG(cf));
            snprintf(param->link, sizeof(param->link), "%s", CURRARG(cf));
        } else {
            if (!strlen(param->ifname))
                snprintf(param->ifname, sizeof(param->ifname), "%s", CURRARG(cf));
            else { /* cannot be set more than once */
                fprintf(stderr, "Is `%s' or `%s' garbage ?\n",
                        CURRARG(cf), param->ifname);
                return EDPVS_INVAL;
            }

        }

        NEXTARG(cf);
    }

    if (cf->argc > 0) {
        fprintf(stderr, "too many arguments\n");
        return EDPVS_INVAL;
    }

    return EDPVS_OK;
}

static int tnl_check(const struct dpip_obj *obj, dpip_cmd_t cmd)
{
    const struct ip_tunnel_param *param = obj->param;

    switch (cmd) {
    case DPIP_CMD_ADD:
        if (!strlen(param->kind)) {
            fprintf(stderr, "missing tunnel type.\n");
            return EDPVS_INVAL;
        }
        break;
    case DPIP_CMD_DEL:
    case DPIP_CMD_SET:
    case DPIP_CMD_REPLACE:
        if (!strlen(param->ifname)) {
            fprintf(stderr, "missing tunnel dev name.\n");
            return EDPVS_INVAL;
        }
        break;
    case DPIP_CMD_SHOW:
        break;
    default:
        return EDPVS_NOTSUPP;
    }

    return EDPVS_OK;
}

static int tnl_do_cmd(struct dpip_obj *obj, dpip_cmd_t cmd,
                      struct dpip_conf *conf)
{
    struct ip_tunnel_param *param = obj->param;
    struct ip_tunnel_param *par_list;
    size_t par_size;
    int err, i;

    switch (cmd) {
    case DPIP_CMD_ADD:
        return dpvs_setsockopt(SOCKOPT_TUNNEL_ADD, param, sizeof(*param));
    case DPIP_CMD_DEL:
        return dpvs_setsockopt(SOCKOPT_TUNNEL_DEL, param, sizeof(*param));
    case DPIP_CMD_SET:
        return dpvs_setsockopt(SOCKOPT_TUNNEL_CHANGE, param, sizeof(*param));
    case DPIP_CMD_REPLACE:
        return dpvs_setsockopt(SOCKOPT_TUNNEL_REPLACE, param, sizeof(*param));
    case DPIP_CMD_SHOW:
        err = dpvs_getsockopt(SOCKOPT_TUNNEL_SHOW, param, sizeof(*param),
                              (void **)&par_list, &par_size);
        if (err != 0)
            return EDPVS_INVAL;

        if (par_size < 0 || (par_size % sizeof(*par_list)) != 0) {
            fprintf(stderr, "corrupted response.\n");
            dpvs_sockopt_msg_free(par_list);
            return EDPVS_INVAL;
        }

        for (i = 0; i < par_size / sizeof(*par_list); i++)
            tnl_dump_param(&par_list[i]);

        dpvs_sockopt_msg_free(par_list);
        return EDPVS_OK;
    default:
        return EDPVS_NOTSUPP;
    }
}

static struct ip_tunnel_param tnl_param;

static struct dpip_obj dpip_tnl = {
    .name   = "tunnel",
    .param  = &tnl_param,
    .help   = tnl_help,
    .parse  = tnl_parse,
    .check  = tnl_check,
    .do_cmd = tnl_do_cmd,
};

static void __init tnl_init(void)
{
    dpip_register_obj(&dpip_tnl);
}

static void __exit tnl_exit(void)
{
    dpip_unregister_obj(&dpip_tnl);
}
