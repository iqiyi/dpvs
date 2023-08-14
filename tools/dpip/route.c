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
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "conf/common.h"
#include "dpip.h"
#include "conf/route.h"
#include "conf/route6.h"
#include "linux_ipv6.h"
#include "sockopt.h"

static void route_help(void)
{
    fprintf(stderr,
        "Usage:\n"
        "    dpip route { show | flush | help }\n"
        "    dpip route { add | del | set } ROUTE\n"
        "Parameters:\n"
        "    ROUTE      := PREFIX [ via ADDR ] [ dev IFNAME ] [ OPTIONS ]\n"
        "    PREFIX     := { ADDR/PLEN | ADDR | default }\n"
        "    OPTIONS    := [ SCOPE | mtu MTU | src ADDR | metric NUM ]\n"
        "    SCOPE      := [ scope { host | link | global | NUM } ]\n"
        "Examples:\n"
        "    dpip route show\n"
        "    dpip route add default via 10.0.0.1\n"
        "    dpip route add 172.0.0.0/16 via 172.0.0.3 dev dpdk0\n"
        "    dpip route add 192.168.0.0/24 dev dpdk0\n"
        "    dpip -6 route add ffe1::/128 dev dpdk0\n"
        "    dpip -6 route add 2001:db8:1::/64 via 2001:db8:1::1 dev dpdk0\n"
        "    dpip route del 172.0.0.0/16\n"
        "    dpip route set 172.0.0.0/16 via 172.0.0.1\n"
        "    dpip route flush\n"
        );
}

static const char *proto_itoa(int proto)
{
    struct {
        uint8_t iproto;
        const char *sproto;
    } proto_tab[] = {
        { ROUTE_CF_PROTO_AUTO, "auto" },
        { ROUTE_CF_PROTO_BOOT, "boot" },
        { ROUTE_CF_PROTO_STATIC, "static" },
        { ROUTE_CF_PROTO_RA, "ra" },
        { ROUTE_CF_PROTO_REDIRECT, "redirect" },
    };
    int i;
    static char num[64];

    num[0] = '\0';
    for (i = 0; i < NELEMS(proto_tab); i++) {
        if (proto == proto_tab[i].iproto)
            return proto_tab[i].sproto;
    }

    snprintf(num, sizeof(num), "%d", proto);
    return num;
}

static const char *scope_itoa(int scope)
{
    struct {
        uint8_t iscope;
        const char *sscope;
    } scope_tab[] = {
        { ROUTE_CF_SCOPE_HOST, "host" },
        { ROUTE_CF_SCOPE_KNI, "kni_host"},
        { ROUTE_CF_SCOPE_LINK, "link" },
        { ROUTE_CF_SCOPE_GLOBAL, "global" },
    };
    int i;
    static char num[64];

    num[0] = '\0';
    for (i = 0; i < NELEMS(scope_tab); i++) {
        if (scope == scope_tab[i].iscope)
            return scope_tab[i].sscope;
    }

    snprintf(num, sizeof(num), "%d", scope);
    return num;
}

static const char *flags_itoa(uint32_t flags)
{
    static char flags_buf[64];
    int left = sizeof(flags_buf);

    flags_buf[0] = '\0';

    if (flags & ROUTE_CF_FLAG_ONLINK)
        left -= snprintf(flags_buf + strlen(flags_buf), left, "%s ", "onlink");

    return flags_buf;
}

static void route4_dump(struct dp_vs_route_detail *route)
{
    char dst[64], via[64], src[64];

    int scope;
    if (route->flags & RTF_LOCALIN) {
        scope = ROUTE_CF_SCOPE_HOST;
    } else if (route->flags & RTF_KNI) {
        scope = ROUTE_CF_SCOPE_KNI;
    } else if (route->gateway.addr.in.s_addr == htonl(INADDR_ANY)) {
        scope = ROUTE_CF_SCOPE_LINK;
        route->flags |= ROUTE_CF_FLAG_ONLINK;
    } else {
        scope = ROUTE_CF_SCOPE_GLOBAL;
    }

    printf("%s %s/%d via %s src %s dev %s"
            " mtu %d tos 0 scope %s metric %d proto %s %s\n",
            af_itoa(route->af),
            inet_ntop(route->af, &route->dst.addr.in, dst, sizeof(dst)) ? dst : "::",
            route->dst.plen,
            inet_ntop(route->af, &route->gateway.addr.in, via, sizeof(via)) ? via : "::",
            inet_ntop(route->af, &route->src.addr.in, src, sizeof(src)) ? src : "::",
            route->ifname, route->mtu, scope_itoa(scope),
            route->metric, proto_itoa(0), flags_itoa(route->flags));

    return;
}

static void route6_dump(const struct dp_vs_route6_conf *rt6_cfg)
{
    char dst[64], gateway[64], src[64], scope[32];

    if (rt6_cfg->flags & RTF_KNI)
        snprintf(scope, sizeof(scope), "%s", "kni_host");
    else if (rt6_cfg->flags & RTF_LOCALIN)
        snprintf(scope, sizeof(scope), "%s", "host");
    else if (rt6_cfg->flags & RTF_FORWARD) {
        if (ipv6_addr_any(&rt6_cfg->gateway))
            snprintf(scope, sizeof(scope), "%s", "link");
        else
            snprintf(scope, sizeof(scope), "%s", "global");
    } else
        snprintf(scope, sizeof(scope), "%s", "::");

    if (ipv6_addr_any(&rt6_cfg->dst.addr.in6) && rt6_cfg->dst.plen == 0) {
        snprintf(dst, sizeof(dst), "%s", "default");
        printf("%s %s", af_itoa(AF_INET6), dst);
    } else {
        inet_ntop(AF_INET6, (union inet_addr*)&rt6_cfg->dst.addr, dst, sizeof(dst));
        printf("%s %s/%d", af_itoa(AF_INET6), dst, rt6_cfg->dst.plen);
    }

    if (!ipv6_addr_any(&rt6_cfg->gateway))
        printf(" via %s", inet_ntop(AF_INET6, (union inet_addr*)&rt6_cfg->gateway,
                    gateway, sizeof(gateway)) ? gateway : "::");
    if (!ipv6_addr_any(&rt6_cfg->src.addr.in6))
        printf(" src %s", inet_ntop(AF_INET6, (union inet_addr*)&rt6_cfg->src.addr,
                    src, sizeof(src)) ? src : "::");
    printf(" dev %s", rt6_cfg->ifname);

    if (rt6_cfg->mtu > 0)
        printf(" mtu %d", rt6_cfg->mtu);

    printf(" scope %s", scope);

    printf("\n");
}

static int route4_parse_args(struct dpip_conf *conf,
                            struct dp_vs_route_detail *route)
{
    char *prefix = NULL;
    int scope;

    memset(route, 0, sizeof(*route));
    route->af = conf->af;
    scope = ROUTE_CF_SCOPE_NONE;

    while (conf->argc > 0) {
        if (strcmp(conf->argv[0], "via") == 0) {
            NEXTARG_CHECK(conf, "via");
            if (inet_pton_try((int*)&route->af, conf->argv[0], &route->gateway.addr) <= 0)
                return -1;
        } else if (strcmp(conf->argv[0], "dev") == 0) {
            NEXTARG_CHECK(conf, "dev");
            snprintf(route->ifname, sizeof(route->ifname), "%s", conf->argv[0]);
        } else if (strcmp(conf->argv[0], "mtu") == 0) {
            NEXTARG_CHECK(conf, "mtu");
            route->mtu = atoi(conf->argv[0]);
        } else if (strcmp(conf->argv[0], "scope") == 0) {
            NEXTARG_CHECK(conf, "scope");
            if (strcmp(conf->argv[0], "host") == 0)
                route->flags |= RTF_LOCALIN;
            else if (strcmp(conf->argv[0], "kni_host") == 0)
                route->flags |= RTF_KNI;
            else if (strcmp(conf->argv[0], "link") == 0)
                route->flags |= ROUTE_CF_FLAG_ONLINK;
        } else if (strcmp(conf->argv[0], "src") == 0) {
            NEXTARG_CHECK(conf, "src");
            if (inet_pton_try((int*)&route->af, conf->argv[0], &route->src.addr) <= 0)
                return -1;
        } else if (strcmp(conf->argv[0], "metric") == 0) {
            NEXTARG_CHECK(conf, "metric");
            route->metric = atoi(conf->argv[0]);
        } else if (strcmp(conf->argv[0], "local") == 0) {
            route->flags |= RTF_HOST;
        } else {
            prefix = conf->argv[0];
        }

        NEXTARG(conf);
    }

    if (conf->argc > 0) {
        fprintf(stderr, "too many arguments\n");
        return -1;
    }

    if (conf->cmd == DPIP_CMD_SHOW)
        return 0;

    if (!prefix) {
        fprintf(stderr, "missing prefix\n");
        return -1;
    }

    /* PREFIX */
    if (strcmp(prefix, "default") == 0) {
        memset(&route->dst.addr.in, 0, sizeof(route->dst.addr.in));
        if (route->af == AF_UNSPEC)
            route->af = AF_INET;
    } else {
        char *addr, *plen;

        addr = prefix;
        if ((plen = strchr(addr, '/')) != NULL)
            *plen++ = '\0';

        if (inet_pton_try((int*)&route->af, prefix, &route->dst.addr) <= 0)
            return -1;

        route->dst.plen = plen ? atoi(plen) : 0;
    }

    if (route->af != AF_INET && route->af != AF_INET6) {
        fprintf(stderr, "invalid family.\n");
        return -1;
    }

    /*
     * if scope is not set by user:
     *
     * IF [ @local is set ]; THEN
     *       scope == HOST
     * ELSE IF [ @via is set ]; THEN
     *       scope == GLOBAL
     * ELSE (@via is not set)
     *       scope == LINK
     */
    if (scope == ROUTE_CF_SCOPE_NONE) {
        if (inet_is_addr_any(route->af, &route->gateway.addr)) {
            route->flags |= ROUTE_CF_FLAG_ONLINK; /*ROUTE_CF_FLAG_ONLINK is invalid flags value*/
        } 
        route->flags |= RTF_FORWARD;
    }

    if (!route->dst.plen && (strcmp(prefix, "default") != 0)) {
        if (route->af == AF_INET)
            route->dst.plen = 32;
        else
            route->dst.plen = 128;
    }

    if (conf->verbose)
        route4_dump(route);

    return 0;
}

static int route6_parse_args(struct dpip_conf *conf,
                            struct dp_vs_route6_conf *rt6_cfg)
{
    int af;
    char *prefix = NULL;

    memset(rt6_cfg, 0, sizeof(*rt6_cfg));

    while (conf->argc > 0) {
        if (strcmp(conf->argv[0], "via") == 0) {
            NEXTARG_CHECK(conf, "via");
            if (inet_pton_try(&af, conf->argv[0],
                        (union inet_addr *)&rt6_cfg->gateway) <= 0)
                return -1;
        } else if (strcmp(conf->argv[0], "dev") == 0) {
            NEXTARG_CHECK(conf, "dev");
            snprintf(rt6_cfg->ifname, sizeof(rt6_cfg->ifname), "%s", conf->argv[0]);
        } else if (strcmp(conf->argv[0], "tos") == 0) {
            NEXTARG_CHECK(conf, "tos");
        } else if (strcmp(conf->argv[0], "mtu") == 0) {
            NEXTARG_CHECK(conf, "mtu");
            rt6_cfg->mtu = atoi(conf->argv[0]);
        } else if (strcmp(conf->argv[0], "scope") == 0) {
            NEXTARG_CHECK(conf, "scope");
            if (strcmp(conf->argv[0], "host") == 0)
                rt6_cfg->flags |= RTF_LOCALIN;
            else if (strcmp(conf->argv[0], "kni_host") == 0)
                rt6_cfg->flags |= RTF_KNI;
            else if (strcmp(conf->argv[0], "link") == 0)
                rt6_cfg->flags |= RTF_FORWARD;
            else if (strcmp(conf->argv[0], "global") == 0)
                rt6_cfg->flags |= RTF_FORWARD;
        } else if (strcmp(conf->argv[0], "src") == 0) {
            NEXTARG_CHECK(conf, "src");
            if (inet_pton_try(&af, conf->argv[0],
                        (union inet_addr *)&rt6_cfg->src.addr) <= 0)
                return -1;
        } else if (strcmp(conf->argv[0], "metric") == 0) {
            NEXTARG_CHECK(conf, "metric");
        } else if (strcmp(conf->argv[0], "proto") == 0) {
            NEXTARG_CHECK(conf, "proto");
        } else if (strcmp(conf->argv[0], "onlink") == 0) {
            ;/* on-link is output only */
        } else if (strcmp(conf->argv[0], "local") == 0) {
            rt6_cfg->flags |= RTF_LOCALIN;
        } else {
            prefix = conf->argv[0];
        }

        NEXTARG(conf);
    }

    if ((rt6_cfg->flags & RTF_FORWARD) && (ipv6_addr_any(&rt6_cfg->dst.addr.in6) == 0))
        rt6_cfg->flags |= RTF_DEFAULT;
    if (!(rt6_cfg->flags & (RTF_LOCALIN|RTF_KNI|RTF_FORWARD|RTF_DEFAULT)))
            rt6_cfg->flags |= RTF_FORWARD;

    if (conf->argc > 0) {
        fprintf(stderr, "too many arguments\n");
        return -1;
    }

    if (conf->cmd == DPIP_CMD_SHOW)
        return 0;

    if (!prefix) {
        fprintf(stderr, "missing prefix\n");
        return -1;
    }

    /* PREFIX */
    if (strcmp(prefix, "default") == 0) {
        memset(&rt6_cfg->dst.addr, 0, sizeof(rt6_cfg->dst.addr));
    } else {
        char *addr, *plen;

        addr = prefix;
        if ((plen = strchr(addr, '/')) != NULL)
            *plen++ = '\0';

        if (inet_pton_try(&af, prefix,
                    (union inet_addr*)&rt6_cfg->dst.addr) <= 0)
            return -1;

        rt6_cfg->dst.plen = plen ? atoi(plen) : 0;
    }

    if (!rt6_cfg->dst.plen && (strcmp(prefix, "default") != 0))
        rt6_cfg->dst.plen = 128;

    if (conf->verbose)
        route6_dump(rt6_cfg);

    return 0;
}

static int route4_do_cmd(struct dpip_obj *obj, dpip_cmd_t cmd,
                        struct dpip_conf *conf)
{
    // struct dp_vs_route_conf route;
    struct dp_vs_route_detail route;
    struct dp_vs_route_conf_array *array;
    size_t size, i;
    int err;

    if (route4_parse_args(conf, &route) != 0)
        return EDPVS_INVAL;

    switch (conf->cmd) {
    case DPIP_CMD_ADD:
        return dpvs_setsockopt(SOCKOPT_SET_ROUTE_ADD, &route, sizeof(route));

    case DPIP_CMD_DEL:
        return dpvs_setsockopt(SOCKOPT_SET_ROUTE_DEL, &route, sizeof(route));

    case DPIP_CMD_SET:
        return dpvs_setsockopt(SOCKOPT_SET_ROUTE_SET, &route, sizeof(route));

    case DPIP_CMD_FLUSH:
        return dpvs_setsockopt(SOCKOPT_SET_ROUTE_FLUSH, NULL, 0);

    case DPIP_CMD_SHOW:
        err = dpvs_getsockopt(SOCKOPT_GET_ROUTE_SHOW, &route, sizeof(route),
                              (void **)&array, &size);
        if (err != 0)
            return err;

        if (size < sizeof(*array)
                || size != sizeof(*array) + \
                           array->nroute * sizeof(struct dp_vs_route_detail)) {
            fprintf(stderr, "corrupted response.\n");
            dpvs_sockopt_msg_free(array);
            return EDPVS_INVAL;
        }

        for (i = 0; i < array->nroute; i++)
            route4_dump(&array->routes[i]);

        dpvs_sockopt_msg_free(array);
        return EDPVS_OK;
    default:
        return EDPVS_NOTSUPP;
    }
}

static int route6_do_cmd(struct dpip_obj *obj, dpip_cmd_t cmd,
                         struct dpip_conf *conf)
{
    struct dp_vs_route6_conf rt6_cfg;
    struct dp_vs_route6_conf_array *rt6_arr;
    size_t size, i;
    int err;

    if (route6_parse_args(conf, &rt6_cfg) != 0)
        return EDPVS_INVAL;

    switch (conf->cmd) {
        case DPIP_CMD_ADD:
            rt6_cfg.ops = RT6_OPS_ADD;
            return dpvs_setsockopt(SOCKOPT_SET_ROUTE6_ADD_DEL, &rt6_cfg, sizeof(rt6_cfg));
        case DPIP_CMD_DEL:
            rt6_cfg.ops = RT6_OPS_DEL;
            return dpvs_setsockopt(SOCKOPT_SET_ROUTE6_ADD_DEL, &rt6_cfg, sizeof(rt6_cfg));
        case DPIP_CMD_SET:
            return EDPVS_NOTSUPP;
        case DPIP_CMD_FLUSH:
            rt6_cfg.ops = RT6_OPS_FLUSH;
            return dpvs_setsockopt(SOCKOPT_SET_ROUTE6_FLUSH, &rt6_cfg, sizeof(rt6_cfg));
        case DPIP_CMD_SHOW:
            err = dpvs_getsockopt(SOCKOPT_GET_ROUTE6_SHOW, &rt6_cfg, sizeof(rt6_cfg),
                    (void **)&rt6_arr, &size);
            if (err != 0)
                return err;
            if (size < sizeof(*rt6_arr) ||
                    size != sizeof(*rt6_arr) +
                    rt6_arr->nroute * sizeof(struct dp_vs_route6_conf)) {
                fprintf(stderr, "corrupted response.\n");
                dpvs_sockopt_msg_free(rt6_arr);
                return EDPVS_INVAL;
            }
            for (i = 0; i < rt6_arr->nroute; i++)
                route6_dump(&rt6_arr->routes[i]);

            dpvs_sockopt_msg_free(rt6_arr);
            return EDPVS_OK;

        default:
            return EDPVS_NOTSUPP;
    }

    return EDPVS_OK;
}

static int route_do_cmd(struct dpip_obj *obj, dpip_cmd_t cmd,
                        struct dpip_conf *conf)
{
    switch (conf->af) {
        case AF_UNSPEC:
        case AF_INET:
            return route4_do_cmd(obj, cmd, conf);
        case AF_INET6:
            return route6_do_cmd(obj, cmd, conf);
        default:
            return EDPVS_NOTSUPP;
    }
}

struct dpip_obj dpip_route = {
    .name   = "route",
    .help   = route_help,
    .do_cmd = route_do_cmd,
};

static void __init route_init(void)
{
    dpip_register_obj(&dpip_route);
}

static void __exit route_exit(void)
{
    dpip_unregister_obj(&dpip_route);
}

