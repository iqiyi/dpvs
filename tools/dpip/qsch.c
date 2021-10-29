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
/**
 * traffic control scheduler of dpip tool.
 * see iproute2 "tc qdisc".
 *
 * raychen@qiyi.com, Aug. 2017, initial.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "conf/common.h"
#include "dpip.h"
#include "sockopt.h"
#include "conf/tc.h"

static void qsch_help(void)
{
    fprintf(stderr,
        "Usage:\n"
        "    dpip qsch { add | del | replace | change | show } dev STRING\n"
        "              [ handle HANDLE ] [ root | ingress | parent HANDLE ]\n"
        "              [ QSCH_KIND [ QOPTIONS ] ]\n"
        "\n"
        "Parameters:\n"
        "    QSCH_KIND := { [b|p]fifo | pfifo_fast | tbf }\n"
        "    QOPTIONS  := { FIFO_OPTS | TBF_OPTS }\n"
        "    FIFO_OPTS := [ limit NUMBER ]\n"
        "    TBF_OPTS  := rate RATE burst BYTES { latency MS | limit BYTES }\n"
        "                 [ peakrate RATE mtu BYTES ]\n"
        "    RATE      := raw bits per-second, and possible followed by\n"
        "                 a SI unit (k, m, g).\n"
        "    MS        := milliseconds.\n"
        );
}

static uint32_t rate_atoi(const char *rate)
{
    char r_buf[64], *p;
    uint64_t r, mul = 1, i;

    if (!rate || !strlen(rate))
        return 0;
    snprintf(r_buf, sizeof(r_buf), "%s", rate);

    p = &r_buf[strlen(r_buf) - 1];
    switch (*p) {
    case 'k':
    case 'K':
        mul = 1000UL;
        *p = '\0';
        break;
    case 'm':
    case 'M':
        mul = 1000000UL;
        *p = '\0';
        break;
    case 'g':
    case 'G':
        mul = 1000000000UL;
        *p = '\0';
        break;
    default:
        break;
    }

    if (!strlen(r_buf))
        return 0;

    for (i = 0; i < strlen(r_buf); i++)
        if (!isdigit(r_buf[i]))
            return 0;

    if (sscanf(r_buf, "%lu", &r) != 1)
        return 0;

    if (r >= 4294967296 || r * mul >= 4294967296)
        return 0;

    return r * mul;
}

static char *rate_itoa(uint32_t rate, char *buf, size_t size)
{
    double r = rate;

    if (rate >= 1000000000UL)
        snprintf(buf, size, "%.2fGbps", r/1000000000);
    else if (rate >= 1000000UL)
        snprintf(buf, size, "%.2fMbps", r/1000000);
    else if (rate >= 1000UL)
        snprintf(buf, size, "%.2fKbps", r/1000);
    else
        snprintf(buf, size, "%ubps", rate);

    return buf;
}

static uint32_t latency_to_limit(const char *latency, uint32_t rate)
{
    int64_t lat = atol(latency); /* ms */

    return (uint32_t)(lat * rate / 1000 / 8);
}

static int qsch_parse(struct dpip_obj *obj, struct dpip_conf *cf)
{
    struct tc_conf *conf = obj->param;
    struct tc_qsch_param *param = &conf->param.qsch;

    memset(param, 0, sizeof(*param));

    while (cf->argc > 0) {
        if (strcmp(CURRARG(cf), "dev") == 0) {
            NEXTARG_CHECK(cf, CURRARG(cf));
            snprintf(conf->ifname, IFNAMSIZ, "%s", CURRARG(cf));
        } else if (strcmp(CURRARG(cf), "handle") == 0) {
            NEXTARG_CHECK(cf, CURRARG(cf));
            param->handle = tc_handle_atoi(CURRARG(cf));
        } else if (strcmp(CURRARG(cf), "root") == 0) {
            param->handle = TC_H_ROOT;
            param->where = TC_H_UNSPEC;
        } else if (strcmp(CURRARG(cf), "ingress") == 0) {
            param->handle = TC_H_INGRESS;
            param->where = TC_H_UNSPEC;
        } else if (strcmp(CURRARG(cf), "parent") == 0) {
            NEXTARG_CHECK(cf, CURRARG(cf));
            param->where = tc_handle_atoi(CURRARG(cf));
        } else if (strcmp(CURRARG(cf), "bfifo") == 0 ||
                   strcmp(CURRARG(cf), "pfifo") == 0 ||
                   strcmp(CURRARG(cf), "pfifo_fast") == 0 ||
                   strcmp(CURRARG(cf), "tbf") == 0) {
            snprintf(param->kind, TCNAMESIZ, "%s", CURRARG(cf));
        } else { /* kind must be set ahead then QOPTIONS */
            if (strcmp(&param->kind[1], "fifo") == 0) {
                if (strcmp(CURRARG(cf), "limit") == 0) {
                    NEXTARG_CHECK(cf, CURRARG(cf));
                    param->qopt.fifo.limit = atoi(CURRARG(cf));
                } else {
                    fprintf(stderr, "invalid option for %s: '%s'\n",
                            param->kind, CURRARG(cf));
                    return EDPVS_INVAL;
                }
            } else if (strcmp(param->kind, "tbf") == 0) {
                if (strcmp(CURRARG(cf), "rate") == 0) {
                    NEXTARG_CHECK(cf, CURRARG(cf));
                    param->qopt.tbf.rate.rate = rate_atoi(CURRARG(cf));
                    if (!param->qopt.tbf.rate.rate) {
                        fprintf(stderr, "invalid rate: '%s'\n", CURRARG(cf));
                        return EDPVS_INVAL;
                    }
                } else if (strcmp(CURRARG(cf), "burst") == 0) {
                    NEXTARG_CHECK(cf, CURRARG(cf));
                    param->qopt.tbf.buffer = atoi(CURRARG(cf));
                } else if (strcmp(CURRARG(cf), "latency") == 0) {
                    NEXTARG_CHECK(cf, CURRARG(cf));

                    if (!param->qopt.tbf.rate.rate) {
                        fprintf(stderr, "latency set before rate ?\n");
                        return EDPVS_INVAL;
                    }

                    param->qopt.tbf.limit = \
                        latency_to_limit(CURRARG(cf),
                                         param->qopt.tbf.rate.rate);
                } else if (strcmp(CURRARG(cf), "limit") == 0) {
                    NEXTARG_CHECK(cf, CURRARG(cf));
                    param->qopt.tbf.limit = atoi(CURRARG(cf));
                } else if (strcmp(CURRARG(cf), "peakrate") == 0) {
                    NEXTARG_CHECK(cf, CURRARG(cf));
                    param->qopt.tbf.peakrate.rate = rate_atoi(CURRARG(cf));
                    if (!param->qopt.tbf.peakrate.rate) {
                        fprintf(stderr, "invalid peakrate: '%s'\n",
                                CURRARG(cf));
                        return EDPVS_INVAL;
                    }
                } else if (strcmp(CURRARG(cf), "mtu") == 0) {
                    NEXTARG_CHECK(cf, CURRARG(cf));
                    param->qopt.tbf.mtu = atoi(CURRARG(cf));
                } else {
                    fprintf(stderr, "invalid option for %s: '%s'\n",
                            param->kind, CURRARG(cf));
                    return EDPVS_INVAL;
                }
            } else if (strcmp(param->kind, "pfifo_fast") == 0) {
                ; // pfifo_fast doesn't have any param
            } else {
                fprintf(stderr, "invalid/miss qsch kind: '%s'\n", param->kind);
                return EDPVS_INVAL;
            }
        }

        NEXTARG(cf);
    }

    return EDPVS_OK;
}

static int qsch_check(const struct dpip_obj *obj, dpip_cmd_t cmd)
{
    const struct tc_conf *conf = obj->param;
    const struct tc_qsch_param *param = &conf->param.qsch;

    if (!strlen(conf->ifname)) {
        fprintf(stderr, "missing device.\n");
        return EDPVS_INVAL;
    }

    switch (cmd) {
    case DPIP_CMD_ADD:
    case DPIP_CMD_REPLACE:
        /* handle 0: is root qdisc for egress */

        if (strcmp(param->kind, "pfifo") == 0 ||
            strcmp(param->kind, "bfifo") == 0) {
            if (!param->qopt.fifo.limit) {
                fprintf(stderr, "missing limit for fifo.\n");
                return EDPVS_INVAL;
            }
        } else if (strcmp(param->kind, "tbf") == 0) {
            if (!param->qopt.tbf.rate.rate) {
                fprintf(stderr, "missing rate for tbf.\n");
                return EDPVS_INVAL;
            }
            if (!param->qopt.tbf.buffer) {
                fprintf(stderr, "missing buffer for tbf.\n");
                return EDPVS_INVAL;
            }
        } else if (strcmp(param->kind, "pfifo_fast") == 0) {
            ;
        } else {
            fprintf(stderr, "invalid qsch kind.\n");
            return EDPVS_INVAL;
        }
        break;

    case DPIP_CMD_DEL:
        if (!param->handle)
            goto missing_handle;
        break;

    case DPIP_CMD_SET:
        if (!param->handle)
            goto missing_handle;

        if (strcmp(param->kind, "pfifo") != 0 &&
            strcmp(param->kind, "bfifo") != 0 &&
            strcmp(param->kind, "tbf") != 0) {
            fprintf(stderr, "qsch kind '%s' doesn't support SET.\n", param->kind);
            return EDPVS_INVAL;
        }
        break;

    case DPIP_CMD_SHOW:
        break;

    default:
        return EDPVS_NOTSUPP;
    }

    return EDPVS_OK;

missing_handle:
    fprintf(stderr, "missing handle.\n");
    return EDPVS_INVAL;
}

static void qsch_dump_stats(const char *prefix, const struct qsch_qstats *qs,
                            const struct qsch_bstats *bs)
{
    printf("%sSent %lu bytes %u pkts "
           "(dropped %u, overlimits %u requeues %u)\n",
           prefix ? : "", bs->bytes, bs->packets,
           qs->drops, qs->overlimits, qs->requeues);
    printf("%sBacklog %u bytes %u pkts\n",
           prefix ? : "", qs->backlog, qs->qlen);
}

static void qsch_dump_param(const char *ifname, const union tc_param *param,
                            bool stats, bool verbose)
{
    char handle[16], where[16], rate[32];
    const struct tc_qsch_param *qsch = &param->qsch;
    int i;

    if (verbose)
        printf("[%02d] ", qsch->cid);

    printf("qsch %s %s dev %s parent %s flags 0x%x cls %d", qsch->kind,
           tc_handle_itoa(qsch->handle, handle, sizeof(handle)), ifname,
           tc_handle_itoa(qsch->where, where, sizeof(where)),
           qsch->flags, qsch->cls_cnt);

    if (strcmp(qsch->kind, "bfifo") == 0 ||
        strcmp(qsch->kind, "pfifo") == 0) {
        printf(" limit %u", qsch->qopt.fifo.limit);
    } else if (strcmp(qsch->kind, "pfifo_fast") == 0) {
        printf(" bands %u priomap", qsch->qopt.prio.bands);
        for (i = 0; i <= TC_PRIO_MAX; i++)
            printf(" %u", qsch->qopt.prio.priomap[i]);
    } else if (strcmp(qsch->kind, "tbf") == 0) {
        const struct tc_tbf_qopt *tbf = &qsch->qopt.tbf;

        printf(" rate %s burst %uB",
               rate_itoa(tbf->rate.rate, rate, sizeof(rate)), tbf->buffer);
        if (tbf->peakrate.rate)
            printf(" peakrate %s minburst %uB",
                   rate_itoa(tbf->peakrate.rate, rate, sizeof(rate)), tbf->mtu);

        printf(" limit %uB", tbf->limit);
    }
    printf("\n");

    if (stats)
        qsch_dump_stats(" ", &qsch->qstats, &qsch->bstats);
}

static int qsch_do_cmd(struct dpip_obj *obj, dpip_cmd_t cmd,
                       struct dpip_conf *conf)
{
    struct tc_conf *tc_conf = obj->param;
    union tc_param *params;
    int err, i;
    size_t size;

    if (conf->stats)
        tc_conf->op_flags |= TC_F_OPS_STATS;

    if (conf->verbose)
        tc_conf->op_flags |= TC_F_OPS_VERBOSE;

    switch (cmd) {
    case DPIP_CMD_ADD:
        return dpvs_setsockopt(SOCKOPT_TC_ADD, tc_conf,
                               sizeof(struct tc_conf));
    case DPIP_CMD_DEL:
        return dpvs_setsockopt(SOCKOPT_TC_DEL, tc_conf,
                               sizeof(struct tc_conf));
    case DPIP_CMD_SET:
        return dpvs_setsockopt(SOCKOPT_TC_CHANGE, tc_conf,
                               sizeof(struct tc_conf));
    case DPIP_CMD_REPLACE:
        return dpvs_setsockopt(SOCKOPT_TC_REPLACE, tc_conf,
                               sizeof(struct tc_conf));
    case DPIP_CMD_SHOW:
        err = dpvs_getsockopt(SOCKOPT_TC_SHOW, tc_conf,
                              sizeof(struct tc_conf), (void **)&params, &size);
        if (err != 0)
            return EDPVS_INVAL;

        if (size < 0 || (size % sizeof(*params)) != 0) {
            fprintf(stderr, "corrupted response.\n");
            dpvs_sockopt_msg_free(params);
            return EDPVS_INVAL;
        }

        for (i = 0; i < size / sizeof(*params); i++)
            qsch_dump_param(tc_conf->ifname, &params[i],
                            conf->stats, conf->verbose);

        dpvs_sockopt_msg_free(params);
        return EDPVS_OK;
    default:
        return EDPVS_NOTSUPP;
    }
}

static struct tc_conf qsch_conf = {
    .obj    = TC_OBJ_QSCH,
};

static struct dpip_obj dpip_qsch = {
    .name   = "qsch",
    .param  = &qsch_conf,
    .help   = qsch_help,
    .parse  = qsch_parse,
    .check  = qsch_check,
    .do_cmd = qsch_do_cmd,
};

static void __init qsch_init(void)
{
    dpip_register_obj(&dpip_qsch);
}

static void __exit qsch_exit(void)
{
    dpip_unregister_obj(&dpip_qsch);
}
