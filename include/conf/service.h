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
#ifndef __DPVS_SVC_CONF_H__
#define __DPVS_SVC_CONF_H__

#include <stdint.h>
#include <net/if.h>
#include "inet.h"
#include "conf/match.h"
#include "conf/stats.h"
#include "conf/dest.h"
#include "conf/sockopts.h"

#define DP_VS_SCHEDNAME_MAXLEN      16

/*
 * Virtual Service Flags derived from "linux/ip_vs.h"
 */
#define IP_VS_SVC_F_PERSISTENT          0x0001              /* persistent port */
#define IP_VS_SVC_F_HASHED              0x0002              /* hashed entry */
#define IP_VS_SVC_F_ONEPACKET           0x0004              /* one-packet scheduling */
#define IP_VS_SVC_F_SYNPROXY            0x0008              /* tcp syn-proxy */
#define IP_VS_SVC_F_EXPIRE_QUIESCENT    0x0010              /* expire quiescent sessions quickly */
#define IP_VS_SVC_F_SCHED1              0x0020              /* scheduler flag 1 */
#define IP_VS_SVC_F_SCHED2              0x0040              /* scheduler flag 2 */
#define IP_VS_SVC_F_SCHED3              0x0080              /* scheduler flag 3 */
#define IP_VS_SVC_F_SIP_HASH            0x0100              /* sip hash target */
#define IP_VS_SVC_F_QID_HASH            0x0200              /* quic cid hash target */
#define IP_VS_SVC_F_MATCH               0x0400              /* snat match */
#define IP_VS_SVC_F_QUIC                0x0800              /* quic/h3 protocol */
#define IP_VS_SVC_F_SCHED_SH_FALLBACK   IP_VS_SVC_F_SCHED1  /* SH fallback */
#define IP_VS_SVC_F_SCHED_SH_PORT       IP_VS_SVC_F_SCHED2  /* SH use port */

#define MAX_ARG_LEN    (sizeof(dpvs_service_compat_t) + sizeof(dpvs_dest_compat_t))

/* dest health check types */
#define DEST_HC_NONE                    0x00
#define DEST_HC_PASSIVE                 0x01
#define DEST_HC_TCP                     0x02
#define DEST_HC_UDP                     0x04
#define DEST_HC_SCTP                    0x08
#define DEST_HC_PING                    0x10
#define DEST_HC_MASK_EXTERNAL           0x1e

/* defaults for dest passive health check */
#define DEST_DOWN_NOTICE_DEFAULT        1
#define DEST_UP_NOTICE_DEFAULT          1
#define DEST_DOWN_WAIT_DURATION         3       // 3s
#define DEST_INHIBIT_DURATION_MIN       5       // 5s
#define DEST_INHIBIT_DURATION_MAX       3600    // 1h

#define PROXY_PROTOCOL_VERSION_MASK     0x0F
#define PROXY_PROTOCOL_FLAGS_MASK       0xF0

#define PROXY_PROTOCOL_VERSION(verflag)     ((verflag) & PROXY_PROTOCOL_VERSION_MASK)
#define PROXY_PROTOCOL_FLAGS(verflag)       ((verflag) & PROXY_PROTOCOL_FLAGS_MASK)
#define PROXY_PROTOCOL_IS_INSECURE(verflag) (!!((verflag) & PROXY_PROTOCOL_F_INSECURE))

enum {
    PROXY_PROTOCOL_DISABLE      = 0x00,
    PROXY_PROTOCOL_V1           = 0x01,
    PROXY_PROTOCOL_V2           = 0x02,
    PROXY_PROTOCOL_MAX          = PROXY_PROTOCOL_VERSION_MASK,

    /* The proxy protocol addresses existing in the received mbuf are passed to backends
     * in insecure mode, making the service subject to Source Address Spoofing Attack,
     * but it's useful when multiple proxies exist before the backend. */
    PROXY_PROTOCOL_F_INSECURE   = 0x10,
    PROXY_PROTOCOL_F_MAX        = PROXY_PROTOCOL_FLAGS_MASK,
};

struct dest_check_configs {
    uint8_t types;                  // DEST_HC_*

    /* params for passive dest check */
    uint8_t dest_down_notice_num;   // how many DOWNs detected in `dest_down_wait` before inhibiting the dest
    uint8_t dest_up_notice_num;     // how many notifications sent when UPs detected after inhibitation
    uint8_t dest_down_wait;
    uint16_t dest_inhibit_min;      // the inhibitation duration range [dest_inhibit_min, dest_inhibit_max]
    uint16_t dest_inhibit_max;
};

typedef struct dp_vs_service_compat {
    /*base*/
    int                 af;
    uint8_t             proto;
    uint8_t             proxy_protocol; /* proxy protocol version: DISABLE | V1 | V2 */
    uint16_t            port;
    uint32_t            fwmark;         /* firwall mark of service */
    unsigned            flags;          /* virtual service flags */
    unsigned            timeout;        /* persistent timeout in sec */
    unsigned            conn_timeout;
    uint32_t            netmask;        /* persistent netmask */
    unsigned            bps;
    unsigned            limit_proportion;
    union inet_addr     addr;           /* virtual ip address */
    char                sched_name[DP_VS_SCHEDNAME_MAXLEN];
    
    /*dp_vs_service_user & dp_vs_service_entry*/
    struct dp_vs_match  match;

    /*dp_vs_service_entry*/
    unsigned int        num_dests;
    unsigned int        num_laddrs;
    lcoreid_t           cid;
    lcoreid_t           index;
    struct dp_vs_stats  stats;
    struct dest_check_configs   check_conf;
} dpvs_service_compat_t;

#define dp_vs_service_conf  dp_vs_service_compat
#define dp_vs_service_entry dp_vs_service_compat
#define dp_vs_service_user  dp_vs_service_compat

typedef struct dp_vs_services_front {
    lcoreid_t cid;
    lcoreid_t index;
    uint16_t count;
    dpvs_service_compat_t entrytable[0];
} dpvs_services_front_t;

struct dp_vs_getinfo {
    unsigned int version;
    unsigned int size;
    unsigned int num_services;
    unsigned int num_lcores;
};

static inline bool
dest_check_passive(const struct dest_check_configs *conf) {
    return conf->types & DEST_HC_PASSIVE;
}

static inline bool
dest_check_external(const struct dest_check_configs *conf) {
    return conf->types & DEST_HC_MASK_EXTERNAL;
}

static inline bool
dest_check_down_only(const struct dest_check_configs *conf) {
    return !(conf->dest_inhibit_min
            | conf->dest_inhibit_max | conf->dest_up_notice_num);
}

static inline bool
dest_check_configs_sanity(struct dest_check_configs *conf) {
    bool res = true;
    if (!(dest_check_passive(conf))) {
        return true;
    }
    if (conf->dest_down_notice_num < 1) {
        conf->dest_down_notice_num = DEST_DOWN_NOTICE_DEFAULT;
        res = false;
    }
    if (conf->dest_down_wait < 1) {
        conf->dest_down_wait = DEST_DOWN_WAIT_DURATION;
        res = false;
    }
    if (dest_check_down_only(conf))
        return res;
    if (conf->dest_up_notice_num < 1) {
        conf->dest_up_notice_num = DEST_UP_NOTICE_DEFAULT;
        res = false;
    }
    if (conf->dest_inhibit_min < 1) {
        conf->dest_inhibit_min = DEST_INHIBIT_DURATION_MIN;
        res = false;
    }
    if (conf->dest_inhibit_max < 1) {
        conf->dest_inhibit_max = DEST_INHIBIT_DURATION_MAX;
        res = false;
    }
    if (conf->dest_inhibit_min > conf->dest_inhibit_max) {
        conf->dest_inhibit_min = DEST_INHIBIT_DURATION_MIN;
        conf->dest_inhibit_max = DEST_INHIBIT_DURATION_MAX;
        res = false;
    }
    return res;
};

static inline uint8_t proxy_protocol_type(const char *str) {
    if (!strcasecmp(str, "v1"))
        return PROXY_PROTOCOL_V1;
    if (!strcasecmp(str, "v2"))
        return PROXY_PROTOCOL_V2;
    if (!strcasecmp(str, "v1-insecure"))
        return PROXY_PROTOCOL_V1 | PROXY_PROTOCOL_F_INSECURE;
    if (!strcasecmp(str, "v2-insecure"))
        return PROXY_PROTOCOL_V2 | PROXY_PROTOCOL_F_INSECURE;
    return PROXY_PROTOCOL_DISABLE;
}

static inline const char *proxy_protocol_str(uint8_t type) {
    switch (PROXY_PROTOCOL_VERSION(type)) {
        case PROXY_PROTOCOL_DISABLE:
            return "disable";
        case PROXY_PROTOCOL_V1:
            return PROXY_PROTOCOL_IS_INSECURE(type) ? "v1-insecure" : "v1";
        case PROXY_PROTOCOL_V2:
            return PROXY_PROTOCOL_IS_INSECURE(type) ? "v2-insecure" : "v2";
    }
    return "unknown";
}

#endif /* __DPVS_SVC_CONF_H__ */
