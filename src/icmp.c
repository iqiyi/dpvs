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
#include <assert.h>
#include "ipv4.h"
#include "icmp.h"
#include "netinet/in.h"
#include "netinet/ip_icmp.h"
#ifdef CONFIG_ICMP_REDIRECT_CORE
#include "netif.h"
#include "scheduler.h"
#include "global_data.h"
#endif

#define ICMP
#define RTE_LOGTYPE_ICMP    RTE_LOGTYPE_USER1

struct icmp_ctrl {
    int (*handler)(struct rte_mbuf *mbuf);
    bool is_error;          /* ICMP error message */
};

#define MAX_ICMP_CTRL       256     /* cannot change */

#ifdef CONFIG_DPVS_ICMP_DEBUG
static void icmp_dump_hdr(const struct rte_mbuf *mbuf)
{
    struct rte_icmp_hdr *ich = rte_pktmbuf_mtod(mbuf, struct rte_icmp_hdr *);
    lcoreid_t lcore = rte_lcore_id();

    fprintf(stderr, "lcore %d port %d icmp type %u code %u id %u seq %u\n",
            lcore, mbuf->port, ich->icmp_type, ich->icmp_code,
            ntohs(ich->icmp_ident), ntohs(ich->icmp_seq_nb));

    return;
}
#endif

static int icmp_echo(struct rte_mbuf *mbuf)
{
    struct rte_ipv4_hdr *iph = MBUF_USERDATA(mbuf, struct rte_ipv4_hdr *, MBUF_FIELD_PROTO);
    struct rte_icmp_hdr *ich = rte_pktmbuf_mtod(mbuf, struct rte_icmp_hdr *);
    uint16_t csum;
    struct flow4 fl4;

    if (ich->icmp_type != RTE_IP_ICMP_ECHO_REQUEST || ich->icmp_code != 0) {
        RTE_LOG(WARNING, ICMP, "%s: not echo-request\n", __func__);
        goto errout;
    }

    if (mbuf_may_pull(mbuf, mbuf->pkt_len) != 0)
        goto errout;

    if (rte_raw_cksum(ich, mbuf->pkt_len) != 0xffff) {
        char sbuf[64], dbuf[64];
        const char *saddr, *daddr;

        saddr = inet_ntop(AF_INET, &iph->src_addr,
                          sbuf, sizeof(sbuf)) ? sbuf : "::";
        daddr = inet_ntop(AF_INET, &iph->dst_addr,
                          dbuf, sizeof(dbuf)) ? dbuf : "::";

        RTE_LOG(WARNING, ICMP, "%s: %s->%s, bad checksum\n",
                __func__, saddr, daddr);
        goto errout;
    }

    ich->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
    /* recalc the checksum */
    ich->icmp_cksum = 0;
    csum = rte_raw_cksum(ich, mbuf->pkt_len);
    ich->icmp_cksum = (csum == 0xffff) ? csum : ~csum;

    memset(&fl4, 0, sizeof(struct flow4));
    fl4.fl4_daddr.s_addr = iph->src_addr;
    fl4.fl4_saddr.s_addr = iph->dst_addr;
    fl4.fl4_oif = netif_port_get(mbuf->port);
    fl4.fl4_proto = IPPROTO_ICMP;
    fl4.fl4_tos = iph->type_of_service;

    return ipv4_xmit(mbuf, &fl4);

errout:
    rte_pktmbuf_free(mbuf);
    return EDPVS_INVPKT;
}

/* cannot reply ICMP error on ICMP error,
 * so all error type must be marked */
static struct icmp_ctrl icmp_ctrls[MAX_ICMP_CTRL] = {
    [ICMP_ECHOREPLY] = {
        .is_error   = true,
    },
    [1] = {
        .is_error = true,
    },
    [2] = {
        .is_error = true,
    },
    [ICMP_DEST_UNREACH] = {
        .is_error   = true,
    },
    [ICMP_SOURCE_QUENCH] = {
        .is_error   = true,
    },
    [ICMP_REDIRECT] = {
        .is_error   = true,
    },
    [6] = {
        .is_error = true,
    },
    [7] = {
        .is_error = true,
    },
    [ICMP_ECHO] = {
        .handler    = icmp_echo,
    },
    [9] = {
        .is_error = true,
    },
    [10] = {
        .is_error = true,
    },
    [ICMP_TIME_EXCEEDED] = {
        .is_error   = true,
    },
    [ICMP_PARAMETERPROB] = {
        .is_error   = true,
    },
    [ICMP_TIMESTAMP] = {
        .is_error   = true,
    },
    [ICMP_TIMESTAMPREPLY] = {
        .is_error   = true,
    },
    [ICMP_INFO_REQUEST] = {
        .is_error   = true,
    },
    [ICMP_INFO_REPLY] = {
        .is_error   = true,
    },
    [ICMP_ADDRESS] = {
        .is_error   = true,
    },
    [ICMP_ADDRESSREPLY] = {
        .is_error   = true,
    },
};

/* @imbuf is input (original) IP packet to trigger ICMP. */
void icmp_send(struct rte_mbuf *imbuf, int type, int code, uint32_t info)
{
    struct route_entry *rt = MBUF_USERDATA(imbuf, struct route_entry *, MBUF_FIELD_ROUTE);
    struct rte_ipv4_hdr *iph = ip4_hdr(imbuf);
    eth_type_t etype = imbuf->packet_type; /* FIXME: use other field ? */
    struct in_addr saddr;
    uint8_t tos;
    struct icmphdr *icmph;
    struct rte_mbuf *mbuf;
    struct flow4 fl4;
    uint16_t csum;
    int room, err;

    /* no replies to physical multicast/broadcast */
    if (etype != ETH_PKT_HOST) {
        RTE_LOG(DEBUG, ICMP, "%s: phy-multi/broadcast.\n", __func__);
        return;
    }

    /* no replies to IP multicast/broadcast. */
    /* FIXME: use route to check if dest is multicast or broadcast.
     * since broadcast is not only ffffffff but in/to network. */
    if (IN_MULTICAST(ntohl(iph->dst_addr))
            || INADDR_BROADCAST == ntohl(iph->dst_addr)) {
        RTE_LOG(DEBUG, ICMP, "%s: multi/broadcast.\n", __func__);
        return;
    }

    /* reply only first fragment. */
    if (iph->fragment_offset & htons(RTE_IPV4_HDR_OFFSET_MASK))
        return;

    if (type > NR_ICMP_TYPES)
        return;

    /* cannot reply ICMP-error to ICMP-error message */
    if (icmp_ctrls[type].is_error) {
        if (iph->next_proto_id == IPPROTO_ICMP) {
            struct icmphdr _oich, *oich; /* original ICMP */

            oich = mbuf_header_pointer(imbuf, ip4_hdrlen(imbuf),
                                       sizeof(_oich), &_oich);

            if (!oich || oich->type > NR_ICMP_TYPES
                    || icmp_ctrls[oich->type].is_error) {
                RTE_LOG(DEBUG, ICMP,
                        "%s: cannot reply error on error.\n", __func__);
                return;
            }
        }
    }

    /* determing source address */
    if (rt && rt->flag & RTF_LOCALIN) { /* original pkt's dest is us ? */
        saddr.s_addr = iph->dst_addr;
    } else {
        /* linux select IP of ingress iface only when param
         * net.ipv4.icmp_errors_use_inbound_ifaddr is true.
         * and by default, this param is false. */
        saddr.s_addr = 0;
    }

    tos = icmp_ctrls[type].is_error ? \
          ((iph->type_of_service & IPTOS_TOS_MASK)
           | IPTOS_PREC_INTERNETCONTROL) : iph->type_of_service;

    memset(&fl4, 0, sizeof(struct flow4));
    fl4.fl4_daddr.s_addr    = iph->src_addr;
    fl4.fl4_saddr           = saddr;
    fl4.fl4_oif             = netif_port_get(imbuf->port);
    fl4.fl4_proto           = IPPROTO_ICMP;
    fl4.fl4_tos             = tos;
    if (!fl4.fl4_oif) {
        RTE_LOG(DEBUG, ICMP, "%s: no output iface.\n", __func__);
        return;
    }

    mbuf = rte_pktmbuf_alloc(fl4.fl4_oif->mbuf_pool);
    if (!mbuf) {
        RTE_LOG(DEBUG, ICMP, "%s: no memory.\n", __func__);
        return;
    }
    mbuf_userdata_reset(mbuf);
    assert(rte_pktmbuf_headroom(mbuf) >= 128); /* for L2/L3 */

    /* prepare ICMP message */
    icmph = (struct icmphdr *)rte_pktmbuf_append(mbuf, sizeof(struct icmphdr));
    if (!icmph) {
        RTE_LOG(DEBUG, ICMP, "%s: no room in mbuf.\n", __func__);
        rte_pktmbuf_free(mbuf);
        return;
    }
    icmph->type = type;
    icmph->code = code;
    icmph->un.gateway = info; /* not good */

    /* copy as much as we can without exceeding 576 (min-MTU) */
    room = fl4.fl4_oif->mtu > 576 ? 576 : fl4.fl4_oif->mtu;
    room -= sizeof(struct rte_ipv4_hdr);
    room -= sizeof(struct icmphdr);

    /* we support only linear mbuf now, use m.data_len
     * instead of m.pkt_len */
    room = imbuf->data_len > room ? room : imbuf->data_len;
    if (rte_pktmbuf_append(mbuf, room) == NULL) {
        RTE_LOG(DEBUG, ICMP, "%s: no room in mbuf.\n", __func__);
        rte_pktmbuf_free(mbuf);
        return;
    }
    memcpy(icmph + 1, iph, room);

    /* recalc the checksum */
    icmph->checksum = 0;
    csum = rte_raw_cksum(icmph, mbuf->pkt_len);
    icmph->checksum = (csum == 0xffff) ? csum : ~csum;

    if ((err = ipv4_xmit(mbuf, &fl4)) != EDPVS_OK)
        RTE_LOG(DEBUG, ICMP, "%s: ipv4_xmit: %s.\n",
                __func__, dpvs_strerror(err));
    return;
}

static int icmp_rcv(struct rte_mbuf *mbuf)
{
    struct rte_ipv4_hdr *iph = MBUF_USERDATA(mbuf, struct rte_ipv4_hdr *, MBUF_FIELD_PROTO);
    struct rte_icmp_hdr *ich;
    struct icmp_ctrl *ctrl;

    if (mbuf_may_pull(mbuf, sizeof(struct rte_icmp_hdr)) != 0)
        goto invpkt;
    ich = rte_pktmbuf_mtod(mbuf, struct rte_icmp_hdr *);

    if (unlikely(!iph)) {
        RTE_LOG(WARNING, ICMP, "%s: no ipv4 header\n", __func__);
        goto invpkt;
    }

#ifdef CONFIG_DPVS_ICMP_DEBUG
    icmp_dump_hdr(mbuf);
#endif

    ctrl = &icmp_ctrls[ich->icmp_type];
    if (ctrl->handler)
        return ctrl->handler(mbuf);
    else
        return EDPVS_KNICONTINUE; /* KNI may like it, don't drop */

invpkt:
    rte_pktmbuf_free(mbuf);
    return EDPVS_INVPKT;
}

static struct inet_protocol icmp_protocol = {
    .handler    = icmp_rcv,
};

#ifdef CONFIG_ICMP_REDIRECT_CORE
static struct rte_ring *icmp_redirect_ring;
#define ICMP_RING_SIZE 2048
lcoreid_t g_icmp_redirect_lcore_id = 0;

static struct dpvs_lcore_job icmp_redirect = {
    .name = "icmp_redirect_proc",
    .type = LCORE_JOB_LOOP,
    .func = icmp_redirect_proc,
    .data = NULL,
};

static int icmp_redirect_init(void)
{
    int ret = 0;
    int socket_id;

    socket_id = rte_socket_id();
    icmp_redirect_ring = rte_ring_create("icmp_redirect_ring", ICMP_RING_SIZE, socket_id, RING_F_SC_DEQ);
    if (icmp_redirect_ring == NULL) {
        rte_panic("create ring:icmp_redirect_ring  failed!\n");
        return EDPVS_NOMEM;
    }

    ret = dpvs_lcore_job_register(&icmp_redirect, LCORE_ROLE_FWD_WORKER);
    if (ret < 0) {
        rte_ring_free(icmp_redirect_ring);
        return ret;
    }

    return EDPVS_OK;
}

int icmp_recv_proc(struct rte_mbuf *mbuf)
{
    int ret = 0;
    ret = rte_ring_enqueue(icmp_redirect_ring, mbuf);
    if (unlikely(-EDQUOT == ret)) {
        RTE_LOG(WARNING, ICMP, "%s: icmp ring quota exceeded\n", __func__);
    }
    else if (ret < 0) {
        RTE_LOG(WARNING, ICMP, "%s: icmp ring enqueue failed\n", __func__);
        rte_pktmbuf_free(mbuf);
    }

    return 0;
}

void icmp_redirect_proc(void *args)
{
    int ret = 0;
    int i = 0;
    lcoreid_t cid;
    struct rte_mbuf *mbufs[NETIF_MAX_PKT_BURST];
    uint16_t nb_rb = 0;
    uint16_t data_off;

    cid = rte_lcore_id();
    if (cid != g_icmp_redirect_lcore_id)
        return;

    nb_rb = rte_ring_dequeue_burst(icmp_redirect_ring, (void**)mbufs, NETIF_MAX_PKT_BURST, NULL);
    if (nb_rb <= 0) {
        return;
    }

    for (i = 0; i < nb_rb; i++) {
        struct rte_mbuf *mbuf = mbufs[i];
        struct netif_port *dev = netif_port_get(mbuf->port);

        /* Remove ether_hdr at the beginning of an mbuf */
        data_off = mbuf->data_off;
        if (unlikely(NULL == rte_pktmbuf_adj(mbuf, sizeof(struct rte_ether_hdr)))) {
            rte_pktmbuf_free(mbuf);
            return;
        }

        ret = INET_HOOK(AF_INET, INET_HOOK_PRE_ROUTING,
                     mbuf, dev, NULL, ipv4_rcv_fin);
        if (ret == EDPVS_KNICONTINUE) {
            if (dev->flag & NETIF_PORT_FLAG_FORWARD2KNI) {
                rte_pktmbuf_free(mbuf);
                return;
            }
            if (likely(NULL != rte_pktmbuf_prepend(mbuf,
                (mbuf->data_off - data_off)))) {
                    kni_ingress(mbuf, dev);
            } else {
                rte_pktmbuf_free(mbuf);
            }
        }
    }

    return;
}
#endif

int icmp_init(void)
{
    int err;

#ifdef CONFIG_ICMP_REDIRECT_CORE
    err = icmp_redirect_init();
    if (err)
        return err;
#endif

    err = ipv4_register_protocol(&icmp_protocol, IPPROTO_ICMP);

    return err;
}

int icmp_term(void)
{
    int err;

    err = ipv4_unregister_protocol(&icmp_protocol, IPPROTO_ICMP);

    return err;
}
