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
 * dpvs VLAN (802.1q) implementation.
 *
 * currently only 802.1q is supported, and may support
 * 802.1ad in the future.
 *
 * raychen@qiyi.com, May 2017, initial.
 */
#include <assert.h>
#include <linux/if_ether.h>
#include "list.h"
#include "netif.h"
#include "netif_addr.h"
#include "kni.h"
#include "ctrl.h"
#include "vlan.h"
#include "conf/vlan.h"

#define VLAN
#define RTE_LOGTYPE_VLAN    RTE_LOGTYPE_USER1

#define this_vlan_stats(vlan)       ((vlan)->lcore_stats[rte_lcore_id()])

static inline bool vlan_id_valid(__be16 id)
{
    return ntohs(id) > 0 && ntohs(id) < VLAN_ID_MAX;
}

static inline int vlan_dev_hash(__be16 proto __rte_unused, __be16 id)
{
    return ntohs(id) & VLAN_ID_MASK;
}

static int alloc_vlan_info(struct netif_port *dev)
{
    struct vlan_info *vinfo;
    int i;

    vinfo = rte_zmalloc(NULL, sizeof(*vinfo), 0);
    if (!vinfo)
        return EDPVS_NOMEM;

    vinfo->vlan_dev_hash = rte_zmalloc(NULL,
                            sizeof(struct hlist_head *) * VLAN_ID_MAX, 0);
    if (!vinfo->vlan_dev_hash) {
        rte_free(vinfo);
        return EDPVS_NOMEM;
    }

    for (i = 0; i < VLAN_ID_MAX; i++)
        INIT_HLIST_HEAD(&vinfo->vlan_dev_hash[i]);

    vinfo->real_dev = dev;
    rte_rwlock_init(&vinfo->vlan_lock);
    rte_atomic32_set(&vinfo->refcnt, 1);
    dev->vlan_info = vinfo;

    return EDPVS_OK;
}

static int vlan_dev_init(struct netif_port *dev)
{
    int err;
    struct inet_device *idev = dev_get_idev(dev);

    err = idev_addr_init(idev);
    if (err != EDPVS_OK) {
        idev_put(idev);
        return err;
    }

    idev_put(idev);
    return EDPVS_OK;
}

static int vlan_xmit(struct rte_mbuf *mbuf, struct netif_port *dev)
{
    struct vlan_dev_priv *vlan = netif_priv(dev);
    struct rte_ether_hdr *ethhdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    unsigned int len;
    int err;

    /**
     * store vlan tag and let real device to handle it.
     * that device may support HW vlan offloading.
     *
     * we do not check real_dev feature and inserting tag here.
     * since it's real_dev's responsibility. furthermore,
     * real_dev may also virtual device inserting tag may performed
     * by most underlying device.
     *
     * see validate_xmit_mbuf() for more info.
     * just as linux:validate_xmit_skb().
     */
    if (ethhdr->ether_type != htons(ETH_P_8021Q)) {
        mbuf->vlan_tci = ntohs(vlan->vlan_id);
        mbuf->ol_flags |= PKT_TX_VLAN_PKT;
    }

    /* hand over it to real device */
    mbuf->port = vlan->real_dev->id;
    len = mbuf->pkt_len;

    err = netif_xmit(mbuf, vlan->real_dev);

    if (likely(err == EDPVS_OK)) {
        this_vlan_stats(vlan).tx_packets++;
        this_vlan_stats(vlan).tx_bytes += len;
    } else {
        this_vlan_stats(vlan).tx_dropped++;
    }

    return err;
}

static int vlan_set_mc_list(struct netif_port *dev)
{
    int err;
    struct vlan_dev_priv *vlan = netif_priv(dev);
    assert(vlan && vlan->real_dev);

    /* we're hoding lock of our dev */

    rte_rwlock_write_lock(&vlan->real_dev->dev_lock);
    err = __netif_mc_sync(vlan->real_dev, dev);
    rte_rwlock_write_unlock(&vlan->real_dev->dev_lock);

    return err;
}

static int vlan_get_queue(struct netif_port *dev, lcoreid_t cid, queueid_t *qid)
{
    struct vlan_dev_priv *vlan = netif_priv(dev);
    assert(vlan && vlan->real_dev);

    return netif_get_queue(vlan->real_dev, cid, qid);
}

static int vlan_get_link(struct netif_port *dev, struct rte_eth_link *link)
{
    struct vlan_dev_priv *vlan = netif_priv(dev);
    assert(vlan && vlan->real_dev);

    return netif_get_link(vlan->real_dev, link);
}

static int vlan_get_promisc(struct netif_port *dev, bool *promisc)
{
    struct vlan_dev_priv *vlan = netif_priv(dev);
    assert(vlan && vlan->real_dev);

    return netif_get_promisc(vlan->real_dev, promisc);
}

static int vlan_get_allmulticast(struct netif_port *dev, bool *allmulticast)
{
    struct vlan_dev_priv *vlan = netif_priv(dev);
    assert(vlan && vlan->real_dev);

    return netif_get_allmulticast(vlan->real_dev, allmulticast);
}

static int vlan_get_stats(struct netif_port *dev, struct rte_eth_stats *stats)
{
    struct vlan_dev_priv *vlan = netif_priv(dev);
    assert(vlan && vlan->real_dev);

    return netif_get_stats(vlan->real_dev, stats);
}

static struct netif_ops vlan_netif_ops = {
    .op_init             = vlan_dev_init,
    .op_xmit             = vlan_xmit,
    .op_set_mc_list      = vlan_set_mc_list,
    .op_get_queue        = vlan_get_queue,
    .op_get_link         = vlan_get_link,
    .op_get_promisc      = vlan_get_promisc,
    .op_get_allmulticast = vlan_get_allmulticast,
    .op_get_stats        = vlan_get_stats,
};

static void vlan_setup(struct netif_port *dev)
{
    dev->netif_ops = &vlan_netif_ops;
    dev->mtu = VLAN_ETH_DATA_LEN;
    dev->hw_header_len = sizeof(struct rte_ether_hdr) + VLAN_HLEN;
}

/* @ifname is optional or vlan dev name will be auto generated. */
int vlan_add_dev(struct netif_port *real_dev, const char *ifname,
                 __be16 vlan_proto, __be16 vlan_id)
{
    int err;
    struct vlan_info *vinfo;
    struct hlist_head *head;
    struct netif_port *dev;
    struct vlan_dev_priv *vlan;
    char name_buf[IFNAMSIZ];

    /* support 802.1q only currently */
    if (!real_dev || vlan_proto != htons(ETH_P_8021Q) || !vlan_id_valid(vlan_id))
        return EDPVS_INVAL;

    /* alloc vlan_info of real_dev when adding first vlan dev */
    if (!real_dev->vlan_info) {
        if ((err = alloc_vlan_info(real_dev)) != EDPVS_OK)
            return err;
    }
    vinfo = real_dev->vlan_info;

    head = &vinfo->vlan_dev_hash[vlan_dev_hash(vlan_proto, vlan_id)];
    rte_rwlock_write_lock(&vinfo->vlan_lock);

    /* already exist ? */
    hlist_for_each_entry(vlan, head, hlist) {
        if (vlan->vlan_proto == vlan_proto && vlan->vlan_id == vlan_id) {
            err = EDPVS_EXIST;
            goto out;
        }
    }

    if (ifname && strlen(ifname) > 0) {
        snprintf(name_buf, sizeof(name_buf), "%s", ifname);
    } else {
        snprintf(name_buf, sizeof(name_buf), "%s.%d", real_dev->name,
                 ntohs(vlan_id));
    }

    /* allocate and register netif device */
    dev = netif_alloc(NETIF_PORT_ID_INVALID, sizeof(struct vlan_dev_priv),
            name_buf, real_dev->nrxq, real_dev->ntxq, vlan_setup);
    if (!dev) {
        err = EDPVS_NOMEM;
        goto out;
    }

    /* inherit features (offloading) and MAC address from real device */
    dev->flag |= real_dev->flag;
    /* XXX: dpdk NIC not support csum offload for VLAN. */
    dev->flag &= ~NETIF_PORT_FLAG_TX_IP_CSUM_OFFLOAD;
    dev->flag &= ~NETIF_PORT_FLAG_TX_TCP_CSUM_OFFLOAD;
    dev->flag &= ~NETIF_PORT_FLAG_TX_UDP_CSUM_OFFLOAD;
    dev->flag &= ~NETIF_PORT_FLAG_LLDP;
    dev->type = PORT_TYPE_VLAN;
    rte_ether_addr_copy(&real_dev->addr, &dev->addr);

    vlan = netif_priv(dev);
    memset(vlan, 0, sizeof(*vlan));
    vlan->vlan_proto = vlan_proto;
    vlan->vlan_id = vlan_id;
    vlan->real_dev = real_dev;
    vlan->dev = dev;

    err = netif_port_register(dev);
    if (err != EDPVS_OK) {
        netif_free(dev);
        goto out;
    }

    err = kni_add_dev(dev, NULL);
    if (err != EDPVS_OK) {
        netif_port_unregister(dev);
        netif_free(dev);
        goto out;
    }

    hlist_add_head(&vlan->hlist, head);
    rte_atomic32_inc(&vinfo->refcnt);
    vinfo->vlan_dev_num++;
    err = EDPVS_OK;

out:
    rte_rwlock_write_unlock(&vinfo->vlan_lock);
    return err;
}

int vlan_del_dev(struct netif_port *real_dev, __be16 vlan_proto,
                 __be16 vlan_id)
{
    struct vlan_info *vinfo;
    struct hlist_head *head;
    struct netif_port *dev = NULL;
    struct vlan_dev_priv *vlan;
    int err;

    if (!real_dev || !vlan_id_valid(vlan_id))
        return EDPVS_INVAL;

    vinfo = real_dev->vlan_info;
    if (!vinfo)
        return EDPVS_NOTEXIST;

    head = &vinfo->vlan_dev_hash[vlan_dev_hash(vlan_proto, vlan_id)];
    rte_rwlock_write_lock(&vinfo->vlan_lock);

    hlist_for_each_entry(vlan, head, hlist) {
        if (vlan->vlan_proto == vlan_proto && vlan->vlan_id == vlan_id) {
            dev = vlan->dev;
            break;
        }
    }

    if (!dev) {
        rte_rwlock_write_unlock(&vinfo->vlan_lock);
        return EDPVS_NOTEXIST;
    }

    err = kni_del_dev(dev);
    if (err != EDPVS_OK) {
        RTE_LOG(WARNING, VLAN, "%s: fail to del kni device: %s\n",
                __func__, dpvs_strerror(err));
    }

    hlist_del(&vlan->hlist);
    vinfo->vlan_dev_num--;
    rte_rwlock_write_unlock(&vinfo->vlan_lock);

    netif_port_unregister(dev);
    netif_free(dev);

    /* just leave it for later use even no more reference. */
    rte_atomic32_dec(&vinfo->refcnt);
    return EDPVS_OK;
}

struct netif_port *vlan_find_dev(const struct netif_port *real_dev,
                                __be16 vlan_proto, __be16 vlan_id)
{
    struct vlan_info *vinfo;
    struct hlist_head *head;
    struct vlan_dev_priv *vlan;

    if (!real_dev || !vlan_id_valid(vlan_id))
        return NULL;

    vinfo = real_dev->vlan_info;
    if (!vinfo)
        return NULL;

    head = &vinfo->vlan_dev_hash[vlan_dev_hash(vlan_proto, vlan_id)];
    rte_rwlock_read_lock(&vinfo->vlan_lock);

    hlist_for_each_entry(vlan, head, hlist) {
        if (vlan->vlan_proto == vlan_proto && vlan->vlan_id == vlan_id) {
            rte_rwlock_read_unlock(&vinfo->vlan_lock);
            return vlan->dev;
        }
    }

    rte_rwlock_read_unlock(&vinfo->vlan_lock);
    return NULL;
}

/**
 * invoke this function before ether_header "stripped".
 *
 * vlan must be handled before netif_deliver_mbuf().
 * because netif_deliver_mbuf() remember the m.data_off and
 * restore it if mbuf should be deliver to KNI device.
 * if vlan tag stripped the m.data_off remembered will be wrong.
 */
static inline int vlan_untag_mbuf(struct rte_mbuf *mbuf)
{
    struct vlan_ethhdr *vehdr = NULL;

    /* VLAN RX offloaded (vlan stripped by HW) ? */
    if (mbuf->ol_flags & PKT_RX_VLAN_STRIPPED)
        return EDPVS_OK;

    if (unlikely(mbuf_may_pull(mbuf, sizeof(struct rte_ether_hdr) + \
                                     sizeof(struct rte_vlan_hdr)) != 0))
        return EDPVS_INVPKT;

    /* the data_off of mbuf is still at ethernet header. */
    vehdr = rte_pktmbuf_mtod(mbuf, struct vlan_ethhdr *);

    mbuf->ol_flags |= PKT_RX_VLAN_STRIPPED; /* "borrow" it */
    mbuf->vlan_tci = ntohs(vehdr->h_vlan_TCI);

    /* strip the vlan header */
    memmove((void *)vehdr + VLAN_HLEN, vehdr, 2 * ETH_ALEN);
    rte_pktmbuf_adj(mbuf, VLAN_HLEN);
    mbuf->l2_len = sizeof(*vehdr) - VLAN_HLEN;
    return EDPVS_OK;
}

/*
 * invoke this function before ether_header "stripped".
 * see vlan_untag_mbuf() for reason, and ether header is used.
 *
 * so we don't register pkt_type{} for vlan_rcv().
 */
int vlan_rcv(struct rte_mbuf *mbuf, struct netif_port *real_dev)
{
    struct netif_port *dev;
    struct vlan_dev_priv *vlan;
    struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    int err;

    err = vlan_untag_mbuf(mbuf);
    if (unlikely(err != EDPVS_OK))
        return err;

    dev = vlan_find_dev(real_dev, htons(ETH_P_8021Q),
                        mbuf_vlan_tag_get_id(mbuf));
    if (!dev)
        return EDPVS_NODEV;

    mbuf->port = dev->id;
    if (unlikely(mbuf->packet_type == ETH_PKT_OTHERHOST)) {
        /* as comments in linux:vlan_do_receive().
         * "Our lower layer thinks this is not local, let's make sure.
         * This allows the VLAN to have a different MAC than the
         * underlying device, and still route correctly." */
        if (eth_addr_equal(&ehdr->d_addr, &dev->addr))
            mbuf->packet_type = ETH_PKT_HOST;
    }

    mbuf->ol_flags &= (~PKT_RX_VLAN_STRIPPED);
    mbuf->vlan_tci = 0;

    /* statistics */
    vlan = netif_priv(dev);
    this_vlan_stats(vlan).rx_packets++;
    this_vlan_stats(vlan).rx_bytes += mbuf->pkt_len;
    if (mbuf->packet_type == ETH_PKT_MULTICAST)
        this_vlan_stats(vlan).rx_multicast++;

    return EDPVS_OK;
}

/**
 * control plane
 */
/* XXX: waiting netif to add control plane hooks for different virtual devices.
 * so that we do not need register sockopt by ourself. */

static int vlan_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
    const struct vlan_param *param = conf;
    struct netif_port *real_dev = NULL, *dev;
    struct vlan_dev_priv *vlan;

    if (!conf || size < sizeof(*param))
        return EDPVS_INVAL;

    if (opt == SOCKOPT_SET_VLAN_ADD ||
            (opt == SOCKOPT_SET_VLAN_DEL && !strlen(param->ifname))) {

        real_dev = netif_port_get_by_name(param->real_dev);
        if (!real_dev) {
            RTE_LOG(WARNING, VLAN, "%s: no such real device\n", __func__);
            return EDPVS_NODEV;
        }

        if (param->vlan_proto != ETH_P_8021Q) {
            RTE_LOG(WARNING, VLAN, "%s: support 802.1q only\n", __func__);
            return EDPVS_INVAL;
        }

        if (!vlan_id_valid(htons(param->vlan_id))) {
            RTE_LOG(WARNING, VLAN, "%s: invlid vlan ID\n", __func__);
            return EDPVS_INVAL;
        }
    }

    switch (opt) {
    case SOCKOPT_SET_VLAN_ADD:
        if (strlen(param->ifname) > 0) {
            if (netif_port_get_by_name(param->ifname) != NULL)
                return EDPVS_EXIST;
        }

        return vlan_add_dev(real_dev, param->ifname,
                            htons(param->vlan_proto), htons(param->vlan_id));

    case SOCKOPT_SET_VLAN_DEL:
        if (strlen(param->ifname) > 0) { /* delete by vlan dev name */
            dev = netif_port_get_by_name(param->ifname);
            if (!dev || dev->netif_ops != &vlan_netif_ops)
                return EDPVS_NOTEXIST;

            vlan = netif_priv(dev);

            return vlan_del_dev(vlan->real_dev,
                                vlan->vlan_proto, vlan->vlan_id);
        }

        return vlan_del_dev(real_dev, htons(param->vlan_proto),
                            htons(param->vlan_id));
    default:
        return EDPVS_NOTSUPP;
    }
}

/**
 * TODO: use msg to fetch per-lcore stats.
 */
static int vlan_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
                            void **out, size_t *outsize)
{
    const struct vlan_param *param = conf;
    struct vlan_param_array *array;
    struct netif_port *real_dev, *dev;
    struct vlan_info *vinfo;
    struct vlan_dev_priv *vlan;
    int i;

    if (!conf || size < sizeof(*param) || !out || !outsize)
        return EDPVS_INVAL;

    if (opt != SOCKOPT_GET_VLAN_SHOW)
        return EDPVS_NOTSUPP;

    if (strlen(param->ifname) > 0) {
        dev = netif_port_get_by_name(param->ifname);
        if (!dev) {
            RTE_LOG(WARNING, VLAN, "%s: no such device\n", __func__);
            return EDPVS_NODEV;
        }

        if (dev->netif_ops != &vlan_netif_ops) { /* good way ? */
            RTE_LOG(WARNING, VLAN, "%s: not vlan device\n", __func__);
            return EDPVS_INVAL;
        }

        vlan = netif_priv(dev);

        *outsize = sizeof(struct vlan_param_array) + sizeof(struct vlan_param);
        array = *out = rte_calloc(NULL, 1, *outsize, 0);
        if (!array)
            return EDPVS_NOMEM;

        array->nparam = 1;

        snprintf(array->params[0].real_dev, IFNAMSIZ, "%s", vlan->real_dev->name);
        snprintf(array->params[0].ifname, IFNAMSIZ, "%s", vlan->dev->name);
        array->params[0].vlan_proto = ntohs(vlan->vlan_proto);
        array->params[0].vlan_id = ntohs(vlan->vlan_id);
        return EDPVS_OK;
    }

    real_dev = netif_port_get_by_name(param->real_dev);
    if (!real_dev) {
        RTE_LOG(WARNING, VLAN, "%s: no such device (master)\n", __func__);
        return EDPVS_NODEV;
    }

    vinfo = real_dev->vlan_info;
    if (!vinfo) {
        *outsize = sizeof(struct vlan_param_array);
        array = *out = rte_calloc(NULL, 1, *outsize, 0);
        if (!array)
            return EDPVS_NOMEM;

        array->nparam = 0;
        return EDPVS_OK;
    }

    rte_rwlock_read_lock(&vinfo->vlan_lock);

    *outsize = sizeof(struct vlan_param_array) + \
               vinfo->vlan_dev_num * sizeof(struct vlan_param);
    array = *out = rte_calloc(NULL, 1, *outsize, 0);
    if (!array) {
        rte_rwlock_read_unlock(&vinfo->vlan_lock);
        return EDPVS_NOMEM;
    }

    for (i = 0; i < VLAN_ID_MAX; i++) {
        hlist_for_each_entry(vlan, &vinfo->vlan_dev_hash[i], hlist) {
            struct vlan_param *outparam;

            if (array->nparam >= vinfo->vlan_dev_num)
                goto end;

            outparam = &array->params[array->nparam];

            if (param->vlan_proto &&
                param->vlan_proto != ntohs(vlan->vlan_proto))
                continue;
            if (param->vlan_id && param->vlan_id != ntohs(vlan->vlan_id))
                continue;

            snprintf(outparam->real_dev, IFNAMSIZ, "%s", real_dev->name);
            snprintf(outparam->ifname, IFNAMSIZ, "%s", vlan->dev->name);
            outparam->vlan_proto = ntohs(vlan->vlan_proto);
            outparam->vlan_id = ntohs(vlan->vlan_id);

            array->nparam++;
        }
    }

end:
    rte_rwlock_read_unlock(&vinfo->vlan_lock);
    return EDPVS_OK;
}

static struct dpvs_sockopts vlan_sockopts = {
    .version        = SOCKOPT_VERSION,
    .set_opt_min    = SOCKOPT_SET_VLAN_ADD,
    .set_opt_max    = SOCKOPT_SET_VLAN_DEL,
    .set            = vlan_sockopt_set,
    .get_opt_min    = SOCKOPT_GET_VLAN_SHOW,
    .get_opt_max    = SOCKOPT_GET_VLAN_SHOW,
    .get            = vlan_sockopt_get,
};

int vlan_init(void)
{
    int err;

    err = sockopt_register(&vlan_sockopts);
    if (err != EDPVS_OK)
        return err;

    return EDPVS_OK;
}
