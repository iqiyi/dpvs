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
 * IPv4 tunnel commom routines and control plane codes.
 *
 * raychen@qiyi.com, Dec 2017, initial.
 */
#include <assert.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include "list.h"
#include "conf/common.h"
#include "netif.h"
#include "ipv4.h"
#include "icmp.h"
#include "ctrl.h"
#include "ip_tunnel.h"

#define TUNNEL
#define RTE_LOGTYPE_TUNNEL  RTE_LOGTYPE_USER1

#ifndef IPV4_MIN_MTU
#define IPV4_MIN_MTU        68
#endif

static rte_rwlock_t         ip_tunnel_lock;

static struct list_head     ip_tunnel_ops_list;

static int tunnel_register_ops(struct ip_tunnel_ops *new)
{
    struct ip_tunnel_ops *ops;

    assert(new);

    rte_rwlock_write_lock(&ip_tunnel_lock);

    list_for_each_entry(ops, &ip_tunnel_ops_list, list) {
        if (strcmp(ops->kind, new->kind) == 0) {
            rte_rwlock_write_unlock(&ip_tunnel_lock);
            return EDPVS_EXIST;
        }
    }

    list_add_tail(&new->list, &ip_tunnel_ops_list);

    rte_rwlock_write_unlock(&ip_tunnel_lock);
    return EDPVS_OK;
}

static int tunnel_unregister_ops(struct ip_tunnel_ops *ops)
{
    assert(ops);

    rte_rwlock_write_lock(&ip_tunnel_lock);
    list_del(&ops->list);
    rte_rwlock_write_unlock(&ip_tunnel_lock);
    return EDPVS_OK;
}

static struct ip_tunnel_ops *tunnel_find_ops(const char *kind)
{
    struct ip_tunnel_ops *ops;

    rte_rwlock_read_lock(&ip_tunnel_lock);

    list_for_each_entry(ops, &ip_tunnel_ops_list, list) {
        if (strcmp(ops->kind, kind) == 0) {
            rte_rwlock_read_unlock(&ip_tunnel_lock);
            return ops;
        }
    }

    rte_rwlock_read_unlock(&ip_tunnel_lock);
    return NULL;
}

static inline struct hlist_head *
tunnel_hash_head(struct ip_tunnel_tab *tab, __be32 key, __be32 remote)
{
    uint32_t h = (uint32_t)key ^ (uint32_t)remote;
    return &tab->tunnels[h % IP_TNL_HASH_SIZE];
}

static inline void tunnel_clear_rt_cache(struct ip_tunnel *tnl)
{
    if (tnl->rt_cache) {
        route4_put(tnl->rt_cache);
        tnl->rt_cache = NULL;
    }
}

/* linux:ip_tunnel_bind_dev
 * return MTU of tunnel device. */
static int tunnel_bind_dev(struct netif_port *dev)
{
    struct ip_tunnel *tnl = netif_priv(dev);
    const struct iphdr *tiph = &tnl->params.iph;
    struct netif_port *linkdev = NULL;
    int mtu = ETH_DATA_LEN; /* 1500 */
    int t_hlen = tnl->hlen + sizeof(struct iphdr);

    /* guess output device to choose mtu and headroom */
    if (tiph->daddr) {
        struct route_entry *rt;
        struct flow4 fl4 = {
            .fl4_proto          = tiph->protocol,
            .fl4_daddr.s_addr   = tiph->daddr,
            .fl4_saddr.s_addr   = tiph->saddr,
            .fl4_tos            = tiph->tos,
            .fl4_oif            = tnl->link,
        };

        rt = route4_output(&fl4);
        if (rt) {
            linkdev = rt->port;
            route4_put(rt);
        }

        tunnel_clear_rt_cache(tnl);
    }

    if (!linkdev && tnl->link)
        linkdev = tnl->link;

    if (linkdev)
        mtu = linkdev->mtu;

    mtu -= dev->hw_header_len + t_hlen;

    if (mtu < IPV4_MIN_MTU)
        mtu = IPV4_MIN_MTU;

    return mtu;
}

static struct netif_port *tunnel_create(struct ip_tunnel_tab *tab,
                                        const struct ip_tunnel_ops *ops,
                                        const struct ip_tunnel_param *par)
{
    struct netif_port *dev;
    struct ip_tunnel *tnl;
    struct ip_tunnel_param params;
    int err;

    assert(tab && ops && par);
    params = *par; /* may modified */

    if (netif_port_count() >= NETIF_MAX_PORTS) {
        RTE_LOG(ERR, TUNNEL, "%s: exceeding specification limits(%d)",
            __func__, NETIF_MAX_PORTS);
        return NULL;
    }

    /* set ifname template if not assigned. */
    if (!strlen(params.ifname))
        snprintf(params.ifname, IFNAMSIZ, "%s%%d", ops->kind);

    dev = netif_alloc(NETIF_PORT_ID_INVALID, ops->priv_size, params.ifname,
            1, 1, ops->setup);
    if (!dev)
        return NULL;

    /* syn back ifname, it may generated. */
    snprintf(params.ifname, IFNAMSIZ, "%.15s", dev->name);

    tnl = netif_priv(dev);

    INIT_HLIST_NODE(&tnl->hlist);
    tnl->dev = dev;
    tnl->tab = tab;
    tnl->params = params;
    if (strlen(params.link)) {
        tnl->link = netif_port_get_by_name(params.link);
        if (!tnl->link) {
            RTE_LOG(WARNING, TUNNEL, "%s: invalid link device\n", __func__);
            tnl->params.link[0] = '\0';
        }
    }

    dev->type = PORT_TYPE_TUNNEL;
    dev->hw_header_len = 0; /* no l2 header or tunnel,
                               set before tunnel_bind_dev */
    if (tnl->link) {
        dev->flag |= tnl->link->flag;
        rte_ether_addr_copy(&tnl->link->addr, &dev->addr);
    }
    dev->flag |= NETIF_PORT_FLAG_RUNNING; /* XXX */
    dev->flag |= NETIF_PORT_FLAG_NO_ARP;
    dev->flag &= ~NETIF_PORT_FLAG_TX_IP_CSUM_OFFLOAD;
    dev->flag &= ~NETIF_PORT_FLAG_TX_TCP_CSUM_OFFLOAD;
    dev->flag &= ~NETIF_PORT_FLAG_TX_UDP_CSUM_OFFLOAD;
    dev->flag &= ~NETIF_PORT_FLAG_LLDP;

    dev->in_ptr->flags |= IDEV_F_NO_IPV6;

    err = netif_port_register(dev);
    if (err != EDPVS_OK) {
        netif_free(dev);
        return NULL;
    }

    /* set MTU after op_init, need calc tnl->hlen first */
    dev->mtu = tunnel_bind_dev(dev);

    /* insert to table */
    hlist_add_head(&tnl->hlist, tunnel_hash_head(tab, params.i_key,
                                                 params.iph.daddr));
    tab->nb_tnl++;

    return dev;
}

static int tunnel_change(struct netif_port *dev,
                         const struct ip_tunnel_param *params)
{
    struct ip_tunnel *tnl = netif_priv(dev);
    struct netif_port *link;
    assert(dev && dev->type == PORT_TYPE_TUNNEL && params && tnl->tab);

    if (strlen(params->link)) {
        link = netif_port_get_by_name(params->link);
        if (!link)
            return EDPVS_NODEV;

        tnl->link = link;
    }

    tunnel_clear_rt_cache(tnl);

    hlist_del(&tnl->hlist);
    tnl->params = *params; /* FIXME: all params changes ! */
    hlist_add_head(&tnl->hlist, tunnel_hash_head(tnl->tab, params->i_key,
                                                 params->iph.daddr));

    dev->mtu = tunnel_bind_dev(dev);

    if (tnl->tab->ops->change)
        return tnl->tab->ops->change(dev, params);

    return EDPVS_OK;
}

static int tunnel_destroy(struct ip_tunnel_tab *tab, struct netif_port *dev)
{
    struct ip_tunnel *tnl = netif_priv(dev);
    assert(dev && dev->type == PORT_TYPE_TUNNEL);

    hlist_del(&tnl->hlist);
    tab->nb_tnl--;

    if (tab->fb_tunnel_dev == dev)
        tab->fb_tunnel_dev = NULL;

    netif_port_unregister(dev);
    return netif_free(dev);
}

/* linux:ip_tunnel_key_match */
static bool tunnel_key_match(const struct ip_tunnel_param *p,
                             __be16 flags, __be32 key)
{
    if (p->i_flags & TUNNEL_F_KEY) {
        if (flags & TUNNEL_F_KEY)
            return key == p->i_key;
        else
            return false;
    } else {
        return !(flags & TUNNEL_F_KEY);
    }
}

static inline bool tunnel_link_match(struct ip_tunnel *tnl, portid_t port)
{
    if (port == NETIF_PORT_ID_INVALID && !tnl->link)
        return true;
    else if (tnl->link && tnl->link->id == port)
        return true;

    return false;
}

static int tunnel_dump_table(struct ip_tunnel_tab *tab,
                             struct ip_tunnel_param *pars,
                             size_t npar, portid_t link)
{
    int h, cnt = 0;
    struct ip_tunnel *tnl;

    assert(tab && pars);

    for (h = 0; h < IP_TNL_HASH_SIZE; h++) {
        hlist_for_each_entry(tnl, &tab->tunnels[h], hlist) {
            if (cnt >= npar)
                break;

            assert(tnl->dev && tnl->dev->type == PORT_TYPE_TUNNEL);

            if (link != NETIF_PORT_ID_INVALID &&
                !tunnel_link_match(tnl, link))
                continue;

            memcpy(pars + cnt, &tnl->params, sizeof(*pars));
            cnt++;
        }
    }

    return cnt;
}

/* linux:tnl_update_pmtu */
static int tunnel_update_pmtu(struct netif_port *dev, struct rte_mbuf *mbuf,
                              struct route_entry *rt, __be16 df,
                              const struct iphdr *iiph)
{
    struct ip_tunnel *tnl = netif_priv(dev);
    int pkt_size = mbuf->pkt_len - tnl->hlen - dev->hw_header_len;
    int mtu;

    if (df)
        mtu = rt->mtu - dev->hw_header_len - sizeof(struct iphdr) - tnl->hlen;
    else
        mtu = rt->mtu ? : dev->mtu;

    if (mbuf->packet_type == RTE_ETHER_TYPE_IPV4) {
        if ((iiph->frag_off & htons(IP_DF)) && mtu < pkt_size) {
            icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu));
            return EDPVS_FRAG;
        }
    }

    return EDPVS_OK;
}

static int tunnel_xmit(struct rte_mbuf *mbuf, __be32 src, __be32 dst,
                       uint8_t proto, uint8_t tos, uint8_t ttl, __be16 df)
{
    struct iphdr *oiph; /* outter IP header */

    oiph = (struct iphdr *)rte_pktmbuf_prepend(mbuf, sizeof(*oiph));
    if (!oiph) {
        rte_pktmbuf_free(mbuf);
        return EDPVS_NOROOM;
    }

    oiph->version   = 4;
    oiph->ihl       = sizeof(struct iphdr) >> 2;
    oiph->frag_off  = df;
    oiph->protocol  = proto;
    oiph->tos       = tos;
    oiph->daddr     = dst;
    oiph->saddr     = src;
    oiph->ttl       = ttl;
    oiph->id        = ip4_select_id((struct rte_ipv4_hdr *)oiph);

    return ipv4_local_out(mbuf);
}

static int tunnel_so_set(sockoptid_t opt, const void *arg, size_t inlen)
{
    const struct ip_tunnel_param *params = arg;
    struct netif_port *dev;
    struct ip_tunnel *tnl;
    struct ip_tunnel_ops *ops = NULL;
    int err = EDPVS_INVAL;

    assert(params && inlen >= sizeof(*params));

    /* find the tunnel mode first */
    dev = netif_port_get_by_name(params->ifname);
    if (dev) {
        if (dev->type != PORT_TYPE_TUNNEL) {
            RTE_LOG(ERR, TUNNEL, "%s: not tunnel device\n", __func__);
            return EDPVS_INVAL;
        }

        tnl = netif_priv(dev);
        ops = tnl->tab->ops;
    } else if (strlen(params->kind)) {
        ops = tunnel_find_ops(params->kind);
        if (!ops) {
            RTE_LOG(ERR, TUNNEL, "%s: invalid tunnel mode\n", __func__);
            return EDPVS_INVAL;
        }
    }

    if (!ops && (opt == SOCKOPT_TUNNEL_ADD || opt == SOCKOPT_TUNNEL_REPLACE)) {
        RTE_LOG(ERR, TUNNEL, "%s: cannot determine tunnel mode\n", __func__);
        return EDPVS_INVAL;
    }

    if (!dev && (opt == SOCKOPT_TUNNEL_DEL || opt == SOCKOPT_TUNNEL_CHANGE ||
                 opt == SOCKOPT_TUNNEL_REPLACE)) {
        return EDPVS_NOTEXIST;
    }

    rte_rwlock_write_lock(&ip_tunnel_lock);
    switch (opt) {
    case SOCKOPT_TUNNEL_ADD:
        if (dev) {
            err = EDPVS_EXIST;
            break;
        }

        dev = tunnel_create(ops->tab, ops, params);
        err = dev ? EDPVS_OK : EDPVS_RESOURCE;
        break;

    case SOCKOPT_TUNNEL_DEL:
        err = tunnel_destroy(ops->tab, dev);
        break;

    case SOCKOPT_TUNNEL_CHANGE:
        err = tunnel_change(dev, params);
        break;

    case SOCKOPT_TUNNEL_REPLACE:
        err = tunnel_destroy(ops->tab, dev);
        if (err != EDPVS_OK)
            break;

        dev = tunnel_create(ops->tab, ops, params);
        err = dev ? EDPVS_OK : EDPVS_RESOURCE;
        break;

    default:
        err = EDPVS_NOTSUPP;
        break;
    }
    rte_rwlock_write_unlock(&ip_tunnel_lock);

    return err;
}

static int tunnel_so_get(sockoptid_t opt, const void *arg, size_t inlen,
                         void **out, size_t *outlen)
{
    const struct ip_tunnel_param *params = arg;
    struct netif_port *dev, *link = NULL;
    const struct ip_tunnel *tnl;
    struct ip_tunnel_ops *ops;
    struct ip_tunnel_tab *tab;
    struct ip_tunnel_param *tp_arr = NULL;
    size_t tp_cnt = 0; /* number of tunnel param */
    int err = EDPVS_OK;

    assert(params && inlen >= sizeof(*params) && out && outlen);

    rte_rwlock_read_lock(&ip_tunnel_lock);

    /* device name is indicated */
    if (strlen(params->ifname)) {
        dev = netif_port_get_by_name(params->ifname);
        if (!dev) {
            err = EDPVS_NOTEXIST;
            goto out;
        }

        if (dev->type != PORT_TYPE_TUNNEL) {
            RTE_LOG(ERR, TUNNEL, "%s: not tunnel device\n", __func__);
            err = EDPVS_INVAL;
            goto out;
        }
        /* no more check, need we ? */

        tnl = netif_priv(dev);

        tp_cnt = 1;
        tp_arr = rte_malloc(NULL, sizeof(*tp_arr) * tp_cnt, 0);
        if (!tp_arr) {
            err = EDPVS_NOMEM;
            goto out;
        }

        memcpy(tp_arr, &tnl->params, sizeof(*tp_arr));
        goto done;
    }

    if (strlen(params->link))
        link = netif_port_get_by_name(params->link);

    /* for specific table */
    if (strlen(params->kind)) {
        ops = tunnel_find_ops(params->kind);
        if (!ops) {
            RTE_LOG(ERR, TUNNEL, "%s: invalid tunnel mode\n", __func__);
            err = EDPVS_INVAL;
            goto out;
        }
        tab = ops->tab;
        assert(tab);

        /* rte_malloc() do not support 0 size allocate,
         * we cannot return EDPVS_NOMEM for that case. */
        if (!tab->nb_tnl)
            goto done;

        tp_arr = rte_malloc(NULL, sizeof(*tp_arr) * tab->nb_tnl, 0);
        if (!tp_arr) {
            err = EDPVS_NOMEM;
            goto out;
        }

        tp_cnt = tunnel_dump_table(tab, tp_arr, tab->nb_tnl,
                                   link ? link->id : NETIF_PORT_ID_INVALID);
        goto done;
    }

    /* for each table */
    list_for_each_entry(ops, &ip_tunnel_ops_list, list) {
        void *new_ptr;
        size_t size;

        tab = ops->tab;

        /* rte_realloc() do not support 0 size,
         * we cannot return EDPVS_NOMEM. */
        size = sizeof(*tp_arr) * (tab->nb_tnl + tp_cnt);
        if (!size)
            continue;

        /* realloc could be slow, but need optimize ? */
        new_ptr = rte_realloc(tp_arr, size, 0);
        if (!new_ptr) {
            rte_free(tp_arr);
            err = EDPVS_NOMEM;
            goto out;
        }
        tp_arr = new_ptr;

        tp_cnt += tunnel_dump_table(tab, tp_arr + tp_cnt, tab->nb_tnl,
                                    link ? link->id : NETIF_PORT_ID_INVALID);
    }

done:
    *out = tp_arr;
    *outlen = tp_cnt * sizeof(*tp_arr);

out:
    rte_rwlock_read_unlock(&ip_tunnel_lock);

    return err;
}

int ip_tunnel_init_tab(struct ip_tunnel_tab *tab, struct ip_tunnel_ops *ops,
                       const char *fbname)
{
    int i;
    struct ip_tunnel_param params = {};
    assert(tab && ops && fbname);

    for (i = 0; i < NELEMS(tab->tunnels); i++)
        INIT_HLIST_HEAD(&tab->tunnels[i]);

    if (fbname)
        snprintf(params.ifname, IFNAMSIZ, "%s", fbname);
    snprintf(params.kind, IFNAMSIZ, "%s", ops->kind);

#if 0 /* need it ? */
    rte_rwlock_write_lock(&ip_tunnel_lock);
    tab->fb_tunnel_dev = tunnel_create(tab, ops, &params);
    if (!tab->fb_tunnel_dev) {
        RTE_LOG(WARNING, TUNNEL, "%s: fail to create fb dev for %s.\n",
                __func__, ops->kind);
    }
    rte_rwlock_write_unlock(&ip_tunnel_lock);
#endif

    tab->ops = ops;
    ops->tab = tab;
    tunnel_register_ops(ops);

    return EDPVS_OK;
}

int ip_tunnel_term_tab(struct ip_tunnel_tab *tab)
{
    int h;
    struct ip_tunnel *tun;
    struct hlist_node *n;
    assert(tab && tab->ops);

    tunnel_unregister_ops(tab->ops);

    rte_rwlock_write_lock(&ip_tunnel_lock);

    if (tab->fb_tunnel_dev) {
        tunnel_destroy(tab, tab->fb_tunnel_dev);
        tab->fb_tunnel_dev = NULL;
    }

    for (h = 0; h < NELEMS(tab->tunnels); h++) {
        hlist_for_each_entry_safe(tun, n, &tab->tunnels[h], hlist) {
            hlist_del(&tun->hlist);
            tunnel_destroy(tab, tun->dev);
        }
    }

    rte_rwlock_write_unlock(&ip_tunnel_lock);

    return EDPVS_OK;
}

static struct dpvs_sockopts ip_tunnel_sockopts = {
    .version        = SOCKOPT_VERSION,
    .set_opt_min    = SOCKOPT_TUNNEL_ADD,
    .set_opt_max    = SOCKOPT_TUNNEL_REPLACE,
    .set            = tunnel_so_set,
    .get_opt_min    = SOCKOPT_TUNNEL_SHOW,
    .get_opt_max    = SOCKOPT_TUNNEL_SHOW,
    .get            = tunnel_so_get,
};

int ip_tunnel_init(void)
{
    int err;

    rte_rwlock_init(&ip_tunnel_lock);
    INIT_LIST_HEAD(&ip_tunnel_ops_list);

    /* control plane */
    err = sockopt_register(&ip_tunnel_sockopts);
    if (err != EDPVS_OK)
        goto so_fail;

    /*
     * init all ipv4 tunnels.
     */

    if ((err = ipip_init()) != EDPVS_OK)
        goto ipip_fail;

    if ((err = gre_init()) != EDPVS_OK)
        goto gre_fail;

    return EDPVS_OK;

gre_fail:
    ipip_term();
ipip_fail:
    sockopt_unregister(&ip_tunnel_sockopts);
so_fail:
    return err;
}

int ip_tunnel_term(void)
{
    int err;

    err = ipip_term();
    if (err != EDPVS_OK)
        return err;

    err = gre_term();
    if (err != EDPVS_OK)
        return err;

    err = sockopt_unregister(&ip_tunnel_sockopts);
    if (err != EDPVS_OK)
        return err;

    return EDPVS_OK;
}

/* linux:ip_tunnel_lookup */
struct ip_tunnel *ip_tunnel_lookup(struct ip_tunnel_tab *tab,
                                   portid_t link, __be16 flags,
                                   __be32 remote, __be32 local,
                                   __be32 key)
{
    struct hlist_head *head;
    struct ip_tunnel *tnl, *cand = NULL;

    head = tunnel_hash_head(tab, key, remote);

    hlist_for_each_entry(tnl, head, hlist) {
        if (local != tnl->params.iph.saddr ||
            remote != tnl->params.iph.daddr ||
            !(tnl->dev->flag & NETIF_PORT_FLAG_RUNNING))
            continue;

        if (!tunnel_key_match(&tnl->params, flags, key))
            continue;

        if (tunnel_link_match(tnl, link))
            return tnl;
        else
            cand = tnl;
    }

    hlist_for_each_entry(tnl, head, hlist) {
        if (remote != tnl->params.iph.daddr ||
            tnl->params.iph.saddr != 0 ||
            !(tnl->dev->flag & NETIF_PORT_FLAG_RUNNING))
            continue;

        if (!tunnel_key_match(&tnl->params, flags, key))
            continue;

        if (tunnel_link_match(tnl, link))
            return tnl;
        else if (!cand)
            cand = tnl;
    }

    head = tunnel_hash_head(tab, key, 0);

    hlist_for_each_entry(tnl, head, hlist) {
        if ((local != tnl->params.iph.saddr || tnl->params.iph.daddr != 0) &&
            (local != tnl->params.iph.daddr || !IN_MULTICAST(local)))
            continue;

        if (!(tnl->dev->flag & NETIF_PORT_FLAG_RUNNING))
            continue;

        if (!tunnel_key_match(&tnl->params, flags, key))
            continue;

        if (tunnel_link_match(tnl, link))
            return tnl;
        else if (!cand)
            cand = tnl;
    }

    if (flags & TUNNEL_F_NO_KEY)
        goto skip_key_lookup;

    hlist_for_each_entry(tnl, head, hlist) {
        if (tnl->params.i_key != key ||
            tnl->params.iph.saddr != 0 ||
            tnl->params.iph.daddr != 0 ||
            !(tnl->dev->flag & NETIF_PORT_FLAG_RUNNING))
            continue;

        if (tunnel_link_match(tnl, link))
            return tnl;
        else if (!cand)
            cand = tnl;
    }

skip_key_lookup:
    if (cand)
        return cand;

    if (tab->fb_tunnel_dev &&
        tab->fb_tunnel_dev->flag & NETIF_PORT_FLAG_RUNNING)
        return netif_priv(tab->fb_tunnel_dev);

    return NULL;
}

/* linux:ip_tunnel_rcv */
int ip_tunnel_rcv(struct ip_tunnel *tnl, struct ip_tunnel_pktinfo *tpi,
                  struct rte_mbuf *mbuf)
{
    const struct ip_tunnel_param *params = &tnl->params;
    assert(tnl && mbuf);

    if ((!(tpi->flags & TUNNEL_F_CSUM) &&  (params->i_flags & TUNNEL_F_CSUM)) ||
         ((tpi->flags & TUNNEL_F_CSUM) && !(params->i_flags & TUNNEL_F_CSUM))) {
        goto drop;
    }

    if (tnl->params.i_flags & TUNNEL_F_SEQ) {
        if (!(tpi->flags & TUNNEL_F_SEQ) ||
            (tnl->i_seqno && (int32_t)(ntohl(tpi->seq) - tnl->i_seqno) < 0)) {
            goto drop;
        }
        tnl->i_seqno = ntohl(tpi->seq) + 1;
    }

    mbuf->port = tnl->dev->id;

    return netif_rcv(tnl->dev, htons(ETH_P_IP), mbuf);

drop:
    rte_pktmbuf_free(mbuf);
    return EDPVS_DROP;
}

/* linux: ip_tunnel_xmit */
int ip_tunnel_xmit(struct rte_mbuf *mbuf, struct netif_port *dev,
                   const struct iphdr *tiph, uint8_t proto)
{
    struct ip_tunnel    *tnl = netif_priv(dev);
    const struct iphdr  *iiph = NULL; /* inner ip header*/
    struct route_entry  *rt;
    struct flow4        fl4 = {};
    int                 err = EDPVS_DROP;
    uint8_t             tos, ttl;
    bool                connected;
    __be16              df;
    __be32              dip;

    assert(mbuf && dev && tiph);

    if (mbuf->packet_type == RTE_ETHER_TYPE_IPV4)
        iiph = rte_pktmbuf_mtod_offset(mbuf, struct iphdr *, tnl->hlen);

    connected = tiph->daddr != 0;

    dip = tiph->daddr;
    if (!dip) {
        /* TODO: NBMA tunnel */
        RTE_LOG(DEBUG, TUNNEL, "%s: NBMA dev not support\n", __func__);
        err = EDPVS_NOTSUPP;
        goto errout;
    }

    tos = tiph->tos;
    if (tos & 0x1) {
        tos &= ~0x1;
        if (iiph)
            tos = iiph->tos;
        connected = false;
    }

    /* try cache first then route lookup */
    rt = connected ? tnl->rt_cache : NULL;
    if (!rt) {
        /* not connected or no route cache */
        fl4.fl4_proto           = proto;
        fl4.fl4_daddr.s_addr    = dip;
        fl4.fl4_saddr.s_addr    = tiph->saddr;
        fl4.fl4_tos             = tos;
        fl4.fl4_oif             = tnl->link;

        rt = route4_output(&fl4);
        if (!rt) {
            err = EDPVS_NOROUTE;
            goto errout;
        }

        tunnel_clear_rt_cache(tnl);
        tnl->rt_cache = rt;
        /* refer route in tunnel do not put it. */
    }

    if (rt->port == dev)
        goto errout;

    /* refer route in mbuf and this reference will be put later. */
    route4_get(rt);
    MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) = rt;

    err = tunnel_update_pmtu(dev, mbuf, rt, tiph->frag_off, iiph);
    if (err != EDPVS_OK)
        goto errout;

    ttl = tiph->ttl;
    if (!ttl) {
        if (iiph)
            ttl = iiph->ttl;
        else
            ttl = INET_DEF_TTL;
    }

    df = tiph->frag_off;
    if (iiph)
        df |= (iiph->frag_off & htons(IP_DF));

    if (!rt->src.s_addr)
        RTE_LOG(WARNING, TUNNEL, "%s: xmit with no source IP\n", __func__);

    return tunnel_xmit(mbuf, rt->src.s_addr, dip, proto, tos, ttl, df);

errout:
    rte_pktmbuf_free(mbuf);
    return err;
}

int ip_tunnel_pull_header(struct rte_mbuf *mbuf, int hlen, __be16 in_proto)
{
    /* pull inner header */
    if (mbuf_may_pull(mbuf, hlen) != 0)
        return EDPVS_NOROOM;

    if (rte_pktmbuf_adj(mbuf, hlen) == NULL)
        return EDPVS_INVPKT;

    /* clean up vlan info, it should be cleared by vlan module. */
    if (unlikely(mbuf->ol_flags & PKT_RX_VLAN_STRIPPED)) {
        mbuf->vlan_tci = 0;
        mbuf->ol_flags &= (~PKT_RX_VLAN_STRIPPED);
    }

    return EDPVS_OK;
}

int ip_tunnel_dev_init(struct netif_port *dev)
{
    int err;
    struct ip_tunnel *tnl = netif_priv(dev);
    struct inet_device *idev = dev_get_idev(tnl->dev);

    err = idev_addr_init(idev);
    if (err != EDPVS_OK) {
        idev_put(idev);
        return err;
    }

    idev_put(idev);
    return EDPVS_OK;
}

int ip_tunnel_set_mc_list(struct netif_port *dev)
{
    // IP tunnel devices need no hw multicast address,
    // and should always return success

    return EDPVS_OK;
}

int ip_tunnel_get_link(struct netif_port *dev, struct rte_eth_link *link)
{
    struct ip_tunnel *tnl = netif_priv(dev);

    if (tnl->link) {
        return netif_get_link(tnl->link, link);
    } else {
        memset(link, 0, sizeof(*link));
        return EDPVS_OK;
    }
}

int ip_tunnel_get_stats(struct netif_port *dev, struct rte_eth_stats *stats)
{
    struct ip_tunnel *tnl = netif_priv(dev);

    if (tnl->link) {
        return netif_get_stats(tnl->link, stats);
    } else {
        /* TODO: support per-lcore stats */
        memset(stats, 0, sizeof(*stats));
        return EDPVS_OK;
    }
}

int ip_tunnel_get_promisc(struct netif_port *dev, bool *promisc)
{
    struct ip_tunnel *tnl = netif_priv(dev);

    if (tnl->link) {
        return netif_get_promisc(tnl->link, promisc);
    } else {
        *promisc = false;
        return EDPVS_OK;
    }
}

int ip_tunnel_get_allmulticast(struct netif_port *dev, bool *allmulticast)
{
    struct ip_tunnel *tnl = netif_priv(dev);

    if (tnl->link) {
        return netif_get_allmulticast(tnl->link, allmulticast);
    } else {
        *allmulticast = false;
        return EDPVS_OK;
    }
}
