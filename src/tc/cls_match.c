/**
 * "match" classifier for traffic control module.
 *
 * Lei Chen <raychen@qiyi.com>, Aug. 2017, initial.
 */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "netif.h"
#include "match.h"
#include "vlan.h"
#include "tc/tc.h"
#include "tc/sch.h"
#include "tc/cls.h"

struct match_cls_priv {
    struct tc_cls           *cls;

    uint8_t                 proto;      /* IPPROTO_XXX */
    struct dp_vs_match      match;

    struct tc_cls_result    result;
};

static int match_classify(struct tc_cls *cls, struct rte_mbuf *mbuf,
                          struct tc_cls_result *result)
{
    struct match_cls_priv *priv = tc_cls_priv(cls);
    struct dp_vs_match *m = &priv->match;
    struct ether_hdr *eh = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    struct iphdr *iph;
    struct tcphdr *th;
    struct udphdr *uh;
    int offset = sizeof(*eh);
    __be16 pkt_type = eh->ether_type;
    __be16 sport, dport;
    struct netif_port *idev, *odev;
    struct vlan_ethhdr *veh;

    idev = netif_port_get_by_name(m->iifname);
    odev = netif_port_get_by_name(m->oifname);

    /* check input device for ingress */
    if (idev && (cls->sch->flags & QSCH_F_INGRESS)) {
        if (idev->id != mbuf->port)
            return TC_ACT_RECLASSIFY;
    }

    /* check output device for egress */
    if (odev && !(cls->sch->flags & QSCH_F_INGRESS)) {
        if (odev->id != mbuf->port)
            return TC_ACT_RECLASSIFY;
    }

    /* support IPv4 and 802.1q/IPv4 */
l2parse:
    switch (ntohs(pkt_type)) {
    case ETH_P_IP:
        if (mbuf_may_pull(mbuf, offset + sizeof(struct iphdr)) != 0)
            return TC_ACT_SHOT;

        iph = rte_pktmbuf_mtod_offset(mbuf, struct iphdr *, offset);

        /* check if source/dest IP in range */
        if (m->srange.max_addr.in.s_addr != htonl(INADDR_ANY)) {
            if (ntohl(iph->saddr) < ntohl(m->srange.min_addr.in.s_addr) ||
                ntohl(iph->saddr) > ntohl(m->srange.max_addr.in.s_addr))
                return TC_ACT_RECLASSIFY;
        }

        if (m->drange.max_addr.in.s_addr != htonl(INADDR_ANY)) {
            if (ntohl(iph->daddr) < ntohl(m->drange.min_addr.in.s_addr) ||
                ntohl(iph->daddr) > ntohl(m->drange.max_addr.in.s_addr))
                return TC_ACT_RECLASSIFY;
        }

        offset += (iph->ihl << 2);
        break;

    case ETH_P_8021Q:
        veh = (struct vlan_ethhdr *)eh;
        pkt_type = veh->h_vlan_encapsulated_proto;
        offset += VLAN_HLEN;
        goto l2parse;

    default:
        return TC_ACT_RECLASSIFY;
    }

    /* check if protocol matches */
    if (priv->proto && priv->proto != iph->protocol)
        return TC_ACT_RECLASSIFY;

    switch (iph->protocol) {
    case IPPROTO_TCP:
        if (mbuf_may_pull(mbuf, offset + sizeof(struct tcphdr)) != 0)
            return TC_ACT_SHOT;

        th = rte_pktmbuf_mtod_offset(mbuf, struct tcphdr *, offset);
        sport = th->source;
        dport = th->dest;
        break;

    case IPPROTO_UDP:
        if (mbuf_may_pull(mbuf, offset + sizeof(struct udphdr)) != 0)
            return TC_ACT_SHOT;

        uh = rte_pktmbuf_mtod_offset(mbuf, struct udphdr *, offset);
        sport = uh->source;
        dport = uh->dest;
        break;

    default:
        return TC_ACT_RECLASSIFY;
    }

    /* check if source/dest port in range */
    if (m->srange.max_port) {
        if (ntohs(sport) < ntohs(m->srange.min_port) ||
            ntohs(sport) > ntohs(m->srange.max_port))
            return TC_ACT_RECLASSIFY;
    }

    if (m->drange.max_port) {
        if (ntohs(dport) < ntohs(m->drange.min_port) ||
            ntohs(dport) > ntohs(m->drange.max_port))
            return TC_ACT_RECLASSIFY;
    }

    /* all matchs */
    *result = priv->result;
    return TC_ACT_OK;
}

static int match_init(struct tc_cls *cls, const void *arg)
{
    struct match_cls_priv *priv = tc_cls_priv(cls);
    const struct tc_cls_match_copt *copt = arg;

    if (!arg)
        return EDPVS_OK;

    if (copt->proto)
        priv->proto = copt->proto;

    if (strlen(copt->match.iifname))
        snprintf(priv->match.iifname, IFNAMSIZ, "%s", copt->match.iifname);

    if (strlen(copt->match.oifname))
        snprintf(priv->match.oifname, IFNAMSIZ, "%s", copt->match.oifname);

    if (ntohl(copt->match.srange.max_addr.in.s_addr) != INADDR_ANY) {
        priv->match.srange.min_addr = copt->match.srange.min_addr;
        priv->match.srange.max_addr = copt->match.srange.max_addr;
    }

    if (ntohs(copt->match.srange.max_port)) {
        priv->match.srange.min_port = copt->match.srange.min_port;
        priv->match.srange.max_port = copt->match.srange.max_port;
    }

    if (ntohl(copt->match.drange.max_addr.in.s_addr) != INADDR_ANY) {
        priv->match.drange.min_addr = copt->match.drange.min_addr;
        priv->match.drange.max_addr = copt->match.drange.max_addr;
    }

    if (ntohs(copt->match.drange.max_port)) {
        priv->match.drange.min_port = copt->match.drange.min_port;
        priv->match.drange.max_port = copt->match.drange.max_port;
    }

    if (copt->result.sch_id != TC_H_UNSPEC)
        priv->result.sch_id = copt->result.sch_id;

    return EDPVS_OK;
}

static int match_dump(struct tc_cls *cls, void *arg)
{
    struct match_cls_priv *priv = tc_cls_priv(cls);
    struct tc_cls_match_copt *copt = arg;

    copt->proto = priv->proto;
    copt->match = priv->match;
    copt->result = priv->result;

    return EDPVS_OK;
}

struct tc_cls_ops match_cls_ops = {
    .name       = "match",
    .priv_size  = sizeof(struct match_cls_priv),
    .classify   = match_classify,
    .init       = match_init,
    .change     = match_init,
    .dump       = match_dump,
};
