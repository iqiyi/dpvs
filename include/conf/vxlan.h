#ifndef __DPVS_CONF_VXLAN_H__
#define __DPVS_CONF_VXLAN_H__

#define DPVS_VXLAN_ARP_RESOLVE 1

#define VXLAN_DEFAULT_PORT 4789
enum {
    /* keepalived health check will bind vni as local ip
     * dpvs MUST replace it with real local ip, and create an session
     */
    DPVS_VXLAN_BIND_VNI = 1 << 0,
    /* dmac is not configed, should resolve with arp */
    DPVS_VXLAN_RESOLVE_ARP = 1 << 1,
    /* arp resolve done */
    DPVS_VXLAN_ARP_RESOLVED = 1 << 2,
    DPVS_VXLAN_AUTO_LOCAL = 1 << 3,
};

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif

/* network order */
struct vxlan_tunnel {
    /* ipv4 only */
    uint32_t local;  // local ip, 0 if auto select
    uint32_t remote; // remote ip
    uint32_t vni; // include reserved 8 bits 
    uint8_t dmac[ETHER_ADDR_LEN]; // inner dest mac
    uint16_t rport;  // remote port, default 4789
    uint16_t flags;  // DPVS_VXLAN_XXX
};

static inline int vxlan_tunnel_enabled(struct vxlan_tunnel *vxlan)
{
    return vxlan && vxlan->remote;
}

static inline int vxlan_tunnel_arp_resolve(struct vxlan_tunnel *vxlan)
{
    return vxlan && vxlan->flags & DPVS_VXLAN_RESOLVE_ARP;
}

static inline int vxlan_tunnel_set_arp_resolve(struct vxlan_tunnel *vxlan, int enable)
{
    if (enable) {
        vxlan->flags |= DPVS_VXLAN_RESOLVE_ARP;
    } else {
        vxlan->flags &= ~DPVS_VXLAN_RESOLVE_ARP;
    }
    return EDPVS_OK;
}

static inline int vxlan_tunnel_arp_resolved(struct vxlan_tunnel *vxlan)
{
    return vxlan && vxlan->flags & DPVS_VXLAN_ARP_RESOLVED;
}

static inline int vxlan_tunnel_set_arp_resolved(struct vxlan_tunnel *vxlan, int enable)
{
    if (!vxlan) {
        return EDPVS_INVAL;
    }
    if (enable) {
        vxlan->flags |= DPVS_VXLAN_ARP_RESOLVED;
    } else {
        vxlan->flags &= ~DPVS_VXLAN_ARP_RESOLVED;
    }
    return EDPVS_OK;
}

static inline int vxlan_tunnel_bind_vni(struct vxlan_tunnel *vxlan)
{
    return vxlan && vxlan->flags & DPVS_VXLAN_BIND_VNI;
}

static inline int vxlan_tunnel_auto_local(struct vxlan_tunnel *vxlan)
{
    return vxlan && vxlan->flags & DPVS_VXLAN_AUTO_LOCAL;
}

static inline int vxlan_tunnel_set_auto_local(struct vxlan_tunnel *vxlan, int enable)
{
    if (!vxlan) {
        return EDPVS_INVAL;
    }
    if (enable) {
        vxlan->flags |= DPVS_VXLAN_AUTO_LOCAL;
    } else {
        vxlan->flags &= ~DPVS_VXLAN_AUTO_LOCAL;
    }
    return EDPVS_OK;
}

#endif /* __DPVS_VXLAN_H__ */

