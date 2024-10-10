/* Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        IPVS Kernel wrapper. Use setsockopt call to add/remove
 *              server to/from the loadbalanced server pool.
 *
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
 *
 *               This program is distributed in the hope that it will be useful,
 *               but WITHOUT ANY WARRANTY; without even the implied warranty of
 *               MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *               See the GNU General Public License for more details.
 *
 *               This program is free software; you can redistribute it and/or
 *               modify it under the terms of the GNU General Public License
 *               as published by the Free Software Foundation; either version
 *               2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef O_CLOEXEC	/* Since Linux 2.6.23 and glibc 2.7 */
#define O_CLOEXEC 0	/* It doesn't really matter if O_CLOEXEC isn't set here */
#endif

#include "ipvswrapper.h"
#include "global_data.h"
#include "list.h"
#include "logger.h"
#include "libipvs.h"
#include "main.h"

static bool no_ipvs = false;

static void ipvs_set_srule(int cmd, dpvs_service_compat_t *srule, virtual_server_t *vs);
/*
 *  * Utility functions coming from Wensong code
 *   */

/* fetch virtual server group from group name */
virtual_server_group_t * __attribute__ ((pure))
ipvs_get_group_by_name(const char *gname, list l)
{
    element e;
    virtual_server_group_t *vsg;

    LIST_FOREACH(l, vsg, e) {
        if (!strcmp(vsg->gname, gname))
            return vsg;
    }
    return NULL;
}

local_addr_group * __attribute__ ((pure))
ipvs_get_laddr_group_by_name(char *gname, list l)
{
    element e;
    local_addr_group *laddr_group;

    if (!gname)
        return NULL;

    LIST_FOREACH(l, laddr_group, e) {
        if (!strcmp(laddr_group->gname, gname))
            return laddr_group;
    }
    return NULL;
}

blklst_addr_group * __attribute__ ((pure))
ipvs_get_blklst_group_by_name(char *gname, list l)
{
    element e;
    blklst_addr_group *blklst_group;

    LIST_FOREACH (l, blklst_group, e) {
        if (!strcmp(blklst_group->gname, gname))
            return blklst_group;
    }
    return NULL;
}

whtlst_addr_group * __attribute__ ((pure))
ipvs_get_whtlst_group_by_name(char *gname, list l)
{
    element e;
    whtlst_addr_group *whtlst_group;

    LIST_FOREACH (l, whtlst_group, e) {
        if (!strcmp(whtlst_group->gname, gname))
            return whtlst_group;
    }
    return NULL;
}

/* Initialization helpers */
int
ipvs_start(void)
{
    log_message(LOG_DEBUG, "%snitializing ipvs", reload ? "Rei" : "I");
    /* Initialize IPVS module */
    if (dpvs_ctrl_init(0)) {
        log_message(LOG_INFO, "IPVS: Can't initialize ipvs: %s",
                ipvs_strerror(errno));
        no_ipvs = true;
        return IPVS_ERROR;
    }

    return IPVS_SUCCESS;
}

void
ipvs_stop(void)
{
    if (no_ipvs)
        return;

    dpvs_ctrl_close();
}

void
ipvs_set_timeouts(int tcp_timeout, int tcpfin_timeout, int udp_timeout)
{
    ipvs_timeout_t to;

    if (!tcp_timeout && !tcpfin_timeout && !udp_timeout)
        return;

    to.tcp_timeout = tcp_timeout;
    to.tcp_fin_timeout = tcpfin_timeout;
    to.udp_timeout = udp_timeout;

    if (dpvs_set_timeout(&to))
        log_message(LOG_INFO, "Failed to set ipvs timeouts");
}

/* Send user rules to IPVS module */
static int
ipvs_talk(int cmd, 
        dpvs_service_compat_t *srule, 
        dpvs_dest_compat_t *drule, 
        ipvs_daemon_t *daemonrule, 
        dpvs_laddr_table_t *laddr_rule, 
        dpvs_blklst_t *blklst_rule,
        dpvs_whtlst_t *whtlst_rule,
        ipvs_tunnel_t *tunnel_rule, 
        bool ignore_error)
{
    int result = -1;

    if (no_ipvs)
        return result;

    switch (cmd) {
        case IP_VS_SO_SET_STARTDAEMON:
            result = dpvs_start_daemon(daemonrule);
            break;
        case IP_VS_SO_SET_STOPDAEMON:
            result = dpvs_stop_daemon(daemonrule);
            break;
        case IP_VS_SO_SET_FLUSH:
            result = dpvs_flush();
            break;
        case IP_VS_SO_SET_ADD:
            result = dpvs_add_service(srule);
            break;
        case IP_VS_SO_SET_DEL:
            result = dpvs_del_service(srule);
            break;
        case IP_VS_SO_SET_EDIT:
            result = dpvs_update_service(srule);
            break;
        case IP_VS_SO_SET_ZERO:
            result = dpvs_zero_service(srule);
            break;
        case IP_VS_SO_SET_ADDDEST:
            result = dpvs_add_dest(srule, drule);
            break;
        case IP_VS_SO_SET_DELDEST:
            result = dpvs_del_dest(srule, drule);
            break;
        case IP_VS_SO_SET_EDITDEST:
            if ((result = dpvs_update_dest(srule, drule)) &&
                    (result == EDPVS_NOTEXIST || result == EDPVS_MSG_FAIL)) {
                result = dpvs_add_dest(srule, drule);
                cmd = IP_VS_SO_SET_ADDDEST;
            }
            break;
        case IP_VS_SO_SET_ADDLADDR:
            result = dpvs_add_laddr(srule, laddr_rule);
            break;
        case IP_VS_SO_SET_DELLADDR:
            result = dpvs_del_laddr(srule, laddr_rule);
            break;
        case IP_VS_SO_SET_ADDBLKLST:
            result = dpvs_add_blklst(srule, blklst_rule);
            break;
        case IP_VS_SO_SET_DELBLKLST:
            result = dpvs_del_blklst(srule, blklst_rule);
            break;
        case IP_VS_SO_SET_ADDWHTLST:
            result = dpvs_add_whtlst(srule, whtlst_rule);
            break;
        case IP_VS_SO_SET_DELWHTLST:
            result = dpvs_del_whtlst(srule, whtlst_rule);
            break;
        case IP_VS_SO_SET_ADDTUNNEL:
            result = dpvs_add_tunnel(tunnel_rule);
            break;
        case IP_VS_SO_SET_DELTUNNEL:
            result = dpvs_del_tunnel(tunnel_rule);
            break;
    }

    if (result) {//EDPVS_MSG_FAIL just ignore set failed
        if ((result == EDPVS_EXIST || result == EDPVS_MSG_FAIL || result == EDPVS_NOTSUPP)
                && (cmd == IP_VS_SO_SET_ADD || cmd == IP_VS_SO_SET_ADDDEST || cmd == IP_VS_SO_SET_ADDTUNNEL))
            ignore_error = true;
        else if ((result == EDPVS_NOTEXIST || result == EDPVS_MSG_FAIL || result == EDPVS_NOTSUPP)
                && (cmd == IP_VS_SO_SET_DEL || cmd == IP_VS_SO_SET_DELDEST || cmd == IP_VS_SO_SET_DELTUNNEL))
            ignore_error = true;
    }

    if (ignore_error)
        result = 0;
    else if (result) {
        if (errno == EEXIST &&
                (cmd == IP_VS_SO_SET_ADD || cmd == IP_VS_SO_SET_ADDDEST))
            result = 0;
        else if (errno == ENOENT &&
                (cmd == IP_VS_SO_SET_DEL || cmd == IP_VS_SO_SET_DELDEST))
            result = 0;
        if (errno)
            log_message(LOG_INFO, "IPVS (cmd %d, errno %d): %s", cmd, errno, ipvs_strerror(errno));
    }
    return result;
}

#ifdef _WITH_VRRP_
/* Note: This function is called in the context of the vrrp child process, not the checker process */
void
ipvs_syncd_cmd(int cmd, const struct lvs_syncd_config *config, int state, bool ignore_interface, bool ignore_error)
{
    ipvs_daemon_t daemonrule;

    memset(&daemonrule, 0, sizeof(ipvs_daemon_t));

    /* prepare user rule */
    daemonrule.state = state;
    if (config) {
        daemonrule.syncid = (int)config->syncid;
        if (!ignore_interface)
            strcpy_safe(daemonrule.mcast_ifn, config->ifname);
#ifdef _HAVE_IPVS_SYNCD_ATTRIBUTES_
        if (cmd == IPVS_STARTDAEMON) {
            if (config->sync_maxlen)
                daemonrule.sync_maxlen = config->sync_maxlen;
            if (config->mcast_port)
                daemonrule.mcast_port = config->mcast_port;
            if (config->mcast_ttl)
                daemonrule.mcast_ttl = config->mcast_ttl;
            if (config->mcast_group.ss_family == AF_INET) {
                daemonrule.mcast_af = AF_INET;
                daemonrule.mcast_group.ip = ((const struct sockaddr_in *)&config->mcast_group)->sin_addr.s_addr;
            }
            else if (config->mcast_group.ss_family == AF_INET6) {
                daemonrule.mcast_af = AF_INET6;
                memcpy(&daemonrule.mcast_group.in6, &((const struct sockaddr_in6 *)&config->mcast_group)->sin6_addr, sizeof(daemonrule.mcast_group.in6));
            }
        }
#endif
    }

    /* Talk to the IPVS channel */
    ipvs_talk(cmd, NULL, NULL, &daemonrule, NULL, NULL, NULL, NULL, ignore_error);
}
#endif

void
ipvs_flush_cmd(void)
{
    ipvs_talk(IP_VS_SO_SET_FLUSH, NULL, NULL, NULL, NULL, NULL, NULL, NULL, false);
}

/* IPVS group range rule */
static int
ipvs_group_range_cmd(int cmd, dpvs_service_compat_t *srule, dpvs_dest_compat_t *drule, virtual_server_group_entry_t *vsg_entry)
{
    uint32_t i;

    /* Set address and port */
    if (vsg_entry->addr.ss_family == AF_INET6)
        inet_sockaddrip6(&vsg_entry->addr, &srule->addr.in6);
    else
        srule->addr.in.s_addr = inet_sockaddrip4(&vsg_entry->addr);

    /* Process the whole range */
    for (i = 0; i <= vsg_entry->range; i++) {
        /* Talk to the IPVS channel */
        if (ipvs_talk(cmd, srule, drule, NULL, NULL, NULL, NULL, NULL, false))
            return -1;

        if (srule->af == AF_INET)
            srule->addr.in.s_addr += htonl(1);
        else
            srule->addr.in6.s6_addr16[7] = htons(ntohs(srule->addr.in6.s6_addr16[7]) + 1);
    }

    return 0;
}

/* set IPVS group rules */
static bool
is_vsge_alive(virtual_server_group_entry_t *vsge, virtual_server_t *vs)
{
    if (vsge->is_fwmark) {
        if (vs->af == AF_INET)
            return !!vsge->fwm4_alive;
        else
            return !!vsge->fwm6_alive;
    }
    else if (vs->service_type == IPPROTO_TCP)
        return !!vsge->tcp_alive;
    else if (vs->service_type == IPPROTO_UDP)
        return !!vsge->udp_alive;
    else
        return !!vsge->sctp_alive;
}

static void
update_vsge_alive_count(virtual_server_group_entry_t *vsge, const virtual_server_t *vs, bool up)
{
    unsigned *alive_p;

    if (vsge->is_fwmark) {
        if (vs->af == AF_INET)
            alive_p = &vsge->fwm4_alive;
        else
            alive_p = &vsge->fwm6_alive;
    }
    else if (vs->service_type == IPPROTO_TCP)
        alive_p = &vsge->tcp_alive;
    else if (vs->service_type == IPPROTO_UDP)
        alive_p = &vsge->udp_alive;
    else
        alive_p = &vsge->sctp_alive;

    if (up)
        (*alive_p)++;
    else
        (*alive_p)--;
}

static void
set_vsge_alive(virtual_server_group_entry_t *vsge, const virtual_server_t *vs)
{
    update_vsge_alive_count(vsge, vs, true);
}

static void
unset_vsge_alive(virtual_server_group_entry_t *vsge, const virtual_server_t *vs)
{
    update_vsge_alive_count(vsge, vs, false);
}

static bool
ipvs_change_needed(int cmd, virtual_server_group_entry_t *vsge, virtual_server_t *vs, real_server_t *rs)
{
    unsigned count;

    if (cmd == IP_VS_SO_SET_ADD)
        return !is_vsge_alive(vsge, vs);
    else if (cmd == IP_VS_SO_SET_DEL) {
        count = vsge->is_fwmark ? (vs->af == AF_INET ? vsge->fwm4_alive : vsge->fwm6_alive) :
            vs->service_type == IPPROTO_TCP ? vsge->tcp_alive :
            vs->service_type == IPPROTO_UDP ? vsge->udp_alive : vsge->sctp_alive;

        return (count == 0);
    }
#if 0
    else if (cmd == IP_VS_SO_SET_ADDDEST)
        return !rs->alive;
    else if (cmd == IP_VS_SO_SET_DELDEST)
        return rs->alive;
#endif
    else /* cmd == IP_VS_SO_SET_EDITDEST */
        return true;
}

static void
ipvs_set_vsge_alive_state(int cmd, virtual_server_group_entry_t *vsge, virtual_server_t *vs)
{
    if (cmd == IP_VS_SO_SET_ADDDEST)
        set_vsge_alive(vsge, vs);
    else if (cmd == IP_VS_SO_SET_DELDEST)
        unset_vsge_alive(vsge, vs);
}

static int
ipvs_group_cmd(int cmd, dpvs_service_compat_t *srule, dpvs_dest_compat_t *drule, virtual_server_t *vs, real_server_t *rs)
{
    virtual_server_group_t *vsg = vs->vsg;
    virtual_server_group_entry_t *vsg_entry;
    element e;

    /* return if jointure fails */
    if (!vsg)
        return 0;

    /* visit addr_range list */
    LIST_FOREACH(vsg->addr_range, vsg_entry, e) {
        if (cmd == IP_VS_SO_SET_ADD && reload && vsg_entry->reloaded)
            continue;
        if (ipvs_change_needed(cmd, vsg_entry, vs, rs)) {
            srule->port = inet_sockaddrport(&vsg_entry->addr);
            if (vsg_entry->range) {
                if (ipvs_group_range_cmd(cmd, srule, drule, vsg_entry))
                    return -1;
            } else {
                if (vsg_entry->addr.ss_family == AF_INET6)
                    inet_sockaddrip6(&vsg_entry->addr, &srule->addr.in6);
                else
                    srule->addr.in.s_addr = inet_sockaddrip4(&vsg_entry->addr);

                /* Talk to the IPVS channel */
                if (ipvs_talk(cmd, srule, drule, NULL, NULL, NULL, NULL, NULL, false))
                    return -1;
            }
        }
        if (cmd == IP_VS_SO_SET_ADDDEST || cmd == IP_VS_SO_SET_DELDEST)
            ipvs_set_vsge_alive_state(cmd, vsg_entry, vs);
    }

    /* visit vfwmark list */
    memset(&srule->addr, 0, sizeof(srule->addr));
    srule->port = 0;
    LIST_FOREACH(vsg->vfwmark, vsg_entry, e) {
        if (cmd == IP_VS_SO_SET_ADD && reload && vsg_entry->reloaded)
            continue;

        srule->fwmark = vsg_entry->vfwmark;

        /* Talk to the IPVS channel */
        if (ipvs_change_needed(cmd, vsg_entry, vs, rs)) {
            if (ipvs_talk(cmd, srule, drule, NULL, NULL, NULL, NULL, NULL, false))
                return -1;
        }
        ipvs_set_vsge_alive_state(cmd, vsg_entry, vs);
    }

    return 0;
}

static void
dpvs_laddr_range_cmd(int cmd, local_addr_entry *laddr_entry, virtual_server_t *vs, dpvs_service_compat_t *srule)
{
    uint32_t addr_ip, ip;
    dpvs_laddr_table_t laddr;

    memset(&laddr, 0, sizeof(dpvs_laddr_table_t));

    laddr.af_s = vs->af;
    laddr.af_l = laddr_entry->addr.ss_family;

    if (laddr_entry->addr.ss_family == AF_INET6) {
        inet_sockaddrip6(&laddr_entry->addr, &laddr.laddr.in6);
        ip = laddr.laddr.in6.s6_addr32[3];
    } else {
        ip = inet_sockaddrip4(&laddr_entry->addr);
    }

    for (addr_ip = ip; ((addr_ip >> 24) & 0xFF) <= laddr_entry->range;
            addr_ip += 0x01000000) {
        if (laddr_entry->addr.ss_family == AF_INET6) {
            laddr.laddr.in6.s6_addr32[3] = addr_ip;
        } else {
            laddr.laddr.in.s_addr = addr_ip;
        }
        strncpy(laddr.ifname, laddr_entry->ifname, sizeof(laddr.ifname));

        ipvs_talk(cmd, srule, NULL, NULL, &laddr, NULL, NULL, NULL, false);
    }
}

static void
dpvs_laddr_group_cmd(int cmd, local_addr_group *laddr_group, virtual_server_t *vs, dpvs_service_compat_t *srule)
{
    local_addr_entry *laddr_entry;
    dpvs_laddr_table_t laddr_rule;
    list l;
    element e;

    if (!laddr_group)
        return;

    l = laddr_group->addr_ip;
    LIST_FOREACH(l, laddr_entry, e) {
        memset(&laddr_rule, 0, sizeof(dpvs_laddr_table_t));
        laddr_rule.af_l = laddr_entry->addr.ss_family;
        laddr_rule.af_s = vs->af;
        if (laddr_entry->addr.ss_family == AF_INET6)
            inet_sockaddrip6(&laddr_entry->addr, &laddr_rule.laddr.in6);
        else
            laddr_rule.laddr.in.s_addr = inet_sockaddrip4(&laddr_entry->addr);
        strncpy(laddr_rule.ifname, laddr_entry->ifname, sizeof(laddr_rule.ifname));

        ipvs_talk(cmd, srule, NULL, NULL, &laddr_rule, NULL, NULL, NULL, false);
    }

    l = laddr_group->range;
    LIST_FOREACH(l, laddr_entry, e) {
        dpvs_laddr_range_cmd(cmd, laddr_entry, vs, srule);
    }
}


static void
ipvs_laddr_vsg_cmd(int cmd, list vs_group, virtual_server_t *vs, local_addr_group *laddr_group, dpvs_service_compat_t *srule)
{
    virtual_server_group_t *vsg = ipvs_get_group_by_name(vs->vsgname, vs_group);
    virtual_server_group_entry_t *vsg_entry;
    list l;
    element e;

    if (!vsg)
        return;

    /* visit range list */
    l = vsg->addr_range;
    LIST_FOREACH(l, vsg_entry, e) {
        uint32_t addr_ip, ip;

        srule->af = vsg_entry->addr.ss_family;
        if (srule->af == AF_INET6) {
            inet_sockaddrip6(&vsg_entry->addr, &srule->addr.in6);
            ip = srule->addr.in6.s6_addr32[3];
        } else {
            ip = inet_sockaddrip4(&vsg_entry->addr);
        }

        if (!vsg_entry->range) {
            if (srule->af == AF_INET6) {
                if (srule->netmask == 0xffffffff)
                    srule->netmask = 128;
                srule->addr.in6.s6_addr32[3] = ip;
            } else {
                srule->addr.in.s_addr = ip;
            }
            srule->port = inet_sockaddrport(&vsg_entry->addr);
            dpvs_laddr_group_cmd(cmd, laddr_group, vs, srule);
            continue;
        }

        /* Parse the whole range */
        for (addr_ip = ip;
                ((addr_ip >> 24) & 0xFF) <= vsg_entry->range;
                addr_ip += 0x01000000) {
            if (srule->af == AF_INET6) {
                if (srule->netmask == 0xffffffff)
                    srule->netmask = 128;
                srule->addr.in6.s6_addr32[3] = addr_ip;
            } else {
                srule->addr.in.s_addr = addr_ip;
            }
            srule->port = inet_sockaddrport(&vsg_entry->addr);

            dpvs_laddr_group_cmd(cmd, laddr_group, vs, srule);
        }
    }
}

static int
ipvs_laddr_cmd(int cmd, dpvs_service_compat_t *srule, virtual_server_t *vs)
{
    local_addr_group *laddr_group;
    laddr_group = ipvs_get_laddr_group_by_name(vs->local_addr_gname, check_data->laddr_group);
    if (!laddr_group) {
        log_message(LOG_ERR, "No address in group %s", vs->local_addr_gname);
        return -1;
    }

    if (vs->vsgname) {
        ipvs_laddr_vsg_cmd(cmd, check_data->vs_group, vs, laddr_group, srule);
    } else {
        if (!vs->vfwmark) {
            srule->af = vs->addr.ss_family;
            if (vs->addr.ss_family == AF_INET6)
                inet_sockaddrip6(&vs->addr, &srule->addr.in6);
            else
                srule->addr.in.s_addr = inet_sockaddrip4(&vs->addr);
            srule->port = inet_sockaddrport(&vs->addr);
            dpvs_laddr_group_cmd(cmd, laddr_group, vs, srule);
        }
    }

    return IPVS_SUCCESS;
}

static void
ipvs_blklst_range_cmd(int cmd, blklst_addr_entry *blklst_entry, dpvs_service_compat_t *srule)
{
    uint32_t addr_ip, ip;
    dpvs_blklst_t blklst_rule;

    memset(&blklst_rule, 0, sizeof(dpvs_blklst_t));
    blklst_rule.af = blklst_entry->addr.ss_family;
    if (blklst_entry->addr.ss_family == AF_INET6) {
        inet_sockaddrip6(&blklst_entry->addr, &blklst_rule.subject.in6);
        ip = blklst_rule.subject.in6.s6_addr32[3];
    } else {
        ip = inet_sockaddrip4(&blklst_entry->addr);
    }

    for (addr_ip = ip;
            ((addr_ip >> 24) & 0xFF) <= blklst_entry->range;
            addr_ip += 0x01000000) {
        if (blklst_entry->addr.ss_family == AF_INET6)
            blklst_rule.subject.in6.s6_addr32[3] = addr_ip;
        else
            blklst_rule.subject.in.s_addr = addr_ip;

        ipvs_talk(cmd, srule, NULL, NULL, NULL, &blklst_rule, NULL, NULL, false);
    }
}

static void
ipvs_blklst_group_cmd(int cmd, blklst_addr_group *blklst_group, dpvs_service_compat_t *srule)
{
    blklst_addr_entry *blklst_entry;
    dpvs_blklst_t blklst_rule;
    list l;
    element e;

    if (!blklst_group)
        return;

    l = blklst_group->addr_ip;
    LIST_FOREACH(l, blklst_entry, e) {
        memset(&blklst_rule, 0, sizeof(dpvs_blklst_t));
        blklst_rule.af = blklst_entry->addr.ss_family;
        if (blklst_entry->addr.ss_family == AF_INET6)
            inet_sockaddrip6(&blklst_entry->addr, &blklst_rule.subject.in6);
        else
            blklst_rule.subject.in.s_addr = inet_sockaddrip4(&blklst_entry->addr);
        ipvs_talk(cmd, srule, NULL, NULL, NULL, &blklst_rule, NULL, NULL, false);
    }

    l = blklst_group->range;
    LIST_FOREACH(l, blklst_entry, e) {
        ipvs_blklst_range_cmd(cmd, blklst_entry, srule);
    }

    l = blklst_group->ipset;
    LIST_FOREACH(l, blklst_entry, e) {
        memset(&blklst_rule, 0, sizeof(dpvs_blklst_t));
        strncpy(blklst_rule.ipset, blklst_entry->ipset, sizeof(blklst_rule.ipset) - 1);
        ipvs_talk(cmd, srule, NULL, NULL, NULL, &blklst_rule, NULL, NULL, false);
    }
}

static void
ipvs_blklst_vsg_cmd(int cmd, 
        list vs_group, 
        virtual_server_t *vs, 
        blklst_addr_group *blklst_group, 
        dpvs_service_compat_t *srule)
{
    virtual_server_group_t *vsg = ipvs_get_group_by_name(vs->vsgname, vs_group);
    virtual_server_group_entry_t *vsg_entry;
    list l;
    element e;
    if (!vsg)
        return;

    /* visit range list */
    l = vsg->addr_range;
    LIST_FOREACH(l, vsg_entry, e) {
        uint32_t addr_ip, ip;

        srule->af = vsg_entry->addr.ss_family;
        if (srule->af == AF_INET6) {
            inet_sockaddrip6(&vsg_entry->addr, &srule->addr.in6);
            ip = srule->addr.in6.s6_addr32[3];
        } else {
            ip = inet_sockaddrip4(&vsg_entry->addr);
        }

        if (!vsg_entry->range) {
            if (srule->af == AF_INET6) {
                if (srule->netmask == 0xffffffff)
                    srule->netmask = 128;
                srule->addr.in6.s6_addr32[3] = ip;
            } else {
                srule->addr.in.s_addr = ip;
            }
            srule->port = inet_sockaddrport(&vsg_entry->addr);

            ipvs_blklst_group_cmd(cmd, blklst_group, srule);
            continue;
        }

        /* Parse the whole range */
        for (addr_ip = ip;
                ((addr_ip >> 24) & 0xFF) <= vsg_entry->range;
                addr_ip += 0x01000000) {
            if (srule->af == AF_INET6) {
                if (srule->netmask == 0xffffffff)
                    srule->netmask = 128;
                srule->addr.in6.s6_addr32[3] = addr_ip;
            } else {
                srule->addr.in.s_addr = addr_ip;
            }
            srule->port = inet_sockaddrport(&vsg_entry->addr);

            ipvs_blklst_group_cmd(cmd, blklst_group, srule);
        }
    }
}

static int
ipvs_blklst_cmd(int cmd, dpvs_service_compat_t *srule, virtual_server_t * vs)
{
    blklst_addr_group *blklst_group = ipvs_get_blklst_group_by_name(vs->blklst_addr_gname,
            check_data->blklst_group);
    if (!blklst_group) {
        log_message(LOG_ERR, "No address in group %s", vs->blklst_addr_gname);
        return -1;
    }

    memset(srule, 0, sizeof(dpvs_service_compat_t));
    srule->netmask = (vs->addr.ss_family == AF_INET6) ? 128 : ((u_int32_t) 0xffffffff);
    srule->proto = vs->service_type;

    if(vs->vsgname) {
        ipvs_blklst_vsg_cmd(cmd, check_data->vs_group, vs, blklst_group, srule);
    } else {
        if (!vs->vfwmark) {
            srule->af = vs->addr.ss_family;
            if (vs->addr.ss_family == AF_INET6)
                inet_sockaddrip6(&vs->addr, &srule->addr.in6);
            else
                srule->addr.in.s_addr = inet_sockaddrip4(&vs->addr);
            srule->port = inet_sockaddrport(&vs->addr);
            ipvs_blklst_group_cmd(cmd, blklst_group, srule);
        }
    }
    return IPVS_SUCCESS;
}

/* Fill IPVS rule with root vs infos */
static void ipvs_set_srule(int cmd, dpvs_service_compat_t *srule, virtual_server_t *vs)
{
    int af = 0;
    /* Clean service rule */
    memset(srule, 0, sizeof(dpvs_service_compat_t));

    strncpy(srule->sched_name, vs->sched, IP_VS_SCHEDNAME_MAXLEN);
    srule->af = vs->af;
    srule->flags = vs->flags;
    srule->netmask = (vs->af == AF_INET6) ? 128 : ((uint32_t) 0xffffffff);
    srule->proto = vs->service_type;
    srule->proxy_protocol = vs->proxy_protocol;
    srule->bps = vs->bps;
    srule->limit_proportion = vs->limit_proportion;
    srule->conn_timeout = vs->conn_timeout;

    if (vs->srange[0] || vs->drange[0] || vs->iifname[0] || vs->oifname[0]) {
        if (dp_vs_match_parse(vs->srange, vs->drange, vs->iifname,
                    vs->oifname,vs->af, &srule->match) == EDPVS_OK) {
            srule->af = srule->match.af;
        } else {
            memset(&srule->match, 0, sizeof(srule->match));
        }
    } else if (!vs->af) {
        log_message(LOG_WARNING, "empty virtual server af\n");
    }

    if (vs->persistence_timeout &&
            (cmd == IP_VS_SO_SET_ADD || cmd == IP_VS_SO_SET_DEL || cmd == IP_VS_SO_SET_EDIT)) {
        srule->timeout = vs->persistence_timeout;
        srule->flags |= IP_VS_SVC_F_PERSISTENT;

        if (vs->persistence_granularity)
            srule->netmask = vs->persistence_granularity;
    }

    if (vs->syn_proxy) {
        srule->flags |= IP_VS_SVC_F_SYNPROXY;
    }

    if (vs->expire_quiescent_conn) {
        srule->flags |= IP_VS_SVC_F_EXPIRE_QUIESCENT;
    }

    if (vs->quic) {
        srule->flags |= IP_VS_SVC_F_QUIC;
    }

    if (!strcmp(vs->sched, "conhash")) {
        if (vs->hash_target) {
            if ((srule->proto != IPPROTO_UDP) &&
                    (vs->hash_target == IP_VS_SVC_F_QID_HASH)) {
                log_message(LOG_ERR, "vs hash_target IP_VS_SVC_F_QID_HASH cannot apply to non-UDP services");
            } else {
                srule->flags |= vs->hash_target;
            }
        } else {
            srule->flags |= IP_VS_SVC_F_SIP_HASH; // default
        }
    }

#if 0
    strcpy(srule->pe_name, vs->pe_name);
#endif
}

/* Fill IPVS rule with rs infos */
static void
ipvs_set_drule(int cmd, dpvs_dest_compat_t *drule, real_server_t * rs)
{
    if (cmd != IP_VS_SO_SET_ADDDEST &&
            cmd != IP_VS_SO_SET_DELDEST &&
            cmd != IP_VS_SO_SET_EDITDEST)
        return;

    /* Clean target rule */
    memset(drule, 0, sizeof(dpvs_dest_compat_t));

    drule->af = rs->addr.ss_family;
    if (rs->addr.ss_family == AF_INET6)
        inet_sockaddrip6(&rs->addr, &drule->addr.in6);
    else
        drule->addr.in.s_addr = inet_sockaddrip4(&rs->addr);

    drule->port = inet_sockaddrport(&rs->addr);
    drule->conn_flags = rs->forwarding_method;
    /*Do not change dead rs weight in dpvs at reload*/
    if (cmd == IP_VS_SO_SET_EDITDEST && rs->reloaded && rs->set && !ISALIVE(rs))
        drule->weight = 0;
    else
        drule->weight = rs->weight;
    drule->fwdmode = rs->forwarding_method;
    drule->max_conn = rs->u_threshold;
    drule->min_conn = rs->l_threshold;
}

/*check whitelist addr*/

static void
ipvs_whtlst_range_cmd(int cmd, whtlst_addr_entry *whtlst_entry, dpvs_service_compat_t *srule)
{
    uint32_t addr_ip, ip;
    dpvs_whtlst_t whtlst_rule;

    memset(&whtlst_rule, 0, sizeof(dpvs_whtlst_t));
    whtlst_rule.af = whtlst_entry->addr.ss_family;
    if (whtlst_entry->addr.ss_family == AF_INET6) {
        inet_sockaddrip6(&whtlst_entry->addr, &whtlst_rule.subject.in6);
        ip = whtlst_rule.subject.in6.s6_addr32[3];
    } else {
        ip = inet_sockaddrip4(&whtlst_entry->addr);
    }

    for (addr_ip = ip; ((addr_ip >> 24) & 0xFF) <= whtlst_entry->range;
            addr_ip += 0x01000000) {
        if (whtlst_entry->addr.ss_family == AF_INET6)
            whtlst_rule.subject.in6.s6_addr32[3] = addr_ip;
        else
            whtlst_rule.subject.in.s_addr = addr_ip;

        ipvs_talk(cmd, srule, NULL, NULL, NULL, NULL, &whtlst_rule, NULL, false);
    }
}

static void
ipvs_whtlst_group_cmd(int cmd, whtlst_addr_group *whtlst_group, dpvs_service_compat_t *srule)
{
    whtlst_addr_entry *whtlst_entry;
    dpvs_whtlst_t whtlst_rule;
    list l;
    element e;

    if (!whtlst_group)
        return;

    l = whtlst_group->addr_ip;
    LIST_FOREACH(l, whtlst_entry, e) {
        memset(&whtlst_rule, 0, sizeof(dpvs_whtlst_t));
        whtlst_rule.af = whtlst_entry->addr.ss_family;
        if (whtlst_entry->addr.ss_family == AF_INET6)
            inet_sockaddrip6(&whtlst_entry->addr, &whtlst_rule.subject.in6);
        else
            whtlst_rule.subject.in.s_addr = inet_sockaddrip4(&whtlst_entry->addr);
        ipvs_talk(cmd, srule, NULL, NULL, NULL, NULL, &whtlst_rule, NULL, false);
    }

    l = whtlst_group->range;
    LIST_FOREACH(l, whtlst_entry, e) {
        ipvs_whtlst_range_cmd(cmd, whtlst_entry, srule);
    }

    l = whtlst_group->ipset;
    LIST_FOREACH(l, whtlst_entry, e) {
        memset(&whtlst_rule, 0, sizeof(dpvs_whtlst_t));
        strncpy(whtlst_rule.ipset, whtlst_entry->ipset, sizeof(whtlst_rule.ipset) - 1);
        ipvs_talk(cmd, srule, NULL, NULL, NULL, NULL, &whtlst_rule, NULL, false);
    }
}

static void
ipvs_whtlst_vsg_cmd(int cmd, 
        list vs_group, 
        virtual_server_t *vs, 
        whtlst_addr_group *whtlst_group, 
        dpvs_service_compat_t *srule)
{
    virtual_server_group_t *vsg = ipvs_get_group_by_name(vs->vsgname, vs_group);
    virtual_server_group_entry_t *vsg_entry;
    list l;
    element e;
    if (!vsg)
        return;

    /* visit range list */
    l = vsg->addr_range;
    LIST_FOREACH(l, vsg_entry, e) {
        uint32_t addr_ip, ip;

        srule->af = vsg_entry->addr.ss_family;
        if (srule->af == AF_INET6) {
            inet_sockaddrip6(&vsg_entry->addr, &srule->addr.in6);
            ip = srule->addr.in6.s6_addr32[3];
        } else {
            ip = inet_sockaddrip4(&vsg_entry->addr);
        }

        if (!vsg_entry->range) {
            if (srule->af == AF_INET6) {
                if (srule->netmask == 0xffffffff)
                    srule->netmask = 128;
                srule->addr.in6.s6_addr32[3] = ip;
            } else {
                srule->addr.in.s_addr = ip;
            }
            srule->port = inet_sockaddrport(&vsg_entry->addr);

            ipvs_whtlst_group_cmd(cmd, whtlst_group, srule);
            continue;
        }

        /* Parse the whole range */
        for (addr_ip = ip;
                ((addr_ip >> 24) & 0xFF) <= vsg_entry->range;
                addr_ip += 0x01000000) {
            if (srule->af == AF_INET6) {
                if (srule->netmask == 0xffffffff)
                    srule->netmask = 128;
                srule->addr.in6.s6_addr32[3] = addr_ip;
            } else {
                srule->addr.in.s_addr = addr_ip;
            }
            srule->port = inet_sockaddrport(&vsg_entry->addr);

            ipvs_whtlst_group_cmd(cmd, whtlst_group, srule);
        }
    }
}

static int
ipvs_whtlst_cmd(int cmd, dpvs_service_compat_t *srule, virtual_server_t * vs)
{
    whtlst_addr_group *whtlst_group = ipvs_get_whtlst_group_by_name(vs->whtlst_addr_gname,
            check_data->whtlst_group);
    if (!whtlst_group) {
        log_message(LOG_ERR, "No address in group %s", vs->whtlst_addr_gname);
        return -1;
    }

    memset(srule, 0, sizeof(dpvs_service_compat_t));
    srule->netmask = (vs->addr.ss_family == AF_INET6) ? 128 : ((u_int32_t) 0xffffffff);
    srule->proto = vs->service_type;

    if(vs->vsgname) {
        ipvs_whtlst_vsg_cmd(cmd, check_data->vs_group, vs, whtlst_group, srule);
    } else {
        if (!vs->vfwmark) {
            srule->af = vs->addr.ss_family;
            if (vs->addr.ss_family == AF_INET6)
                inet_sockaddrip6(&vs->addr, &srule->addr.in6);
            else
                srule->addr.in.s_addr = inet_sockaddrip4(&vs->addr);
            srule->port = inet_sockaddrport(&vs->addr);
            ipvs_whtlst_group_cmd(cmd, whtlst_group, srule);
        }
    }
    return IPVS_SUCCESS;
}

int ipvs_tunnel_cmd(int cmd, tunnel_entry *entry)
{
    ipvs_tunnel_t tunnel_rule;
    memset(&tunnel_rule, 0, sizeof(ipvs_tunnel_t));
    strncpy(tunnel_rule.ifname, entry->ifname, sizeof(tunnel_rule.ifname));
    strncpy(tunnel_rule.kind, entry->kind, sizeof(tunnel_rule.kind));
    strncpy(tunnel_rule.link, entry->link, sizeof(tunnel_rule.link));

    tunnel_rule.laddr.ip = inet_sockaddrip4(&entry->local);
    tunnel_rule.raddr.ip = inet_sockaddrip4(&entry->remote);
    ipvs_talk(cmd, NULL, NULL, NULL, NULL, NULL, NULL, &tunnel_rule, false);

    return IPVS_SUCCESS;
}

/* Set/Remove a RS from a VS */
int
ipvs_cmd(int cmd, virtual_server_t *vs, real_server_t *rs)
{
    dpvs_service_compat_t srule;
    dpvs_dest_compat_t drule;

    /* Allocate the room */
    ipvs_set_srule(cmd, &srule, vs);

    /* Set/Remove local address */
    if (cmd == IP_VS_SO_SET_ADDLADDR || cmd == IP_VS_SO_SET_DELLADDR)
        return ipvs_laddr_cmd(cmd, &srule, vs);
    /* Set/Remove deny address */
    if (cmd == IP_VS_SO_SET_ADDBLKLST || cmd == IP_VS_SO_SET_DELBLKLST)
        return ipvs_blklst_cmd(cmd, &srule, vs);
    /* Set/Remove allow address */
    if (cmd == IP_VS_SO_SET_ADDWHTLST || cmd == IP_VS_SO_SET_DELWHTLST)
        return ipvs_whtlst_cmd(cmd, &srule, vs);


    if (rs) {
        ipvs_set_drule(cmd, &drule, rs);

        /* Does the service use inhibit flag ? */
        if (cmd == IP_VS_SO_SET_DELDEST && rs->inhibit) {
            drule.weight = 0;
            cmd = IP_VS_SO_SET_EDITDEST;
        }
        else if (cmd == IP_VS_SO_SET_ADDDEST && rs->inhibit && rs->set)
            cmd = IP_VS_SO_SET_EDITDEST;

        /* Set flag */
        else if (cmd == IP_VS_SO_SET_ADDDEST && !rs->set) {
            rs->set = true;
            if (rs->inhibit && rs->num_failed_checkers)
                drule.weight = 0;
        }
        else if (cmd == IP_VS_SO_SET_DELDEST && rs->set)
            rs->set = false;
    }

    /* Set vs rule and send to kernel */
    if (vs->vsg)
        return ipvs_group_cmd(cmd, &srule, &drule, vs, rs);

    if (vs->vfwmark) {
        srule.fwmark = vs->vfwmark;
    } else if (vs->forwarding_method == IP_VS_CONN_F_SNAT) {
        srule.addr.in.s_addr = 0;
        srule.port = inet_sockaddrport(&vs->addr);
        srule.flags |= IP_VS_SVC_F_MATCH;
        /* srule.af should be set in ipvs_set_srule  */
        if (!srule.af)
            srule.af = vs->addr.ss_family;
    } else {
        if (vs->af == AF_INET6)
            inet_sockaddrip6(&vs->addr, &srule.addr.in6);
        else
            srule.addr.in.s_addr = inet_sockaddrip4(&vs->addr);
        srule.port = inet_sockaddrport(&vs->addr);
        /* srule.af should be set in ipvs_set_srule  */
        //srule.af = vs->af;
    }

    /* Talk to the IPVS channel */
    return ipvs_talk(cmd, &srule, &drule, NULL, NULL, NULL, NULL, NULL, false);
}

/* at reload, add alive destinations to the newly created vsge */
void
ipvs_group_sync_entry(virtual_server_t *vs, virtual_server_group_entry_t *vsge)
{
    real_server_t *rs;
    element e;
    dpvs_service_compat_t srule;
    dpvs_dest_compat_t drule;

    ipvs_set_srule(IP_VS_SO_SET_ADDDEST, &srule, vs);
    if (vsge->is_fwmark)
        srule.fwmark = vsge->vfwmark;
    else
        srule.port = inet_sockaddrport(&vsge->addr);

    /* Process realserver queue */
    LIST_FOREACH(vs->rs, rs, e) {
        if (rs->reloaded && (rs->alive || (rs->inhibit && rs->set))) {
            /* Prepare the IPVS drule */
            ipvs_set_drule(IP_VS_SO_SET_ADDDEST, &drule, rs);
            drule.weight = rs->inhibit && !rs->alive ? 0 : rs->weight;

            /* Set vs rule */
            if (vsge->is_fwmark) {
                /* Talk to the IPVS channel */
                ipvs_talk(IP_VS_SO_SET_ADDDEST, &srule, &drule, NULL, NULL, NULL, NULL, NULL, false);
            }
            else
                ipvs_group_range_cmd(IP_VS_SO_SET_ADDDEST, &srule, &drule, vsge);
        }
    }
}

static void 
ipvs_rm_lentry_from_vsg(local_addr_entry *laddr_entry, virtual_server_t *vs)
{
    list l;
    element e;
    dpvs_service_compat_t srule;
    dpvs_laddr_table_t laddr_rule;
    virtual_server_group_t *vsg;
    virtual_server_group_entry_t *vsg_entry;

    /* Allocate the room */
    ipvs_set_srule(IP_VS_SO_SET_DELLADDR, &srule, vs);

    vsg = ipvs_get_group_by_name(vs->vsgname, check_data->vs_group);
    if (!vsg)
        return;

    l = vsg->addr_range;
    LIST_FOREACH(l, vsg_entry, e) {
        uint32_t addr_ip, ip;

        srule.af = vsg_entry->addr.ss_family;
        srule.netmask = (vsg_entry->addr.ss_family == AF_INET6) ? 128 : ((u_int32_t) 0xffffffff);
        srule.port = inet_sockaddrport(&vsg_entry->addr);
        if (vsg_entry->addr.ss_family == AF_INET6) {
            inet_sockaddrip6(&vsg_entry->addr, &srule.addr.in6);
            ip = srule.addr.in6.s6_addr32[3];
        } else {
            ip = inet_sockaddrip4(&vsg_entry->addr);
        }

        if (!vsg_entry->range) {
            if (srule.af == AF_INET6)
                srule.addr.in6.s6_addr32[3] = ip;
            else
                srule.addr.in.s_addr = ip;

            if (laddr_entry->range)
                dpvs_laddr_range_cmd(IP_VS_SO_SET_DELLADDR, laddr_entry, vs, &srule);
            else {
                memset(&laddr_rule, 0, sizeof(dpvs_laddr_table_t));
                laddr_rule.af_l = laddr_entry->addr.ss_family;
                laddr_rule.af_s = vs->af;

                if (laddr_entry->addr.ss_family == AF_INET6)
                    inet_sockaddrip6(&laddr_entry->addr, &laddr_rule.laddr.in6);
                else
                    laddr_rule.laddr.in.s_addr = inet_sockaddrip4(&laddr_entry->addr);
                strncpy(laddr_rule.ifname, laddr_entry->ifname, sizeof(laddr_rule.ifname));

                ipvs_talk(IP_VS_SO_SET_DELLADDR,
                        &srule,
                        NULL/*drule*/,
                        NULL/*daemonrule*/,
                        &laddr_rule,
                        NULL/*blklst_rule*/,
                        NULL/*whtlst_rule*/,
                        NULL,
                        false);
            }
            continue;
        }

        for (addr_ip = ip;
                ((addr_ip >> 24) & 0xFF) <= vsg_entry->range;
                addr_ip += 0x01000000) {
            if (srule.af == AF_INET6)
                srule.addr.in6.s6_addr32[3] = addr_ip;
            else
                srule.addr.in.s_addr = addr_ip;

            if (laddr_entry->range)
                dpvs_laddr_range_cmd(IP_VS_SO_SET_DELLADDR, laddr_entry, vs, &srule);
            else {
                memset(&laddr_rule, 0, sizeof(dpvs_laddr_table_t));
                laddr_rule.af_l = laddr_entry->addr.ss_family;
                laddr_rule.af_s = vs->af;
                if (laddr_entry->addr.ss_family == AF_INET6)
                    inet_sockaddrip6(&laddr_entry->addr, &laddr_rule.laddr.in6);
                else
                    laddr_rule.laddr.in.s_addr = inet_sockaddrip4(&laddr_entry->addr);
                strncpy(laddr_rule.ifname, laddr_entry->ifname, sizeof(laddr_rule.ifname));

                ipvs_talk(IP_VS_SO_SET_DELLADDR, 
                        &srule, 
                        NULL/*drule*/, 
                        NULL/*daemonrule*/, 
                        &laddr_rule, 
                        NULL/*blklst_rule*/, 
                        NULL/*whtlst_rule*/, 
                        NULL,
                        false);
            }
        }
    }
}

int
ipvs_laddr_remove_entry(virtual_server_t *vs, local_addr_entry *laddr_entry)
{
    dpvs_laddr_table_t laddr_rule;
    dpvs_service_compat_t srule;

    memset(&srule, 0, sizeof(dpvs_service_compat_t));
    srule.proto = vs->service_type;

    if (vs->vsgname) {
        ipvs_rm_lentry_from_vsg(laddr_entry, vs);
    } else if (!vs->vfwmark) {
        srule.af = vs->addr.ss_family;
        if (vs->addr.ss_family == AF_INET6) {
            srule.netmask = 128;
            inet_sockaddrip6(&vs->addr, &srule.addr.in6);
        } else {
            srule.netmask = 0xffffffff;
            srule.addr.in.s_addr = inet_sockaddrip4(&vs->addr);
        }
        srule.port = inet_sockaddrport(&vs->addr);

        if (laddr_entry->range) {
            dpvs_laddr_range_cmd(IP_VS_SO_SET_DELLADDR, laddr_entry, vs, &srule);
        } else {
            memset(&laddr_rule, 0, sizeof(dpvs_laddr_table_t));
            laddr_rule.af_l = laddr_entry->addr.ss_family;
            laddr_rule.af_s = vs->af;
            if (laddr_entry->addr.ss_family == AF_INET6)
                inet_sockaddrip6(&laddr_entry->addr, &laddr_rule.laddr.in6);
            else
                laddr_rule.laddr.in.s_addr = inet_sockaddrip4(&laddr_entry->addr);
            strncpy(laddr_rule.ifname, laddr_entry->ifname, sizeof(laddr_rule.ifname));

            ipvs_talk(IP_VS_SO_SET_DELLADDR, &srule, NULL, NULL, &laddr_rule, NULL, NULL, NULL, false);
        }
    }

    return IPVS_SUCCESS;
}

static void
ipvs_rm_bentry_from_vsg(blklst_addr_entry *blklst_entry, whtlst_addr_entry *whtlst_entry, const char *vsgname, dpvs_service_compat_t *srule)
{
    list l;
    element e;
    virtual_server_group_t *vsg;
    virtual_server_group_entry_t *vsg_entry;
    dpvs_blklst_t blklst_rule;
    dpvs_whtlst_t whtlst_rule;

    vsg = ipvs_get_group_by_name(vsgname, check_data->vs_group);
    if (!vsg) return; 

    l = vsg->addr_range;
    LIST_FOREACH(l, vsg_entry, e) {
        uint32_t addr_ip, ip;

        srule->af = vsg_entry->addr.ss_family;
        srule->netmask = (vsg_entry->addr.ss_family == AF_INET6) ? 128 : ((u_int32_t) 0xffffffff);
        srule->port = inet_sockaddrport(&vsg_entry->addr);
        if (vsg_entry->addr.ss_family == AF_INET6) {
            inet_sockaddrip6(&vsg_entry->addr, &srule->addr.in6);
            ip = srule->addr.in6.s6_addr32[3];
        } else {
            ip = inet_sockaddrip4(&vsg_entry->addr);
        }

        if (!vsg_entry->range) {
            if (srule->af == AF_INET6)
                srule->addr.in6.s6_addr32[3] = ip;
            else
                srule->addr.in.s_addr = ip;

            if (blklst_entry != NULL) {
                if(blklst_entry->ipset[0] != '\0') {
                    memset(&blklst_rule, 0, sizeof(dpvs_blklst_t));
                    strncpy(blklst_rule.ipset, blklst_entry->ipset, sizeof(blklst_rule.ipset) - 1);
                    ipvs_talk(IP_VS_SO_SET_DELBLKLST, srule, NULL, NULL, NULL, &blklst_rule, NULL, NULL, false);
                } else if (blklst_entry->range) {
                    ipvs_blklst_range_cmd(IP_VS_SO_SET_DELBLKLST, blklst_entry, srule);
                } else {
                    memset(&blklst_rule, 0, sizeof(dpvs_blklst_t));
                    blklst_rule.af = blklst_entry->addr.ss_family;
                    if (blklst_entry->addr.ss_family == AF_INET6)
                        inet_sockaddrip6(&blklst_entry->addr, &blklst_rule.subject.in6);
                    else
                        blklst_rule.subject.in.s_addr = inet_sockaddrip4(&blklst_entry->addr);
                    ipvs_talk(IP_VS_SO_SET_DELBLKLST, srule, NULL, NULL, NULL, &blklst_rule, NULL, NULL, false);
                }
            }
            if (whtlst_entry != NULL) {
                if (whtlst_entry->ipset[0] != '\0') {
                    memset(&whtlst_rule, 0, sizeof(dpvs_whtlst_t));
                    strncpy(whtlst_rule.ipset, whtlst_entry->ipset, sizeof(whtlst_rule.ipset) - 1);
                    ipvs_talk(IP_VS_SO_SET_DELWHTLST, srule, NULL, NULL, NULL, NULL, &whtlst_rule, NULL, false);
                } else if (whtlst_entry->range) {
                    ipvs_whtlst_range_cmd(IP_VS_SO_SET_DELWHTLST, whtlst_entry, srule);
                } else {
                    memset(&whtlst_rule, 0, sizeof(dpvs_whtlst_t));
                    whtlst_rule.af = whtlst_entry->addr.ss_family;
                    if (whtlst_entry->addr.ss_family == AF_INET6)
                        inet_sockaddrip6(&whtlst_entry->addr, &whtlst_rule.subject.in6);
                    else
                        whtlst_rule.subject.in.s_addr = inet_sockaddrip4(&whtlst_entry->addr);
                    ipvs_talk(IP_VS_SO_SET_DELWHTLST, srule, NULL, NULL, NULL, NULL, &whtlst_rule, NULL, false);
                }
            }
            continue;
        }

        for (addr_ip = ip;
                ((addr_ip >> 24) & 0xFF) <= vsg_entry->range;
                addr_ip += 0x01000000) {
            if (srule->af == AF_INET6)
                srule->addr.in6.s6_addr32[3] = addr_ip;
            else
                srule->addr.in.s_addr = addr_ip;
            if (blklst_entry != NULL)
            {
                if(blklst_entry->ipset[0] != '\0') {
                    memset(&blklst_rule, 0, sizeof(dpvs_blklst_t));
                    strncpy(blklst_rule.ipset, blklst_entry->ipset, sizeof(blklst_rule.ipset) - 1);
                    ipvs_talk(IP_VS_SO_SET_DELBLKLST, srule, NULL, NULL, NULL, &blklst_rule, NULL, NULL, false);
                } else if (blklst_entry->range) {
                    ipvs_blklst_range_cmd(IP_VS_SO_SET_DELBLKLST, blklst_entry, srule);
                } else {
                    memset(&blklst_rule, 0, sizeof(dpvs_blklst_t));
                    blklst_rule.af = blklst_entry->addr.ss_family;
                    if (blklst_entry->addr.ss_family == AF_INET6)
                        inet_sockaddrip6(&blklst_entry->addr, &blklst_rule.subject.in6);
                    else
                        blklst_rule.subject.in.s_addr = inet_sockaddrip4(&blklst_entry->addr);

                    ipvs_talk(IP_VS_SO_SET_DELBLKLST, srule, NULL, NULL, NULL, &blklst_rule, NULL, NULL, false);
                }
            }
            if (whtlst_entry != NULL) {
                if (whtlst_entry->ipset[0] != '\0') {
                    memset(&whtlst_rule, 0, sizeof(dpvs_whtlst_t));
                    strncpy(whtlst_rule.ipset, whtlst_entry->ipset, sizeof(whtlst_rule.ipset) - 1);
                    ipvs_talk(IP_VS_SO_SET_DELWHTLST, srule, NULL, NULL, NULL, NULL, &whtlst_rule, NULL, false);
                } else if (whtlst_entry->range) {
                    ipvs_whtlst_range_cmd(IP_VS_SO_SET_DELWHTLST, whtlst_entry, srule);
                } else {
                    memset(&whtlst_rule, 0, sizeof(dpvs_whtlst_t));
                    whtlst_rule.af = whtlst_entry->addr.ss_family;
                    if (whtlst_entry->addr.ss_family == AF_INET6)
                        inet_sockaddrip6(&whtlst_entry->addr, &whtlst_rule.subject.in6);
                    else
                        whtlst_rule.subject.in.s_addr = inet_sockaddrip4(&whtlst_entry->addr);
                    ipvs_talk(IP_VS_SO_SET_DELWHTLST, srule, NULL, NULL, NULL, NULL, &whtlst_rule, NULL, false);
                }
            }
        }
    }
}

int
ipvs_blklst_remove_entry(virtual_server_t *vs, blklst_addr_entry *blklst_entry)
{
    dpvs_service_compat_t srule;
    dpvs_blklst_t blklst_rule;

    memset(&srule, 0, sizeof(dpvs_service_compat_t));
    srule.proto = vs->service_type;

    if (vs->vsgname) {
        ipvs_rm_bentry_from_vsg(blklst_entry, NULL, vs->vsgname, &srule);
    } else if (!vs->vfwmark) {
        srule.af = vs->addr.ss_family;
        if (vs->addr.ss_family == AF_INET6) {
            srule.netmask = 128;
            inet_sockaddrip6(&vs->addr, &srule.addr.in6);
        } else {
            srule.netmask = 0xffffffff;
            srule.addr.in.s_addr = inet_sockaddrip4(&vs->addr);
        }
        srule.port = inet_sockaddrport(&vs->addr);

        if(blklst_entry->ipset[0] != '\0') {
            memset(&blklst_rule, 0, sizeof(dpvs_blklst_t));
            strncpy(blklst_rule.ipset, blklst_entry->ipset, sizeof(blklst_rule.ipset) - 1);
            ipvs_talk(IP_VS_SO_SET_DELBLKLST, &srule, NULL, NULL, NULL, &blklst_rule, NULL, NULL, false);
        } else if (blklst_entry->range) {
            ipvs_blklst_range_cmd(IP_VS_SO_SET_DELBLKLST, blklst_entry, &srule);
        } else {
            memset(&blklst_rule, 0, sizeof(dpvs_blklst_t));
            blklst_rule.af = blklst_entry->addr.ss_family;
            if (blklst_entry->addr.ss_family == AF_INET6)
                inet_sockaddrip6(&blklst_entry->addr, &blklst_rule.subject.in6);
            else
                blklst_rule.subject.in.s_addr = inet_sockaddrip4(&blklst_entry->addr);

            ipvs_talk(IP_VS_SO_SET_DELBLKLST, &srule, NULL, NULL, NULL, &blklst_rule, NULL, NULL, false);
        }
    }

    return IPVS_SUCCESS;
}

int
ipvs_whtlst_remove_entry(virtual_server_t *vs, whtlst_addr_entry *whtlst_entry)
{
    dpvs_service_compat_t srule;
    dpvs_whtlst_t whtlst_rule;

    memset(&srule, 0, sizeof(dpvs_service_compat_t));
    srule.proto = vs->service_type;

    if (vs->vsgname) {
        ipvs_rm_bentry_from_vsg(NULL, whtlst_entry, vs->vsgname, &srule);
    } else if (!vs->vfwmark) {
        srule.af = vs->addr.ss_family;
        if (vs->addr.ss_family == AF_INET6) {
            srule.netmask = 128;
            inet_sockaddrip6(&vs->addr, &srule.addr.in6);
        } else {
            srule.netmask = 0xffffffff;
            srule.addr.in.s_addr = inet_sockaddrip4(&vs->addr);
        }
        srule.port = inet_sockaddrport(&vs->addr);

        if (whtlst_entry->ipset[0] != '\0') {
            memset(&whtlst_rule, 0, sizeof(dpvs_whtlst_t));
            strncpy(whtlst_rule.ipset, whtlst_entry->ipset, sizeof(whtlst_rule.ipset) - 1);
            ipvs_talk(IP_VS_SO_SET_DELWHTLST, &srule, NULL, NULL, NULL, NULL, &whtlst_rule, NULL, false);
        } else if (whtlst_entry->range) {
            ipvs_whtlst_range_cmd(IP_VS_SO_SET_DELWHTLST, whtlst_entry, &srule);
        } else {
            memset(&whtlst_rule, 0, sizeof(dpvs_whtlst_t));
            whtlst_rule.af = whtlst_entry->addr.ss_family;
            if (whtlst_entry->addr.ss_family == AF_INET6)
                inet_sockaddrip6(&whtlst_entry->addr, &whtlst_rule.subject.in6);
            else
                whtlst_rule.subject.in.s_addr = inet_sockaddrip4(&whtlst_entry->addr);

            ipvs_talk(IP_VS_SO_SET_DELWHTLST, &srule, NULL, NULL, NULL, NULL, &whtlst_rule, NULL, false);
        }
    }

    return IPVS_SUCCESS;
}


/* Remove a specific vs group entry */
void
ipvs_group_remove_entry(virtual_server_t *vs, virtual_server_group_entry_t *vsge)
{
    real_server_t *rs;
    element e;
    dpvs_service_compat_t srule;
    dpvs_dest_compat_t drule;

    /* Prepare target rules */
    ipvs_set_srule(IP_VS_SO_SET_DELDEST, &srule, vs);
    if (vsge->is_fwmark)
        srule.fwmark = vsge->vfwmark;
    else
        srule.port = inet_sockaddrport(&vsge->addr);

    /* Process realserver queue */
    LIST_FOREACH(vs->rs, rs, e) {
        if (rs->alive) {
            /* Setting IPVS drule */
            ipvs_set_drule(IP_VS_SO_SET_DELDEST, &drule, rs);

            /* Set vs rule */
            if (vsge->is_fwmark) {
                /* Talk to the IPVS channel */
                ipvs_talk(IP_VS_SO_SET_DELDEST, &srule, &drule, NULL, NULL, NULL, NULL, NULL, false);
            }
            else
                ipvs_group_range_cmd(IP_VS_SO_SET_DELDEST, &srule, &drule, vsge);
        }
    }

    /* Remove VS entry if this is the last VS using it */
    unset_vsge_alive(vsge, vs);
    if (!is_vsge_alive(vsge, vs)) {
        if (vsge->range)
            ipvs_group_range_cmd(IP_VS_SO_SET_DEL, &srule, NULL, vsge);
        else {
            srule.af = vsge->addr.ss_family;
            if (vsge->addr.ss_family == AF_INET6)
                inet_sockaddrip6(&vsge->addr, &srule.addr.in6);
            else
                srule.addr.in.s_addr = inet_sockaddrip4(&vsge->addr);
            srule.port = inet_sockaddrport(&vsge->addr);
            srule.fwmark = vsge->vfwmark;

            ipvs_talk(IP_VS_SO_SET_DEL, &srule, NULL, NULL, NULL, NULL, NULL, NULL, false);
        }
    }
}

#ifdef _WITH_SNMP_CHECKER_
static inline bool
vsd_equal(real_server_t *rs, struct ip_vs_dest_entry_app *entry)
{
    if (entry->af != AF_INET && entry->af != AF_INET6)
        return false;

    if (rs->addr.ss_family != entry->af)
        return false;

    if (!inaddr_equal(entry->af, &entry->nf_addr,
                entry->af == AF_INET ? (void *)&((struct sockaddr_in *)&rs->addr)->sin_addr
                : (void *)&((struct sockaddr_in6 *)&rs->addr)->sin6_addr))
        return false;

    if (entry->user.port != (entry->af == AF_INET ? ((struct sockaddr_in *)&rs->addr)->sin_port
                : ((struct sockaddr_in6 *)&rs->addr)->sin6_port))
        return false;

    return true;
}

static void
ipvs_update_vs_stats(virtual_server_t *vs, uint32_t fwmark, union nf_inet_addr *nfaddr, uint16_t port)
{
    element e;
    struct ip_vs_get_dests_app *dests = NULL;
    real_server_t *rs;
    unsigned int i;
    ipvs_service_entry_t *serv;

    if (!(serv = ipvs_get_service(fwmark, vs->af, vs->service_type, nfaddr, port)))
        return;

    /* Update virtual server stats */
    vs->stats.conns		+= serv->stats.conns;
    vs->stats.inpkts	+= serv->stats.inpkts;
    vs->stats.outpkts	+= serv->stats.outpkts;
    vs->stats.inbytes	+= serv->stats.inbytes;
    vs->stats.outbytes	+= serv->stats.outbytes;
    vs->stats.cps		+= serv->stats.cps;
    vs->stats.inpps		+= serv->stats.inpps;
    vs->stats.outpps	+= serv->stats.outpps;
    vs->stats.inbps		+= serv->stats.inbps;
    vs->stats.outbps	+= serv->stats.outbps;

    /* Get real servers */
    dests = ipvs_get_dests(serv);
    FREE(serv);
    if (!dests)
        return;

    for (i = 0; i < dests->user.num_dests; i++) {
        rs = NULL;

        /* Is it the sorry server? */
        if (vs->s_svr && vsd_equal(vs->s_svr, &dests->user.entrytable[i]))
            rs = vs->s_svr;
        else {
            /* Search for a match in the list of real servers */
            for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
                rs = ELEMENT_DATA(e);
                if (vsd_equal(rs, &dests->user.entrytable[i]))
                    break;
            }
            if (!e)
                rs = NULL;
        }

        if (rs) {
            rs->activeconns		+= dests->user.entrytable[i].user.activeconns;
            rs->inactconns		+= dests->user.entrytable[i].user.inactconns;
            rs->persistconns	+= dests->user.entrytable[i].user.persistconns;
            rs->stats.conns		+= dests->user.entrytable[i].stats.conns;
            rs->stats.inpkts	+= dests->user.entrytable[i].stats.inpkts;
            rs->stats.outpkts	+= dests->user.entrytable[i].stats.outpkts;
            rs->stats.inbytes	+= dests->user.entrytable[i].stats.inbytes;
            rs->stats.outbytes	+= dests->user.entrytable[i].stats.outbytes;
            rs->stats.cps		+= dests->user.entrytable[i].stats.cps;
            rs->stats.inpps		+= dests->user.entrytable[i].stats.inpps;
            rs->stats.outpps	+= dests->user.entrytable[i].stats.outpps;
            rs->stats.inbps		+= dests->user.entrytable[i].stats.inbps;
            rs->stats.outbps	+= dests->user.entrytable[i].stats.outbps;
        }
    }
    FREE(dests);
}

/* Update statistics for a given virtual server. This includes
   statistics of real servers. The update is only done if we need
   refreshing. */
void
ipvs_update_stats(virtual_server_t *vs)
{
    element e, ge;
    virtual_server_group_entry_t *vsg_entry;
    uint32_t addr_ip;
    uint16_t port;
    union nf_inet_addr nfaddr;
    unsigned i;
    real_server_t *rs;
    time_t cur_time = time(NULL);

    if (cur_time - vs->lastupdated < STATS_REFRESH)
        return;
    vs->lastupdated = cur_time;

    /* Reset stats */
    memset(&vs->stats, 0, sizeof(vs->stats));
    if (vs->s_svr) {
        memset(&vs->s_svr->stats, 0, sizeof(vs->s_svr->stats));
        vs->s_svr->activeconns =
            vs->s_svr->inactconns = vs->s_svr->persistconns = 0;
    }
    for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
        rs = ELEMENT_DATA(e);
        memset(&rs->stats, 0, sizeof(rs->stats));
        rs->activeconns = rs->inactconns = rs->persistconns = 0;
    }

    /* Update the stats */
    if (vs->vsg) {
        for (ge = LIST_HEAD(vs->vsg->vfwmark); ge; ELEMENT_NEXT(ge)) {
            vsg_entry = ELEMENT_DATA(ge);
            ipvs_update_vs_stats(vs, vsg_entry->vfwmark, &nfaddr, 0);
        }
        for (ge = LIST_HEAD(vs->vsg->addr_range); ge; ELEMENT_NEXT(ge)) {
            vsg_entry = ELEMENT_DATA(ge);
            addr_ip = (vsg_entry->addr.ss_family == AF_INET6) ?
                ntohs(((struct sockaddr_in6 *)&vsg_entry->addr)->sin6_addr.s6_addr16[7]) :
                ntohl(((struct sockaddr_in *)&vsg_entry->addr)->sin_addr.s_addr);
            if (vsg_entry->addr.ss_family == AF_INET6)
                inet_sockaddrip6(&vsg_entry->addr, &nfaddr.in6);

            port = inet_sockaddrport(&vsg_entry->addr);
            for (i = 0; i <= vsg_entry->range; i++, addr_ip++) {
                if (vsg_entry->addr.ss_family == AF_INET6)
                    nfaddr.in6.s6_addr16[7] = htons(addr_ip);
                else
                    nfaddr.ip = htonl(addr_ip);

                ipvs_update_vs_stats(vs, 0, &nfaddr, port);
            }
        }
    } else if (vs->vfwmark) {
        memset(&nfaddr, 0, sizeof(nfaddr));
        ipvs_update_vs_stats(vs, vs->vfwmark, &nfaddr, 0);
    } else {
        memcpy(&nfaddr, (vs->addr.ss_family == AF_INET6)?
                (void*)(&((struct sockaddr_in6 *)&vs->addr)->sin6_addr):
                (void*)(&((struct sockaddr_in *)&vs->addr)->sin_addr),
                sizeof(nfaddr));
        ipvs_update_vs_stats(vs, 0, &nfaddr, inet_sockaddrport(&vs->addr));
    }
}
#endif /* _WITH_SNMP_CHECKER_ */

#ifdef _WITH_VRRP_
/*
 * Common IPVS functions
 */
/* Note: This function is called in the context of the vrrp child process, not the checker process */
void
ipvs_syncd_master(const struct lvs_syncd_config *config)
{
    ipvs_syncd_cmd(IPVS_STOPDAEMON, config, IPVS_BACKUP, false, false);
    ipvs_syncd_cmd(IPVS_STARTDAEMON, config, IPVS_MASTER, false, false);
}

/* Note: This function is called in the context of the vrrp child process, not the checker process */
void
ipvs_syncd_backup(const struct lvs_syncd_config *config)
{
    ipvs_syncd_cmd(IPVS_STOPDAEMON, config, IPVS_MASTER, false, false);
    ipvs_syncd_cmd(IPVS_STARTDAEMON, config, IPVS_BACKUP, false, false);
}
#endif
