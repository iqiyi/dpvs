/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Healthcheckers dynamic data structure definition.
 *
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#include <netdb.h>
#include "check_data.h"
#include "check_api.h"
#include "logger.h"
#include "memory.h"
#include "utils.h"
#include "ipwrapper.h"

/* global vars */
check_data_t *check_data = NULL;
check_data_t *old_check_data = NULL;

/* SSL facility functions */
ssl_data_t *
alloc_ssl(void)
{
	ssl_data_t *ssl = (ssl_data_t *) MALLOC(sizeof(ssl_data_t));
	return ssl;
}
void
free_ssl(void)
{
	if (!check_data)
		return;

	ssl_data_t *ssl = check_data->ssl;

	if (!ssl)
		return;
	FREE_PTR(ssl->password);
	FREE_PTR(ssl->cafile);
	FREE_PTR(ssl->certfile);
	FREE_PTR(ssl->keyfile);
	FREE(ssl);
}
static void
dump_ssl(void)
{
	if (!check_data)
      return;

	ssl_data_t *ssl = check_data->ssl;

	if (ssl->password)
		log_message(LOG_INFO, " Password : %s", ssl->password);
	if (ssl->cafile)
		log_message(LOG_INFO, " CA-file : %s", ssl->cafile);
	if (ssl->certfile)
		log_message(LOG_INFO, " Certificate file : %s", ssl->certfile);
	if (ssl->keyfile)
		log_message(LOG_INFO, " Key file : %s", ssl->keyfile);
	if (!ssl->password && !ssl->cafile && !ssl->certfile && !ssl->keyfile)
		log_message(LOG_INFO, " Using autogen SSL context");
}

/* local IP address group facility functions */
static void
free_laddr_group(void *data)
{
	local_addr_group *laddr_group = data;
	FREE_PTR(laddr_group->gname);
	free_list(laddr_group->addr_ip);
	free_list(laddr_group->range);
	FREE(laddr_group);
}
static void
dump_laddr_group(void *data)
{
	local_addr_group *laddr_group = data;

	log_message(LOG_INFO, " local IP address group = %s", laddr_group->gname);
	dump_list(laddr_group->addr_ip);
	dump_list(laddr_group->range);
}
static void
free_laddr_entry(void *data)
{
	FREE(data);
}
static void
dump_laddr_entry(void *data)
{
	local_addr_entry *laddr_entry = data;

	if (laddr_entry->range)
		log_message(LOG_INFO, "   IP Range = %s-%d"
				    , inet_sockaddrtos(&laddr_entry->addr)
				    , laddr_entry->range);
	else
		log_message(LOG_INFO, "   IP = %s"
				    , inet_sockaddrtos(&laddr_entry->addr));
}
void
alloc_laddr_group(char *gname)
{
	int size = strlen(gname);
	local_addr_group *new;

	new = (local_addr_group *) MALLOC(sizeof (local_addr_group));
	new->gname = (char *) MALLOC(size + 1);
	memcpy(new->gname, gname, size);
	new->addr_ip = alloc_list(free_laddr_entry, dump_laddr_entry);
	new->range = alloc_list(free_laddr_entry, dump_laddr_entry);

	list_add(check_data->laddr_group, new);
}
void
alloc_laddr_entry(vector_t *strvec)
{
	local_addr_group *laddr_group = LIST_TAIL_DATA(check_data->laddr_group);
	local_addr_entry *new;

	new = (local_addr_entry *) MALLOC(sizeof (local_addr_entry));


	new->range = inet_stor(vector_slot(strvec, 0));
	inet_stosockaddr(vector_slot(strvec, 0), NULL, &new->addr);
	strncpy(new->ifname, vector_slot(strvec, 1), sizeof(new->ifname));
    
	if (!new->range)
		list_add(laddr_group->addr_ip, new);
	else if ( (0 < new->range) && (new->range < 255) )
		list_add(laddr_group->range, new);
	else
		log_message(LOG_INFO, "invalid: local IP address range %d", new->range);
}

/* blacklist IP address group facility functions */
static void
free_blklst_group(void *data)
{
        blklst_addr_group *blklst_group = data;
        FREE_PTR(blklst_group->gname);
        free_list(blklst_group->addr_ip);
        free_list(blklst_group->range);
        FREE(blklst_group);
}
static void
dump_blklst_group(void *data)
{
        blklst_addr_group *blklst_group = data;

        log_message(LOG_INFO, " blacllist IP address group = %s", blklst_group->gname);
        dump_list(blklst_group->addr_ip);
        dump_list(blklst_group->range);
}
static void
free_blklst_entry(void *data)
{
        FREE(data);
}
static void
dump_blklst_entry(void *data)
{
        blklst_addr_entry *blklst_entry = data;

        if (blklst_entry->range)
                log_message(LOG_INFO, "   IP Range = %s-%d"
                                    , inet_sockaddrtos(&blklst_entry->addr)
                                    , blklst_entry->range);
        else
                log_message(LOG_INFO, "   IP = %s"
                                    , inet_sockaddrtos(&blklst_entry->addr));
}
void
alloc_blklst_group(char *gname)
{
        int size = strlen(gname);
        blklst_addr_group *new;

        new = (blklst_addr_group *) MALLOC(sizeof (blklst_addr_group));
        new->gname = (char *) MALLOC(size + 1);
        memcpy(new->gname, gname, size);
        new->addr_ip = alloc_list(free_blklst_entry, dump_blklst_entry);
        new->range = alloc_list(free_blklst_entry, dump_blklst_entry);

        list_add(check_data->blklst_group, new);
}
void
alloc_blklst_entry(vector_t *strvec)
{
        blklst_addr_group *blklst_group = LIST_TAIL_DATA(check_data->blklst_group);
        blklst_addr_entry *new;

        new = (blklst_addr_entry *) MALLOC(sizeof (blklst_addr_entry));

        new->range = inet_stor(vector_slot(strvec, 0));
        inet_stosockaddr(vector_slot(strvec, 0), NULL, &new->addr);

        if (!new->range)
                list_add(blklst_group->addr_ip, new);
        else if ( (0 < new->range) && (new->range < 255) )
                list_add(blklst_group->range, new);
        else
                log_message(LOG_INFO, "invalid: blacklist IP address range %d", new->range);
}

/* Virtual server group facility functions */
static void
free_vsg(void *data)
{
	virtual_server_group_t *vsg = data;
	FREE_PTR(vsg->gname);
	free_list(vsg->addr_ip);
	free_list(vsg->range);
	free_list(vsg->vfwmark);
	FREE(vsg);
}
static void
dump_vsg(void *data)
{
	virtual_server_group_t *vsg = data;

	log_message(LOG_INFO, " Virtual Server Group = %s", vsg->gname);
	dump_list(vsg->addr_ip);
	dump_list(vsg->range);
	dump_list(vsg->vfwmark);
}
static void
free_vsg_entry(void *data)
{
	FREE(data);
}
static void
dump_vsg_entry(void *data)
{
	virtual_server_group_entry_t *vsg_entry = data;

	if (vsg_entry->vfwmark)
		log_message(LOG_INFO, "   FWMARK = %d", vsg_entry->vfwmark);
	else if (vsg_entry->range)
		log_message(LOG_INFO, "   VIP Range = %s-%d, VPORT = %d"
				    , inet_sockaddrtos(&vsg_entry->addr)
				    , vsg_entry->range
				    , ntohs(inet_sockaddrport(&vsg_entry->addr)));
	else
		log_message(LOG_INFO, "   VIP = %s, VPORT = %d"
				    , inet_sockaddrtos(&vsg_entry->addr)
				    , ntohs(inet_sockaddrport(&vsg_entry->addr)));
}
void
alloc_vsg(char *gname)
{
	int size = strlen(gname);
	virtual_server_group_t *new;

	new = (virtual_server_group_t *) MALLOC(sizeof(virtual_server_group_t));
	new->gname = (char *) MALLOC(size + 1);
	memcpy(new->gname, gname, size);
	new->addr_ip = alloc_list(free_vsg_entry, dump_vsg_entry);
	new->range = alloc_list(free_vsg_entry, dump_vsg_entry);
	new->vfwmark = alloc_list(free_vsg_entry, dump_vsg_entry);

	list_add(check_data->vs_group, new);
}
void
alloc_vsg_entry(vector_t *strvec)
{
	virtual_server_group_t *vsg = LIST_TAIL_DATA(check_data->vs_group);
	virtual_server_group_entry_t *new;

	new = (virtual_server_group_entry_t *) MALLOC(sizeof(virtual_server_group_entry_t));

	if (!strcmp(vector_slot(strvec, 0), "fwmark")) {
		new->vfwmark = atoi(vector_slot(strvec, 1));
		list_add(vsg->vfwmark, new);
	} else {
		new->range = inet_stor(vector_slot(strvec, 0));
		inet_stosockaddr(vector_slot(strvec, 0), vector_slot(strvec, 1), &new->addr);
		if (!new->range)
			list_add(vsg->addr_ip, new);
		else
			list_add(vsg->range, new);
	}
}

/* Virtual server facility functions */
static void
free_vs(void *data)
{
	virtual_server_t *vs = data;
	FREE_PTR(vs->vsgname);
	FREE_PTR(vs->virtualhost);
	FREE_PTR(vs->s_svr);
	free_list(vs->rs);
	FREE_PTR(vs->quorum_up);
	FREE_PTR(vs->quorum_down);
	FREE_PTR(vs->local_addr_gname);
	FREE_PTR(vs->blklst_addr_gname);
	FREE_PTR(vs->vip_bind_dev);
	FREE(vs);
}
static void
dump_vs(void *data)
{
	virtual_server_t *vs = data;

	if (vs->vsgname)
		log_message(LOG_INFO, " VS GROUP = %s", vs->vsgname);
	else if (vs->vfwmark)
		log_message(LOG_INFO, " VS FWMARK = %d", vs->vfwmark);
	else
		log_message(LOG_INFO, " VIP = %s, VPORT = %d"
				    , inet_sockaddrtos(&vs->addr), ntohs(inet_sockaddrport(&vs->addr)));
	if (vs->virtualhost)
		log_message(LOG_INFO, "   VirtualHost = %s", vs->virtualhost);
	log_message(LOG_INFO, "   delay_loop = %lu, lb_algo = %s",
	       (vs->delay_loop >= TIMER_MAX_SEC) ? vs->delay_loop/TIMER_HZ :
						   vs->delay_loop,
	       vs->sched);
	if (atoi(vs->timeout_persistence) > 0)
		log_message(LOG_INFO, "   persistence timeout = %s",
		       vs->timeout_persistence);
	if (vs->granularity_persistence)
		log_message(LOG_INFO, "   persistence granularity = %s",
		       inet_ntop2(vs->granularity_persistence));
	if (atoi(vs->bps) > 0)
		log_message(LOG_INFO, "   in bytes per second = %s",
			vs->bps);
        if (atoi(vs->limit_proportion) > 0 && atoi(vs->limit_proportion) < 100)
                log_message(LOG_INFO, "   limit proportion = %s",
                        vs->limit_proportion);
	log_message(LOG_INFO, "   protocol = %s",
	       (vs->service_type == IPPROTO_TCP) ? "TCP" : "UDP");
	log_message(LOG_INFO, "   alpha is %s, omega is %s",
		    vs->alpha ? "ON" : "OFF", vs->omega ? "ON" : "OFF");
	log_message(LOG_INFO, "   SYN proxy is %s", 
		    vs->syn_proxy ? "ON" : "OFF");
	log_message(LOG_INFO, "   quorum = %lu, hysteresis = %lu", vs->quorum, vs->hysteresis);
	if (vs->quorum_up)
		log_message(LOG_INFO, "   -> Notify script UP = %s",
			    vs->quorum_up);
	if (vs->quorum_down)
		log_message(LOG_INFO, "   -> Notify script DOWN = %s",
			    vs->quorum_down);
	if (vs->ha_suspend)
		log_message(LOG_INFO, "   Using HA suspend");

	switch (vs->loadbalancing_kind) {
#ifdef _WITH_LVS_
	case IP_VS_CONN_F_MASQ:
		log_message(LOG_INFO, "   lb_kind = NAT");
		break;
	case IP_VS_CONN_F_DROUTE:
		log_message(LOG_INFO, "   lb_kind = DR");
		break;
	case IP_VS_CONN_F_TUNNEL:
		log_message(LOG_INFO, "   lb_kind = TUN");
		break;
	case IP_VS_CONN_F_FULLNAT:
		log_message(LOG_INFO, "   lb_kind = FNAT");
		break;
	case IP_VS_CONN_F_SNAT:
		log_message(LOG_INFO, "   lb_kind = SNAT");
		break;
#endif
	}

	if (vs->s_svr) {
		log_message(LOG_INFO, "   sorry server = %s"
				    , FMT_RS(vs->s_svr));
	}
	if (!LIST_ISEMPTY(vs->rs))
		dump_list(vs->rs);
	if (vs->local_addr_gname)
		log_message(LOG_INFO, " LOCAL_ADDR GROUP = %s", vs->local_addr_gname);
        if (vs->blklst_addr_gname)
                log_message(LOG_INFO, " BLACK_LIST GROUP = %s", vs->blklst_addr_gname);
	if (vs->vip_bind_dev)
		log_message(LOG_INFO, " vip_bind_dev = %s", vs->vip_bind_dev);
}

void
alloc_vs(char *ip, char *port)
{
	int size = strlen(port);
	virtual_server_t *new;

	new = (virtual_server_t *) MALLOC(sizeof(virtual_server_t));

	if (!strcmp(ip, "group")) {
		new->vsgname = (char *) MALLOC(size + 1);
		memcpy(new->vsgname, port, size);
	} else if (!strcmp(ip, "fwmark")) {
		new->vfwmark = atoi(port);
	} else if (!strcmp(ip, "match")) {
		new->loadbalancing_kind = IP_VS_CONN_F_SNAT;
	} else {
		inet_stosockaddr(ip, port, &new->addr);
	}

	new->delay_loop = KEEPALIVED_DEFAULT_DELAY;
	strncpy(new->timeout_persistence, "0", 1);
	strncpy(new->bps, "0", 1);
	strncpy(new->limit_proportion, "100", 3);
	new->conn_timeout = 0;
	new->virtualhost = NULL;
	new->alpha = 0;
	new->omega = 0;
	new->syn_proxy = 0;
	new->quorum_up = NULL;
	new->quorum_down = NULL;
	new->quorum = 1;
	new->hysteresis = 0;
	new->quorum_state = UP;
	new->local_addr_gname = NULL;
	new->blklst_addr_gname = NULL;
	new->vip_bind_dev = NULL;
	memset(new->srange, 0, 256);
	memset(new->drange, 0, 256);
	memset(new->iifname, 0, IFNAMSIZ);
	memset(new->oifname, 0, IFNAMSIZ);

	list_add(check_data->vs, new);
}

/* Sorry server facility functions */
void
alloc_ssvr(char *ip, char *port)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);

	vs->s_svr = (real_server_t *) MALLOC(sizeof(real_server_t));
	vs->s_svr->weight = 1;
	vs->s_svr->iweight = 1;
	inet_stosockaddr(ip, port, &vs->s_svr->addr);
}

/* Real server facility functions */
static void
free_rs(void *data)
{
	real_server_t *rs = data;
	FREE_PTR(rs->notify_up);
	FREE_PTR(rs->notify_down);
	free_list(rs->failed_checkers);
	FREE(rs);
}
static void
dump_rs(void *data)
{
	real_server_t *rs = data;

	log_message(LOG_INFO, "   RIP = %s, RPORT = %d, WEIGHT = %d"
			    , inet_sockaddrtos(&rs->addr)
			    , ntohs(inet_sockaddrport(&rs->addr))
			    , rs->weight);
	if (rs->inhibit)
		log_message(LOG_INFO, "     -> Inhibit service on failure");
	if (rs->notify_up)
		log_message(LOG_INFO, "     -> Notify script UP = %s",
		       rs->notify_up);
	if (rs->notify_down)
		log_message(LOG_INFO, "     -> Notify script DOWN = %s",
		       rs->notify_down);
}

static void
free_failed_checkers(void *data)
{
	FREE(data);
}

void
alloc_rs(char *ip, char *port)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *new;

	new = (real_server_t *) MALLOC(sizeof(real_server_t));
	inet_stosockaddr(ip, port, &new->addr);

	new->weight = 1;
	new->iweight = 1;
	new->failed_checkers = alloc_list(free_failed_checkers, NULL);

	if (LIST_ISEMPTY(vs->rs))
		vs->rs = alloc_list(free_rs, dump_rs);
	list_add(vs->rs, new);
}

/* data facility functions */
check_data_t *
alloc_check_data(void)
{
	check_data_t *new;

	new = (check_data_t *) MALLOC(sizeof(check_data_t));
	new->vs = alloc_list(free_vs, dump_vs);
	new->vs_group = alloc_list(free_vsg, dump_vsg);
	new->laddr_group = alloc_list(free_laddr_group, dump_laddr_group);
	new->blklst_group = alloc_list(free_blklst_group, dump_blklst_group);

	return new;
}

void
free_check_data(check_data_t *data)
{
	if (!check_data)
		return;
	free_list(data->vs);
	free_list(data->vs_group);
	free_list(data->laddr_group);
	free_list(data->blklst_group);
	FREE(data);
}

void
dump_check_data(check_data_t *data)
{
	if (data->ssl) {
		log_message(LOG_INFO, "------< SSL definitions >------");
		dump_ssl();
	}
	if (!LIST_ISEMPTY(data->vs)) {
		log_message(LOG_INFO, "------< LVS Topology >------");
		log_message(LOG_INFO, " System is compiled with LVS v%d.%d.%d",
		       NVERSION(IP_VS_VERSION_CODE));
		if (!LIST_ISEMPTY(data->laddr_group))
			dump_list(data->laddr_group);
		if (!LIST_ISEMPTY(data->blklst_group))
			dump_list(data->blklst_group);
		if (!LIST_ISEMPTY(data->vs_group))
			dump_list(data->vs_group);
		dump_list(data->vs);
	}
	dump_checkers_queue();
}

char *
format_vs (virtual_server_t *vs)
{
	static char addr_str[INET6_ADDRSTRLEN + 1];
	/* alloc large buffer because of unknown length of vs->vsgname */
	static char ret[512];

	if (vs->vsgname)
		snprintf (ret, sizeof (ret) - 1, "[%s]:%d"
			, vs->vsgname
			, ntohs(inet_sockaddrport(&vs->addr)));
	else if (vs->vfwmark)
		snprintf (ret, sizeof (ret) - 1, "FWM %d", vs->vfwmark);
	else {
		inet_sockaddrtos2(&vs->addr, addr_str);
		snprintf(ret, sizeof(ret) - 1, "[%s]:%d"
			, addr_str
			, ntohs(inet_sockaddrport(&vs->addr)));
	}
	return ret;
}
