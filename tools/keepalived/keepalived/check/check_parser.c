/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        Configuration file parser/reader. Place into the dynamic
 *              data structure representation the conf file representing
 *              the loadbalanced server pool.
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

#include "check_parser.h"
#include "check_data.h"
#include "check_api.h"
#include "global_data.h"
#include "global_parser.h"
#include "logger.h"
#include "parser.h"
#include "memory.h"
#include "utils.h"
#include "ipwrapper.h"


#define ESTABLISH_TIMOUT_MAX 3600
#define ESTABLISH_TIMOUT_MIN 1

/* SSL handlers */
static void
ssl_handler(vector_t *strvec)
{
	check_data->ssl = alloc_ssl();
}
static void
sslpass_handler(vector_t *strvec)
{
	check_data->ssl->password = set_value(strvec);
}
static void
sslca_handler(vector_t *strvec)
{
	check_data->ssl->cafile = set_value(strvec);
}
static void
sslcert_handler(vector_t *strvec)
{
	check_data->ssl->certfile = set_value(strvec);
}
static void
sslkey_handler(vector_t *strvec)
{
	check_data->ssl->keyfile = set_value(strvec);
}

/* Virtual Servers handlers */
static void
vsg_handler(vector_t *strvec)
{
	/* Fetch queued vsg */
	alloc_vsg(vector_slot(strvec, 1));
	alloc_value_block(strvec, alloc_vsg_entry);
}
static void
laddr_group_handler(vector_t *strvec)
{
	alloc_laddr_group(vector_slot(strvec, 1));
	alloc_value_block(strvec, alloc_laddr_entry);
}
static void
vs_handler(vector_t *strvec)
{
	alloc_vs(vector_slot(strvec, 1), vector_slot(strvec, 2));
}
static void
delay_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->delay_loop = atoi(vector_slot(strvec, 1)) * TIMER_HZ;
	if (vs->delay_loop < TIMER_HZ)
		vs->delay_loop = TIMER_HZ;
}
static void
lbalgo_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	char *str = vector_slot(strvec, 1);
	int size = sizeof (vs->sched);
	int str_len = strlen(str);

	if (size > str_len)
		size = str_len;

	memcpy(vs->sched, str, size);
}
static void
lbkind_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	char *str = vector_slot(strvec, 1);

	if (!strcmp(str, "NAT"))
		vs->loadbalancing_kind = IP_VS_CONN_F_MASQ;
	else if (!strcmp(str, "DR"))
		vs->loadbalancing_kind = IP_VS_CONN_F_DROUTE;
	else if (!strcmp(str, "TUN"))
		vs->loadbalancing_kind = IP_VS_CONN_F_TUNNEL;
	else if (!strcmp(str, "FNAT"))
		vs->loadbalancing_kind = IP_VS_CONN_F_FULLNAT;
	else if (!strcmp(str, "SNAT"))
		vs->loadbalancing_kind = IP_VS_CONN_F_SNAT;
	else
		log_message(LOG_INFO, "PARSER : unknown [%s] routing method.", str);
}
static void
natmask_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	inet_ston(vector_slot(strvec, 1), &vs->nat_mask);
}
static void
pto_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	char *str = vector_slot(strvec, 1);
	int size = sizeof (vs->timeout_persistence);
	int str_len = strlen(str);

	if (size > str_len)
		size = str_len;

	memcpy(vs->timeout_persistence, str, size);
}
static void
pgr_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	if (vs->addr.ss_family == AF_INET6)
		vs->granularity_persistence = atoi(vector_slot(strvec, 1));
	else
		inet_ston(vector_slot(strvec, 1), &vs->granularity_persistence);
}
static void
proto_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	char *str = vector_slot(strvec, 1);
	if(!strcmp(str, "UDP"))
		vs->service_type = IPPROTO_UDP;
	else if(!strcmp(str, "ICMP"))
		vs->service_type = IPPROTO_ICMP;
	else
		vs->service_type = IPPROTO_TCP; /*default*/
}
static void
hasuspend_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->ha_suspend = 1;
}
static void
ops_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->ops = 1;
}
static void
virtualhost_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->virtualhost = set_value(strvec);
}

/* Sorry Servers handlers */
static void
ssvr_handler(vector_t *strvec)
{
	alloc_ssvr(vector_slot(strvec, 1), vector_slot(strvec, 2));
}
static void
ssvri_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	if (vs->s_svr) {
		vs->s_svr->inhibit = 1;
	} else {
		log_message(LOG_ERR, "Ignoring sorry_server_inhibit used before or without sorry_server");
	}
}

/* Real Servers handlers */
static void
rs_handler(vector_t *strvec)
{
	alloc_rs(vector_slot(strvec, 1), vector_slot(strvec, 2));
}
static void
weight_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	rs->weight = atoi(vector_slot(strvec, 1));
	rs->iweight = rs->weight;
}
#ifdef _KRNL_2_6_
static void
uthreshold_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	rs->u_threshold = atoi(vector_slot(strvec, 1));
}
static void
lthreshold_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	rs->l_threshold = atoi(vector_slot(strvec, 1));
}
#endif
static void
inhibit_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	rs->inhibit = 1;
}
static void
notify_up_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	rs->notify_up = set_value(strvec);
}
static void
notify_down_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	rs->notify_down = set_value(strvec);
}
static void
alpha_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->alpha = 1;
	vs->quorum_state = DOWN;
}
static void
omega_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->omega = 1;
}
static void
quorum_up_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->quorum_up = set_value(strvec);
}
static void
quorum_down_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->quorum_down = set_value(strvec);
}
static void
quorum_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	long tmp = atol (vector_slot(strvec, 1));
	if (tmp < 1) {
		log_message(LOG_ERR, "Condition not met: Quorum >= 1");
		log_message(LOG_ERR, "Ignoring requested value %s, using 1 instead",
		  (char *) vector_slot(strvec, 1));
		tmp = 1;
	}
	vs->quorum = tmp;
}
static void
hysteresis_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	long tmp = atol (vector_slot(strvec, 1));
	if (tmp < 0) {
		log_message(LOG_ERR, "Condition not met: 0 <= Hysteresis");
		log_message(LOG_ERR, "Ignoring requested value %s, using 0 instead",
		       (char *) vector_slot(strvec, 1));
		tmp = 0;
	}
	vs->hysteresis = tmp;
}
static void 
laddr_gname_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	
	vs->local_addr_gname = set_value(strvec);
}
static void 
syn_proxy_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->syn_proxy = 1;
}
static void
bind_dev_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->vip_bind_dev = set_value(strvec);
}
static void
blklst_group_handler(vector_t *strvec)
{
	alloc_blklst_group(vector_slot(strvec, 1));
	alloc_value_block(strvec, alloc_blklst_entry);
}
static void
blklst_gname_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	vs->blklst_addr_gname = set_value(strvec);
}

static void
bps_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	char *str = vector_slot(strvec, 1);
	int size = sizeof (vs->bps);
	int str_len = strlen(str);

	if (size > str_len)
		size = str_len;
	memcpy(vs->bps, str, size);
}

static void
limit_proportion_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
        char *str = vector_slot(strvec, 1); 
        int size = sizeof (vs->limit_proportion);
        int str_len = strlen(str);
        memset(vs->limit_proportion,0,size);
        if (size > str_len)
                size = str_len;
        memcpy(vs->limit_proportion, str, size);
}

static void
establish_timeout_handler(vector_t *strvec)
{
    int conn_timeout;
    virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
    conn_timeout = atoi(vector_slot(strvec, 1));
    if (conn_timeout > ESTABLISH_TIMOUT_MAX)
        conn_timeout = ESTABLISH_TIMOUT_MAX;
    if (conn_timeout < ESTABLISH_TIMOUT_MIN)
        conn_timeout = ESTABLISH_TIMOUT_MIN;
    vs->conn_timeout = conn_timeout;
}

static void
src_range_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	snprintf(vs->srange, sizeof(vs->srange), "%s", (char *)vector_slot(strvec, 1));
}

static void
dst_range_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	snprintf(vs->drange, sizeof(vs->drange), "%s", (char *)vector_slot(strvec, 1));
}

static void
oif_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	snprintf(vs->iifname, sizeof(vs->iifname), "%s", (char *)vector_slot(strvec, 1));
}

static void
iif_handler(vector_t *strvec)
{
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	snprintf(vs->oifname, sizeof(vs->oifname), "%s", (char *)vector_slot(strvec, 1));
}

vector_t *
check_init_keywords(void)
{
	/* global definitions mapping */
	global_init_keywords();

	/* SSL mapping */
	install_keyword_root("SSL", &ssl_handler);
	install_keyword("password", &sslpass_handler);
	install_keyword("ca", &sslca_handler);
	install_keyword("certificate", &sslcert_handler);
	install_keyword("key", &sslkey_handler);

	/* local IP address mapping */
	install_keyword_root("local_address_group", &laddr_group_handler);
	/* blacklist IP */
	install_keyword_root("deny_address_group", &blklst_group_handler);

	/* Virtual server mapping */
	install_keyword_root("virtual_server_group", &vsg_handler);
	install_keyword_root("virtual_server", &vs_handler);
	install_keyword("delay_loop", &delay_handler);
	install_keyword("lb_algo", &lbalgo_handler);
	install_keyword("lvs_sched", &lbalgo_handler);
	install_keyword("lb_kind", &lbkind_handler);
	install_keyword("establish_timeout", &establish_timeout_handler);
	install_keyword("lvs_method", &lbkind_handler);
	install_keyword("nat_mask", &natmask_handler);
	install_keyword("persistence_timeout", &pto_handler);
	install_keyword("persistence_granularity", &pgr_handler);
	install_keyword("bps", &bps_handler);
	install_keyword("limit_proportion", &limit_proportion_handler);
	install_keyword("protocol", &proto_handler);
	install_keyword("ha_suspend", &hasuspend_handler);
	install_keyword("ops", &ops_handler);
	install_keyword("virtualhost", &virtualhost_handler);
	install_keyword("src-range", &src_range_handler);
	install_keyword("dst-range", &dst_range_handler);
	install_keyword("oif", &oif_handler);
	install_keyword("iif", &iif_handler);

	/* Pool regression detection and handling. */
	install_keyword("alpha", &alpha_handler);
	install_keyword("omega", &omega_handler);
	install_keyword("quorum_up", &quorum_up_handler);
	install_keyword("quorum_down", &quorum_down_handler);
	install_keyword("quorum", &quorum_handler);
	install_keyword("hysteresis", &hysteresis_handler);

	/* Real server mapping */
	install_keyword("sorry_server", &ssvr_handler);
	install_keyword("sorry_server_inhibit", &ssvri_handler);
	install_keyword("real_server", &rs_handler);
	install_sublevel();
	install_keyword("weight", &weight_handler);
#ifdef _KRNL_2_6_
	install_keyword("uthreshold", &uthreshold_handler);
	install_keyword("lthreshold", &lthreshold_handler);
#endif
	install_keyword("inhibit_on_failure", &inhibit_handler);
	install_keyword("notify_up", &notify_up_handler);
	install_keyword("notify_down", &notify_down_handler);

	/* Checkers mapping */
	install_checkers_keyword();
	install_sublevel_end();

	install_keyword("laddr_group_name", &laddr_gname_handler);
	install_keyword("daddr_group_name", &blklst_gname_handler);
	install_keyword("syn_proxy", &syn_proxy_handler);
	install_keyword("vip_bind_dev", &bind_dev_handler);

	return keywords;
}
