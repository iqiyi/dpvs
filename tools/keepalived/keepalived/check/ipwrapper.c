/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Manipulation functions for IPVS & IPFW wrappers.
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

#include "ipwrapper.h"
#include "ipvswrapper.h"
#include "logger.h"
#include "memory.h"
#include "utils.h"
#include "notify.h"
#include "main.h"
#ifdef _WITH_SNMP_
  #include "check_snmp.h"
#endif
/* out-of-order functions declarations */
static void update_quorum_state(virtual_server_t * vs);

/* Returns the sum of all RS weight in a virtual server. */
long unsigned
weigh_live_realservers(virtual_server_t * vs)
{
	element e;
	real_server_t *svr;
	long unsigned count = 0;

	for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
		svr = ELEMENT_DATA(e);
		if (ISALIVE(svr))
			count += svr->weight;
	}
	return count;
}

/* Remove a realserver IPVS rule */
static int
clear_service_rs(list vs_group, virtual_server_t * vs, list l)
{
	element e;
	real_server_t *rs;
	long unsigned weight_sum;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		if (ISALIVE(rs)) {
			log_message(LOG_INFO, "Removing service %s from VS %s"
						, FMT_RS(rs)
						, FMT_VS(vs));
			if (!ipvs_cmd(LVS_CMD_DEL_DEST, vs_group, vs, rs))
				return 0;
			UNSET_ALIVE(rs);
			if (!vs->omega)
				continue;

			/* In Omega mode we call VS and RS down notifiers
			 * all the way down the exit, as necessary.
			 */
			if (rs->notify_down) {
				log_message(LOG_INFO, "Executing [%s] for service %s in VS %s"
						    , rs->notify_down
						    , FMT_RS(rs)
						    , FMT_VS(vs));
				notify_exec(rs->notify_down);
			}
#ifdef _WITH_SNMP_
			check_snmp_rs_trap(rs, vs);
#endif

			/* Sooner or later VS will lose the quorum (if any). However,
			 * we don't push in a sorry server then, hence the regression
			 * is intended.
			 */
			weight_sum = weigh_live_realservers(vs);
			if (vs->quorum_state == UP && (
				!weight_sum ||
				weight_sum < vs->quorum - vs->hysteresis)
			) {
				vs->quorum_state = DOWN;
				if (vs->quorum_down) {
					log_message(LOG_INFO, "Executing [%s] for VS %s"
							    , vs->quorum_down
							    , FMT_VS(vs));
					notify_exec(vs->quorum_down);
				}
#ifdef _WITH_SNMP_
				check_snmp_quorum_trap(vs);
#endif
			}
		}
	}

	return 1;
}

/* Remove a virtualserver IPVS rule */
static int
clear_service_vs(list vs_group, virtual_server_t * vs)
{
	/* Processing real server queue */
	if (!LIST_ISEMPTY(vs->rs)) {
		if (vs->s_svr) {
			if (ISALIVE(vs->s_svr))
				if (!ipvs_cmd(LVS_CMD_DEL_DEST, vs_group, vs, vs->s_svr))
					return 0;
		} else if (!clear_service_rs(vs_group, vs, vs->rs))
			return 0;
		/* The above will handle Omega case for VS as well. */
	}

	if (!ipvs_cmd(LVS_CMD_DEL, vs_group, vs, NULL))
		return 0;

	UNSET_ALIVE(vs);
	return 1;
}

/* IPVS cleaner processing */
int
clear_services(void)
{
	if (!check_data)
		return 0;

	element e;
	list l = check_data->vs;
	virtual_server_t *vs;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vs = ELEMENT_DATA(e);
		if (!clear_service_vs(check_data->vs_group, vs))
			return 0;
	}
	return 1;
}

/* Set a realserver IPVS rules */
static int
init_service_rs(virtual_server_t * vs)
{
	element e;
	real_server_t *rs;

	for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		/* In alpha mode, be pessimistic (or realistic?) and don't
		 * add real servers into the VS pool. They will get there
		 * later upon healthchecks recovery (if ever).
		 */
		if (vs->alpha) {
			if (! rs->reloaded)
				UNSET_ALIVE(rs);
			continue;
		}
		if (!ISALIVE(rs)) {
			if (!ipvs_cmd(LVS_CMD_ADD_DEST, check_data->vs_group, vs, rs))
				return 0;
			else
				SET_ALIVE(rs);
		} else if (vs->vsgname) {
			UNSET_ALIVE(rs);
			if (!ipvs_cmd(LVS_CMD_ADD_DEST, check_data->vs_group, vs, rs))
				return 0;
			SET_ALIVE(rs);
		}
	}

	return 1;
}

/* Set a virtualserver IPVS rules */
static int
init_service_vs(virtual_server_t * vs)
{
	/* Init the VS root */
	if (!ISALIVE(vs) || vs->vsgname) {
		if (!ipvs_cmd(LVS_CMD_ADD, check_data->vs_group, vs, NULL))
			return 0;
		else
			SET_ALIVE(vs);
	}

	/* Set local ip address in "FNAT" mode of IPVS */
	if (vs->local_addr_gname &&
        (vs->loadbalancing_kind == IP_VS_CONN_F_FULLNAT ||
         vs->loadbalancing_kind == IP_VS_CONN_F_SNAT)) {
		if (!ipvs_cmd(LVS_CMD_ADD_LADDR, check_data->vs_group, vs, NULL))
			return 0; 
	}
    
    /*Set blacklist ip address */
    if (vs->blklst_addr_gname) {
        if (!ipvs_cmd(LVS_CMD_ADD_BLKLST, check_data->vs_group, vs, NULL))
            return 0;
    }
        
	/* Processing real server queue */
	if (!LIST_ISEMPTY(vs->rs)) {
		if (vs->alpha && ! vs->reloaded)
			vs->quorum_state = DOWN;
		if (!init_service_rs(vs))
			return 0;
	}

	/* if the service was reloaded, we may have got/lost quorum due to quorum setting changed */
	if (vs->reloaded)
		update_quorum_state(vs);

	return 1;
}

/* Set IPVS rules */
int
init_services(void)
{
	element e;
	list l = check_data->vs;
	virtual_server_t *vs;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vs = ELEMENT_DATA(e);
		if (!init_service_vs(vs))
			return 0;
	}
	return 1;
}

static int init_tunnel_entry(tunnel_entry *entry)
{
	return ipvs_tunnel_cmd(LVS_CMD_ADD_TUNNEL, entry);
}

static int init_tunnel_group(tunnel_group* group)
{
	list l;
	element e;
	tunnel_entry* entry;

	l = group->tunnel_entry;
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		entry = ELEMENT_DATA(e);
		if (!init_tunnel_entry(entry)) {
			log_message(LOG_ERR, "%s create tunnel %s error.", __FUNCTION__, entry->ifname);
			return IPVS_ERROR;
		}
	}

	return IPVS_SUCCESS;
}

int init_tunnel(void)
{
	element e;
	list l = check_data->tunnel_group;
	tunnel_group* entry;

	if (LIST_ISEMPTY(l))
		return IPVS_SUCCESS;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		entry = ELEMENT_DATA(e);
		if (!init_tunnel_group(entry)) {
			log_message(LOG_ERR, "%s create tunnel group %s error.", __FUNCTION__, entry->gname);
			return IPVS_ERROR;
		}
	}
	return IPVS_SUCCESS;
}

/* add or remove _alive_ real servers from a virtual server */
void
perform_quorum_state(virtual_server_t *vs, int add)
{
	element e;
	real_server_t *rs;

	if (LIST_ISEMPTY(vs->rs))
		return;

	log_message(LOG_INFO, "%s the pool for VS %s"
			    , add?"Adding alive servers to":"Removing alive servers from"
			    , FMT_VS(vs));
	for (e = LIST_HEAD(vs->rs); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		if (!ISALIVE(rs)) /* We only handle alive servers */
			continue;
		if (add)
			rs->alive = 0;
		ipvs_cmd(add?LVS_CMD_ADD_DEST:LVS_CMD_DEL_DEST, check_data->vs_group, vs, rs);
		rs->alive = 1;
	}
}

/* set quorum state depending on current weight of real servers */
static void
update_quorum_state(virtual_server_t * vs)
{
	long unsigned weight_sum = weigh_live_realservers(vs);

	/* If we have just gained quorum, it's time to consider notify_up. */
	if (vs->quorum_state == DOWN &&
	    weight_sum >= vs->quorum + vs->hysteresis) {
		vs->quorum_state = UP;
		log_message(LOG_INFO, "Gained quorum %lu+%lu=%lu <= %u for VS %s"
				    , vs->quorum
				    , vs->hysteresis
				    , vs->quorum + vs->hysteresis
				    , weight_sum
				    , FMT_VS(vs));
		if (vs->s_svr && ISALIVE(vs->s_svr)) {
			log_message(LOG_INFO, "%s sorry server %s from VS %s"
					    , (vs->s_svr->inhibit ? "Disabling" : "Removing")
					    , FMT_RS(vs->s_svr)
					    , FMT_VS(vs));

			ipvs_cmd(LVS_CMD_DEL_DEST, check_data->vs_group, vs, vs->s_svr);
			vs->s_svr->alive = 0;

			/* Adding back alive real servers */
			perform_quorum_state(vs, 1);
		}
		if (vs->quorum_up) {
			log_message(LOG_INFO, "Executing [%s] for VS %s"
					    , vs->quorum_up
					    , FMT_VS(vs));
			notify_exec(vs->quorum_up);
		}
#ifdef _WITH_SNMP_
               check_snmp_quorum_trap(vs);
#endif
		return;
	}

	/* If we have just lost quorum for the VS, we need to consider
	 * VS notify_down and sorry_server cases
	 */
	if (vs->quorum_state == UP && (
		!weight_sum ||
	    weight_sum < vs->quorum - vs->hysteresis)
	) {
		vs->quorum_state = DOWN;
		log_message(LOG_INFO, "Lost quorum %lu-%lu=%lu > %u for VS %s"
				    , vs->quorum
				    , vs->hysteresis
				    , vs->quorum - vs->hysteresis
				    , weight_sum
				    , FMT_VS(vs));
		if (vs->quorum_down) {
			log_message(LOG_INFO, "Executing [%s] for VS %s"
					    , vs->quorum_down
					    , FMT_VS(vs));
			notify_exec(vs->quorum_down);
		}
		if (vs->s_svr) {
			log_message(LOG_INFO, "%s sorry server %s to VS %s"
					    , (vs->s_svr->inhibit ? "Enabling" : "Adding")
					    , FMT_RS(vs->s_svr)
					    , FMT_VS(vs));

			/* the sorry server is now up in the pool, we flag it alive */
			ipvs_cmd(LVS_CMD_ADD_DEST, check_data->vs_group, vs, vs->s_svr);
			vs->s_svr->alive = 1;

			/* Remove remaining alive real servers */
			perform_quorum_state(vs, 0);
		}
#ifdef _WITH_SNMP_
		check_snmp_quorum_trap(vs);
#endif
		return;
	}
}

/* manipulate add/remove rs according to alive state */
bool
perform_svr_state(int alive, virtual_server_t * vs, real_server_t * rs)
{
	/*
	 * | ISALIVE(rs) | alive | context
	 * | 0           | 0     | first check failed under alpha mode, unreachable here
	 * | 0           | 1     | RS went up, add it to the pool
	 * | 1           | 0     | RS went down, remove it from the pool
	 * | 1           | 1     | first check succeeded w/o alpha mode, unreachable here
	 */
	if (!ISALIVE(rs) && alive) {
		log_message(LOG_INFO, "%s service %s to VS %s"
				    , (rs->inhibit) ? "Enabling" : "Adding"
				    , FMT_RS(rs)
				    , FMT_VS(vs));
		/* Add only if we have quorum or no sorry server */
		if (vs->quorum_state == UP || !vs->s_svr || !ISALIVE(vs->s_svr)) {
			if (ipvs_cmd(LVS_CMD_ADD_DEST, check_data->vs_group, vs, rs) != IPVS_SUCCESS) {
				log_message(LOG_INFO, "LVS cmd add dest fail!");
				return false;
			}
		}
		rs->alive = alive;
		if (rs->notify_up) {
			log_message(LOG_INFO, "Executing [%s] for service %s in VS %s"
					    , rs->notify_up
					    , FMT_RS(rs)
					    , FMT_VS(vs));
			notify_exec(rs->notify_up);
		}
#ifdef _WITH_SNMP_
		check_snmp_rs_trap(rs, vs);
#endif

		/* We may have gained quorum */
		update_quorum_state(vs);
	}

	if (ISALIVE(rs) && !alive) {
		log_message(LOG_INFO, "%s service %s from VS %s"
				    , (rs->inhibit) ? "Disabling" : "Removing"
				    , FMT_RS(rs)
				    , FMT_VS(vs));

		/* server is down, it is removed from the LVS realserver pool
		 * Remove only if we have quorum or no sorry server
		 */
		if (vs->quorum_state == UP || !vs->s_svr || !ISALIVE(vs->s_svr)) {
			if (ipvs_cmd(LVS_CMD_DEL_DEST, check_data->vs_group, vs, rs) != IPVS_SUCCESS) {
				log_message(LOG_INFO, "LVS cmd del dest fail!");
				return false;
			}
		}
		rs->alive = alive;
		if (rs->notify_down) {
			log_message(LOG_INFO, "Executing [%s] for service %s in VS %s"
					    , rs->notify_down
					    , FMT_RS(rs)
					    , FMT_VS(vs));
			notify_exec(rs->notify_down);
		}
#ifdef _WITH_SNMP_
		check_snmp_rs_trap(rs, vs);
#endif

		/* We may have lost quorum */
		update_quorum_state(vs);
	}
	return true;
}

/* Store new weight in real_server struct and then update kernel. */
void
update_svr_wgt(int weight, virtual_server_t * vs, real_server_t * rs)
{
	if (weight != rs->weight) {
		log_message(LOG_INFO, "Changing weight from %d to %d for %s service %s of VS %s"
				    , rs->weight
				    , weight
				    , ISALIVE(rs) ? "active" : "inactive"
				    , FMT_RS(rs)
				    , FMT_VS(vs));
		rs->weight = weight;
		/*
		 * Have weight change take effect now only if rs is in
		 * the pool and alive and the quorum is met (or if
		 * there is no sorry server). If not, it will take
		 * effect later when it becomes alive.
		 */
		if (rs->set && ISALIVE(rs) &&
		    (vs->quorum_state == UP || !vs->s_svr || !ISALIVE(vs->s_svr)))
			ipvs_cmd(LVS_CMD_EDIT_DEST, check_data->vs_group, vs, rs);
		update_quorum_state(vs);
	}
}

/* Test if realserver is marked UP for a specific checker */
int
svr_checker_up(checker_id_t cid, real_server_t *rs)
{
	element e;
	list l = rs->failed_checkers;
	checker_id_t *id;

	/*
	 * We assume there is not too much checker per
	 * real server, so we consider this lookup as
	 * o(1).
	 */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		id = ELEMENT_DATA(e);
		if (*id == cid)
			return 0;
	}

	return 1;
}

static int
remove_failed_checker_list(checker_id_t cid, real_server_t *rs)
{
	element e;
	list l = rs->failed_checkers;
	checker_id_t *id;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		id = ELEMENT_DATA(e);
		if (*id == cid) {
			free_list_element(l, e);
			/* If we don't break, the next iteration will trigger
			 * a SIGSEGV.
			 */
			break;
		}
	}
	return 0;
}

static int
add_failed_checker_list(checker_id_t cid, real_server_t *rs)
{
	list l = rs->failed_checkers;
	checker_id_t *id;

	id = (checker_id_t *) MALLOC(sizeof(checker_id_t));
	*id = cid;
	list_add(l, id);

	return 0;
}

/* Update checker's state */
void
update_svr_checker_state(int alive, checker_id_t cid, virtual_server_t *vs, real_server_t *rs)
{
	/* Handle alive state. Depopulate failed_checkers and call
	 * perform_svr_state() independently, letting the latter sort
	 * things out itself.
	 */
	if (alive) {
		/* Remove the succeeded check from failed_checkers list. */
		remove_failed_checker_list(cid, rs);
		if (LIST_SIZE(rs->failed_checkers) == 0) {
			if (!perform_svr_state(alive, vs, rs))
				add_failed_checker_list(cid, rs);
		}
	}
	/* Handle not alive state */
	else {
		add_failed_checker_list(cid, rs);
		if (LIST_SIZE(rs->failed_checkers) == 1) {
			if (!perform_svr_state(alive, vs, rs))
				remove_failed_checker_list(cid, rs);
		}
	}
}

/* Check if a vsg entry is in new data */
static int
vsge_exist(virtual_server_group_entry_t *vsg_entry, list l)
{
	element e;
	virtual_server_group_entry_t *vsge;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsge = ELEMENT_DATA(e);
		if (VSGE_ISEQ(vsg_entry, vsge)) {
			/*
			 * If vsge exist this entry
			 * is alive since only rs entries
			 * are changing from alive state.
			 */
			SET_ALIVE(vsge);
			return 1;
		}
	}

	return 0;
}

/* Clear the diff vsge of old group */
static int
clear_diff_vsge(list old, list new, virtual_server_t * old_vs)
{
	virtual_server_group_entry_t *vsge;
	element e;

	for (e = LIST_HEAD(old); e; ELEMENT_NEXT(e)) {
		vsge = ELEMENT_DATA(e);
		if (!vsge_exist(vsge, new)) {
			log_message(LOG_INFO, "VS [[%s]:%d:%d:%d] in group %s no longer exist" 
					    , inet_sockaddrtos(&vsge->addr)
					    , ntohs(inet_sockaddrport(&vsge->addr))
					    , vsge->range
					    , vsge->vfwmark
					    , old_vs->vsgname);

			if (!ipvs_group_remove_entry(old_vs, vsge))
				return 0;
		}
	}

	return 1;
}

/* Clear the diff vsg of the old vs */
static int
clear_diff_vsg(virtual_server_t * old_vs)
{
	virtual_server_group_t *old;
	virtual_server_group_t *new;

	/* Fetch group */
	old = ipvs_get_group_by_name(old_vs->vsgname, old_check_data->vs_group);
	new = ipvs_get_group_by_name(old_vs->vsgname, check_data->vs_group);

	/* Diff the group entries */
	if (!clear_diff_vsge(old->addr_ip, new->addr_ip, old_vs))
		return 0;
	if (!clear_diff_vsge(old->range, new->range, old_vs))
		return 0;
	if (!clear_diff_vsge(old->vfwmark, new->vfwmark, old_vs))
		return 0;

	return 1;
}

/* Check if a vs exist in new data and returns pointer to it */
static virtual_server_t*
vs_exist(virtual_server_t * old_vs, bool* empty_vsg)
{
	element e;
	list l = check_data->vs;
	virtual_server_t *vs;
	virtual_server_group_t *vsg, *old_vsg;

	if (LIST_ISEMPTY(l))
		return NULL;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vs = ELEMENT_DATA(e);
		if (VS_ISEQ(old_vs, vs)) {
			/* Check if group exist */
			if (vs->vsgname) {
				vsg = ipvs_get_group_by_name(old_vs->vsgname,
							    check_data->vs_group);
				old_vsg = ipvs_get_group_by_name(old_vs->vsgname,
								old_check_data->vs_group);
				if (!vsg)
					return NULL;
				if (!old_vsg){
					*empty_vsg = true;
					return NULL;
				}
					
				else
					if (!clear_diff_vsg(old_vs))
						return NULL;
			}

			/*
			 * Exist so set alive.
			 */
			SET_ALIVE(vs);
			return vs;
		}
	}

	return NULL;
}

/* Check if rs is in new vs data */
static int
rs_exist(real_server_t * old_rs, list l)
{
	element e;
	real_server_t *rs;

	if (LIST_ISEMPTY(l))
		return 0;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		if (RS_ISEQ(rs, old_rs)) {
			/*
			 * We reflect the previous alive
			 * flag value to not try to set
			 * already set IPVS rule.
			 */
			rs->alive = old_rs->alive;
			rs->set = old_rs->set;
			rs->weight = old_rs->weight;
			return 1;
		}
	}

	return 0;
}

/* get rs list for a specific vs */
static list
get_rs_list(virtual_server_t * vs)
{
	element e;
	list l = check_data->vs;
	virtual_server_t *vsvr;

	if (LIST_ISEMPTY(l))
		return NULL;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vsvr = ELEMENT_DATA(e);
		if (VS_ISEQ(vs, vsvr))
			return vsvr->rs;
	}

	/* most of the time never reached */
	return NULL;
}

/* Clear the diff rs of the old vs */
static int
clear_diff_rs(list old_vs_group, virtual_server_t * old_vs)
{
	element e;
	list l = old_vs->rs;
	list new = get_rs_list(old_vs);
	real_server_t *rs;

	/* If old vs didn't own rs then nothing return */
	if (LIST_ISEMPTY(l))
		return 1;

	/* remove RS from old vs which are not found in new vs */
	list rs_to_remove = alloc_list (NULL, NULL);
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		rs = ELEMENT_DATA(e);
		if (!rs_exist(rs, new)) {
			/* Reset inhibit flag to delete inhibit entries */
			log_message(LOG_INFO, "service %s no longer exist"
					    , FMT_RS(rs));
			rs->inhibit = 0;
			SET_ALIVE(rs);
			list_add (rs_to_remove, rs);
		}
	}
	int ret = clear_service_rs (old_vs_group, old_vs, rs_to_remove);
	free_list (rs_to_remove);

	return ret;
}

/* Check if a local address entry is in list */
static int
laddr_entry_exist(local_addr_entry *laddr_entry, list l)
{
	element e;
	local_addr_entry *entry;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		entry = ELEMENT_DATA(e);
		if (sockstorage_equal(&entry->addr, &laddr_entry->addr) && 
				(entry->range == laddr_entry->range) &&
                         !strcmp(entry->ifname, laddr_entry->ifname))
			return 1;
	}
	return 0;
}

/* Clear the diff local address entry of eth old vs */
static int
clear_diff_laddr_entry(list old, list new, virtual_server_t * old_vs)
{
	element e;
	local_addr_entry *laddr_entry;

	for (e = LIST_HEAD(old); e; ELEMENT_NEXT(e)) {
		laddr_entry = ELEMENT_DATA(e);
		if (!laddr_entry_exist(laddr_entry, new)) {
			log_message(LOG_INFO, "VS [%s-%d] in local address group %s no longer exist\n" 
					    , inet_sockaddrtos(&laddr_entry->addr)
					    , laddr_entry->range
					    , old_vs->local_addr_gname);

			if (!ipvs_laddr_remove_entry(old_vs, laddr_entry))
				return 0;
		}
	}

	return 1;
}

/* Clear the diff local address of the old vs */
static int
clear_diff_laddr(virtual_server_t * old_vs)
{
	local_addr_group *old;
	local_addr_group *new;

	/*
 	 *  If old vs was not in fulllnat mod or didn't own local address group, 
 	 * then do nothing and return 
 	 */
	if ((old_vs->loadbalancing_kind != IP_VS_CONN_F_FULLNAT) || 
						!old_vs->local_addr_gname)
		return 1;

	/* Fetch local address group */
	old = ipvs_get_laddr_group_by_name(old_vs->local_addr_gname, 
							old_check_data->laddr_group);
	new = ipvs_get_laddr_group_by_name(old_vs->local_addr_gname, 
							check_data->laddr_group);

	if (!clear_diff_laddr_entry(old->addr_ip, new->addr_ip, old_vs))
		return 0;
	if (!clear_diff_laddr_entry(old->range, new->range, old_vs))
		return 0;

	return 1;
}

/* Check if a blacklist address entry is in list */
static int
blklst_entry_exist(blklst_addr_entry *blklst_entry, list l)
{
        element e;
        blklst_addr_entry *entry;

        for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
                entry = ELEMENT_DATA(e);
                if (sockstorage_equal(&entry->addr, &blklst_entry->addr) &&
                                        entry->range == blklst_entry->range)
                        return 1;
        }
        return 0;
}

/* Clear the diff blklst address entry of the old vs */
static int
clear_diff_blklst_entry(list old, list new, virtual_server_t * old_vs)
{
        element e;
        blklst_addr_entry *blklst_entry;

        for (e = LIST_HEAD(old); e; ELEMENT_NEXT(e)) {
                blklst_entry = ELEMENT_DATA(e);
                if (!blklst_entry_exist(blklst_entry, new)) {
                        log_message(LOG_INFO, "VS [%s-%d] in blacklist address group %s no longer exist\n"
                                            , inet_sockaddrtos(&blklst_entry->addr)
                                            , blklst_entry->range
                                            , old_vs->blklst_addr_gname);

                        if (!ipvs_blklst_remove_entry(old_vs, blklst_entry))
                                return 0;
                }
        }

        return 1;
}

/* Clear the diff blacklist address of the old vs */
static int
clear_diff_blklst(virtual_server_t * old_vs)
{
        blklst_addr_group *old;
        blklst_addr_group *new;

        /*
         *  If old vs  didn't own blacklist address group, 
         * then do nothing and return 
         */
        if (!old_vs->blklst_addr_gname)
                return 1;

        /* Fetch blacklist address group */
        old = ipvs_get_blklst_group_by_name(old_vs->blklst_addr_gname,
                                                        old_check_data->blklst_group);
        new = ipvs_get_blklst_group_by_name(old_vs->blklst_addr_gname,
                                                        check_data->blklst_group);

        if (!clear_diff_blklst_entry(old->addr_ip, new->addr_ip, old_vs))
                return 0;
        if (!clear_diff_blklst_entry(old->range, new->range, old_vs))
                return 0;

        return 1;
}

/* When reloading configuration, remove negative diff entries */
int
clear_diff_services(void)
{
	element e;
	list l = old_check_data->vs;
	virtual_server_t *vs;
	bool empty_vsg = false;

	/* If old config didn't own vs then nothing return */
	if (LIST_ISEMPTY(l))
		return 1;

	/* Remove diff entries from previous IPVS rules */
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		vs = ELEMENT_DATA(e);

		/*
		 * Try to find this vs into the new conf data
		 * reloaded.
		 */
		if (!vs_exist(vs, &empty_vsg)) {
			if (vs->vsgname) {
				if (empty_vsg)
					continue;
				log_message(LOG_INFO, "Removing Virtual Server Group [%s]"
						    , vs->vsgname);
			}
			else
				log_message(LOG_INFO, "Removing Virtual Server %s"
						    , FMT_VS(vs));

			/* Clear VS entry */
			if (!clear_service_vs(old_check_data->vs_group, vs))
				return 0;
		} else {
			/* If vs exist, perform rs pool diff */
			/* omega = 0 must not prevent the notifiers from being called,
			   because the VS still exists in new configuration */
			vs->omega = 1;
			if (!clear_diff_rs(old_check_data->vs_group, vs))
				return 0;
			if (vs->s_svr)
				if (ISALIVE(vs->s_svr))
					if (!ipvs_cmd(LVS_CMD_DEL_DEST
						      , check_data->vs_group
						      , vs
						      , vs->s_svr))
						return 0;
			/* perform local address diff */
			if (!clear_diff_laddr(vs))
				return 0;
                        /* perform blacklist address diff */
                        if (!clear_diff_blklst(vs))
                                return 0;
		}
	}

	return 1;
}

/* When reloading configuration, copy still alive RS/VS alive/set attributes into corresponding new config items */
int
copy_srv_states (void)
{
	element e;
	list l = old_check_data->vs;
	virtual_server_t *old_vs, *new_vs;
	bool empty_vsg = false;

	/* If old config didn't own vs then nothing return */
	if (LIST_ISEMPTY(l))
		return 1;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		old_vs = ELEMENT_DATA(e);
		new_vs = vs_exist (old_vs, &empty_vsg);
		if (new_vs) {
			/* copy quorum_state field of VS */
			new_vs->quorum_state = old_vs->quorum_state;
			new_vs->reloaded = 1;

			list old_rsl = old_vs->rs;
			list new_rsl = new_vs->rs;
			if (LIST_ISEMPTY(old_rsl) || LIST_ISEMPTY (new_rsl))
				continue;
			element oe, ne;
			real_server_t *old_rs, *new_rs;
			/* iterate over equal rs */
			for (oe = LIST_HEAD(old_rsl); oe; ELEMENT_NEXT (oe)) {
				old_rs = ELEMENT_DATA(oe);
				for (ne = LIST_HEAD(new_rsl); ne; ELEMENT_NEXT(ne)) {
					new_rs = ELEMENT_DATA(ne);
					if (RS_ISEQ (old_rs, new_rs)) {
						/* copy alive, set fields of RS */
						new_rs->alive = old_rs->alive;
						new_rs->set = old_rs->set;
						new_rs->reloaded = 1;
						if (new_rs->alive) {
							/* clear failed_checkers list */
							free_list_elements(new_rs->failed_checkers);
						}
						break;
					}
				}
			}
		}
	}
	return 0;
}

static tunnel_group *
get_tunnel_group_by_name(char *gname, list l)
{
	element e;
	tunnel_group* group;

	if (LIST_ISEMPTY(l))
		return NULL;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		group = ELEMENT_DATA(e);
		if (!strcmp(group->gname, gname))
			return group;
	}

	return NULL;
}

static int
tunnel_entry_exist(tunnel_entry* old_entry, tunnel_group* new_group)
{
	element e;
	tunnel_entry* new_entry;
	list l = new_group->tunnel_entry;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		new_entry = ELEMENT_DATA(e);
		if (!strcmp(old_entry->ifname, new_entry->ifname) &&
			!strcmp(old_entry->link, new_entry->link) &&
			!strcmp(old_entry->kind, new_entry->kind) &&
			sockstorage_equal(&old_entry->local, &new_entry->local) &&
			sockstorage_equal(&old_entry->remote, &new_entry->remote)) {
			return 1;
		}
	}

	return 0;
}

static int
clear_tunnel_entry(tunnel_entry *entry)
{
	return ipvs_tunnel_cmd(LVS_CMD_DEL_TUNNEL, entry);
}

static int
clear_tunnel_group(tunnel_group* group)
{
	element e;
	tunnel_entry *entry;
	list l = group->tunnel_entry;

	if (LIST_ISEMPTY(l))
		return IPVS_SUCCESS;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		entry = ELEMENT_DATA(e);
		if (!clear_tunnel_entry(entry)) {
			log_message(LOG_ERR, "%s clear tunnel %s error.", __FUNCTION__, entry->ifname);
			return IPVS_ERROR;
		}
	}

	return IPVS_SUCCESS;
}

static int
clear_diff_tunnel_group(tunnel_group* old_group, tunnel_group* new_group)
{
	element e;
	tunnel_entry *entry;
	list l = old_group->tunnel_entry;

	if (LIST_ISEMPTY(old_group->tunnel_entry))
		return IPVS_SUCCESS;

	if (LIST_ISEMPTY(new_group->tunnel_entry))
		return clear_tunnel_group(old_group);

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		entry = ELEMENT_DATA(e);
		if (!tunnel_entry_exist(entry, new_group))
			clear_tunnel_entry(entry);
	}

	return IPVS_SUCCESS;
}

int clear_diff_tunnel(void)
{
	element e;
	tunnel_group *group;
	tunnel_group* new_group;
	list l = old_check_data->tunnel_group;

	/* If old config didn't own tunnel then nothing return */
	if (LIST_ISEMPTY(l))
		return IPVS_SUCCESS;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		group = ELEMENT_DATA(e);
		new_group = get_tunnel_group_by_name(group->gname, check_data->tunnel_group);
		if (new_group) {
			clear_diff_tunnel_group(group, new_group);
		} else {
			clear_tunnel_group(group);
		}
	}

	return IPVS_SUCCESS;
}

