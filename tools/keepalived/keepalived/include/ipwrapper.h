/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        ipwrapper.c include file.
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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _IPWRAPPER_H
#define _IPWRAPPER_H

/* system includes */
#include <stdbool.h>

/* local includes */
#include "check_data.h"
#include "check_api.h"

/* UP & DOWN value */
#define UP   true
#define DOWN false

/* LVS command set by kernel */
#define LVS_CMD_ADD		IP_VS_SO_SET_ADD
#define LVS_CMD_DEL		IP_VS_SO_SET_DEL
#define LVS_CMD_ADD_DEST	IP_VS_SO_SET_ADDDEST
#define LVS_CMD_DEL_DEST	IP_VS_SO_SET_DELDEST
#define LVS_CMD_EDIT_DEST	IP_VS_SO_SET_EDITDEST
#define LVS_CMD_ADD_LADDR	IP_VS_SO_SET_ADDLADDR
#define LVS_CMD_DEL_LADDR	IP_VS_SO_SET_DELLADDR
#define LVS_CMD_ADD_BLKLST	IP_VS_SO_SET_ADDBLKLST
#define LVS_CMD_DEL_BLKLST	IP_VS_SO_SET_DELBLKLST
#define LVS_CMD_ADD_WHTLST	IP_VS_SO_SET_ADDWHTLST
#define LVS_CMD_DEL_WHTLST	IP_VS_SO_SET_DELWHTLST
#define LVS_CMD_ADD_TUNNEL	IP_VS_SO_SET_ADDTUNNEL
#define LVS_CMD_DEL_TUNNEL	IP_VS_SO_SET_DELTUNNEL

/* prototypes */
extern void update_svr_wgt(int, virtual_server_t *, real_server_t *, bool);
extern void set_checker_state(checker_t *, bool);
extern void update_svr_checker_state(bool, checker_t *);
extern bool init_services(void);
extern void clear_services(void);
extern void clear_tunnels(void);
extern void set_quorum_states(void);
extern void clear_diff_services(list);
extern void check_new_rs_state(void);
extern void link_vsg_to_vs(void);
extern int svr_checker_up(bool, real_server_t *);
extern int copy_srv_states(void);

extern int init_tunnel(void);
extern int clear_diff_tunnel(void);

#endif
