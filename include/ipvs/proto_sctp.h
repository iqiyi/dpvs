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
#ifndef __DP_VS_PROTO_SCTP_H__
#define __DP_VS_PROTO_SCTP_H__

#include <netinet/in.h>
#include "sctp/sctp.h"

enum dpvs_sctp_event_t {
	DPVS_SCTP_DATA = 0, /* DATA, SACK, HEARTBEATs */
	DPVS_SCTP_INIT,
	DPVS_SCTP_INIT_ACK,
	DPVS_SCTP_COOKIE_ECHO,
	DPVS_SCTP_COOKIE_ACK,
	DPVS_SCTP_SHUTDOWN,
	DPVS_SCTP_SHUTDOWN_ACK,
	DPVS_SCTP_SHUTDOWN_COMPLETE,
	DPVS_SCTP_ERROR,
	DPVS_SCTP_ABORT,
	DPVS_SCTP_EVENT_LAST
};

/* ip_vs_conn handling functions
 * (from ip_vs_conn.c)
 */
enum { DPVS_DIR_INPUT = 0,
       DPVS_DIR_OUTPUT,
       DPVS_DIR_INPUT_ONLY,
       DPVS_DIR_LAST,
};

/* SCTP State Values */
enum dpvs_sctp_states {
	DPVS_SCTP_S_NONE,
	DPVS_SCTP_S_INIT1,
	DPVS_SCTP_S_INIT,
	DPVS_SCTP_S_COOKIE_SENT,
	DPVS_SCTP_S_COOKIE_REPLIED,
	DPVS_SCTP_S_COOKIE_WAIT,
	DPVS_SCTP_S_COOKIE,
	DPVS_SCTP_S_COOKIE_ECHOED,
	DPVS_SCTP_S_ESTABLISHED,
	DPVS_SCTP_S_SHUTDOWN_SENT,
	DPVS_SCTP_S_SHUTDOWN_RECEIVED,
	DPVS_SCTP_S_SHUTDOWN_ACK_SENT,
	DPVS_SCTP_S_REJECTED,
	DPVS_SCTP_S_CLOSED,
	DPVS_SCTP_S_LAST
};

#endif
