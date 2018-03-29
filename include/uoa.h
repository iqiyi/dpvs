/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2018 iQIYI (www.iqiyi.com).
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
 * UDP Option of Address (UOA) Kernel Module for Real Server.
 * it refers TOA of LVS and ip_vs kernel module.
 *
 * raychen@qiyi.com, Feb 2018, initial.
 */

#ifndef __DPVS_UOA__
#define __DPVS_UOA__

/* avoid IANA ip options */
#define IPOPT_UOA	(31|IPOPT_CONTROL)
#define IPOLEN_UOA	sizeof(struct ipopt_uoa)

/* UOA IP option */
struct ipopt_uoa {
	__u8	op_code;
	__u8	op_len;
	__be16  op_port;
	__be32  op_addr;
} __attribute__((__packed__));

/* per-cpu statistics */
struct uoa_cpu_stats {
	__u64   uoa_got;	/* UDP packet got UOA. */
	__u64   uoa_none;	/* UDP packet has no UOA. */
	__u64   uoa_saved;	/* UOA saved to mapping table */
	__u64   uoa_ack_fail;	/* Fail to send UOA ACK. */
	__u64   uoa_miss;	/* Fail to get UOA info from pkt. */

	__u64   success;	/* uoa address returned. */
	__u64   miss;		/* no such uoa info . */
	__u64   invalid;	/* bad uoa info found. */

#ifdef __KERNEL__
	struct u64_stats_sync syncp;
#endif
} __attribute__((__packed__));

/* normal kernel statistics (global) */
struct uoa_kstats {
	__u64   uoa_got;	/* UDP packet got UOA. */
	__u64   uoa_none;	/* UDP packet has no UOA. */
	__u64   uoa_saved;	/* UOA saved to mapping table */
	__u64   uoa_ack_fail;	/* Fail to shand UOA ACK. */
	__u64   uoa_miss;	/* Fail to get UOA info from pkt. */

	__u64   success;	/* uoa address returned. */
	__u64   miss;		/* no such uoa info . */
	__u64   invalid;	/* bad uoa info found. */
} __attribute__((__packed__));

/* uoa socket options */
enum {
	UOA_BASE_CTL		= 2048,
	/* set */
	UOA_SO_SET_MAX		= UOA_BASE_CTL,
	/* get */
	UOA_SO_GET_LOOKUP	= UOA_BASE_CTL,
	UOA_SO_GET_MAX		= UOA_SO_GET_LOOKUP,
};

struct uoa_param_map {
	/* input */
	__be32	saddr;
	__be32	daddr;
	__be16	sport;
	__be16	dport;
	/* output */
	__be32	real_saddr;
	__be16	real_sport;
} __attribute__((__packed__));

#endif
