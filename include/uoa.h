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
 * it refers TOA of LVS.
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
	__u64   uoa_saved;	/* UOA saved. */
	__u64   uoa_ack_fail;	/* Fail to send UOA ACK. */
	__u64   uoa_miss;	/* Fail to get UOA info from pkt. */

	__u64   success;	/* getname returns UOA address. */
	__u64   miss;		/* getname fail to get UOA info. */
	__u64   invalid;	/* getname find invalid UOA option. */
	__u64   empty;		/* getname not returns peer addr. */

#ifdef __KERNEL__
	struct u64_stats_sync syncp;
#endif
} __attribute__((__packed__));

/* normal kernel statistics (global) */
struct uoa_kstats {
	__u64   uoa_got;	/* UDP packet got UOA. */
	__u64   uoa_none;	/* UDP packet has no UOA. */
	__u64   uoa_saved;	/* UOA saved to sock */
	__u64   uoa_ack_fail;	/* Fail to shand UOA ACK. */
	__u64   uoa_miss;	/* Fail to get UOA info from pkt. */

	__u64   success;	/* getname returns UOA address. */
	__u64   miss;		/* getname fail to get UOA info in sock. */
	__u64   invalid;	/* getname find invalid UOA option. */
	__u64   empty;		/* getname not returns peer addr. */
} __attribute__((__packed__));

#endif
