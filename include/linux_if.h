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
#ifndef __DPVS_LINUX_IF_H__
#define __DPVS_LINUX_IF_H__

#include <linux/ethtool.h>

int linux_get_link_status(const char *ifname, int *if_flags, char *if_flags_str, size_t len);
int linux_set_if_mac(const char *ifname, const unsigned char mac[ETH_ALEN]);
int linux_hw_mc_add(const char *ifname, const uint8_t hwma[ETH_ALEN]);
int linux_hw_mc_del(const char *ifname, const uint8_t hwma[ETH_ALEN]);
int linux_ifname2index(const char *ifname);
int linux_get_tx_csum_offload(const char *ifname);
int linux_set_tx_csum_offload(const char *ifname, int on);
int linux_get_if_features(const char *ifname, int nblocks, struct ethtool_gfeatures *gfeatures);

#endif /* __DPVS_LINUX_IF_H__ */
