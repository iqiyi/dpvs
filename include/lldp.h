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

#ifndef __DPVS_LLDP_H__
#define __DPVS_LLDP_H__

#define DPVS_LLDP_TYPE_MAX  128

/* IEEE 802.3AB Clause 9: TLV Types */
enum {
    LLDP_TYPE_END           = 0,
    LLDP_TYPE_CHASSIS_ID    = 1,
    LLDP_TYPE_PORT_ID       = 2,
    LLDP_TYPE_TTL           = 3,
    LLDP_TYPE_PORT_DESC     = 4,
    LLDP_TYPE_SYS_NAME      = 5,
    LLDP_TYPE_SYS_DESC      = 6,
    LLDP_TYPE_SYS_CAP       = 7,
    LLDP_TYPE_MNG_ADDR      = 8,
    LLDP_TYPE_ORG           = 127,
};
#define LLDP_TYPE_VALID(t)  (((t) >= 0) && ((t) < DPVS_LLDP_TYPE_MAX))

/* IEEE 802.3AB Clause 9.5.2: Chassis subtypes */
enum {
    LLDP_CHASSIS_ID_RESERVED            = 0,
    LLDP_CHASSIS_ID_CHASSIS_COMPONENT   = 1,
    LLDP_CHASSIS_ID_INTERFACE_ALIAS     = 2,
    LLDP_CHASSIS_ID_PORT_COMPONENT      = 3,
    LLDP_CHASSIS_ID_MAC_ADDRESS         = 4,
    LLDP_CHASSIS_ID_NETWORK_ADDRESS     = 5,
    LLDP_CHASSIS_ID_INTERFACE_NAME      = 6,
    LLDP_CHASSIS_ID_LOCALLY_ASSIGNED    = 7,
};
#define LLDP_CHASSIS_ID_VALID(t)    (((t) > 0) && ((t) <= 7))

/* IEEE 802.3AB Clause 9.5.3: Port subtype */
enum {
    LLDP_PORT_ID_RESERVED           = 0,
    LLDP_PORT_ID_INTERFACE_ALIAS    = 1,
    LLDP_PORT_ID_PORT_COMPONENT     = 2,
    LLDP_PORT_ID_MAC_ADDRESS        = 3,
    LLDP_PORT_ID_NETWORK_ADDRESS    = 4,
    LLDP_PORT_ID_INTERFACE_NAME     = 5,
    LLDP_PORT_ID_AGENT_CIRCUIT_ID   = 6,
    LLDP_PORT_ID_LOCALLY_ASSIGNED   = 7,
};
#define LLDP_PORT_ID_VALID(t)   (((t) > 0) && ((t) <= 7))

/*
 * IETF RFC 3232:
 * http://www.iana.org/assignments/ianaaddressfamilynumbers-mib
 */
enum {
    LLDP_ADDR_OTHER             = 0,
    LLDP_ADDR_IPV4              = 1,
    LLDP_ADDR_IPV6              = 2,
    LLDP_ADDR_NSAP              = 3,
    LLDP_ADDR_HDLC              = 4,
    LLDP_ADDR_BBN1822           = 5,
    LLDP_ADDR_ALL802            = 6,
    LLDP_ADDR_E163              = 7,
    LLDP_ADDR_E164              = 8,
    LLDP_ADDR_F69               = 9,
    LLDP_ADDR_X121              = 10,
    LLDP_ADDR_IPX               = 11,
    LLDP_ADDR_APPLETALK         = 12,
    LLDP_ADDR_DECNETIV          = 13,
    LLDP_ADDR_BANYANVINES       = 14,
    LLDP_ADDR_E164WITHNSAP      = 15,
    LLDP_ADDR_DNS               = 16,
    LLDP_ADDR_DISTINGUISHEDNAME = 17,
    LLDP_ADDR_ASNUMBER          = 18,
    LLDP_ADDR_XTPOVERIPV4       = 19,
    LLDP_ADDR_XTPOVERIPV6       = 20,
    LLDP_ADDR_XTPNATIVEMODEXTP  = 21,
    LLDP_ADDR_FIBRECHANNELWWPN  = 22,
    LLDP_ADDR_FIBRECHANNELWWNN  = 23,
    LLDP_ADDR_GWID              = 24,
    LLDP_ADDR_AFI               = 25,
    LLDP_ADDR_RESERVED          = 65535,
};

/* IEEE 802.1AB: Annex E, Table E.1: Organizationally Specific TLVs */
enum {
    LLDP_ORG_SPEC_PVID              = 1,
    LLDP_ORG_SPEC_PPVID             = 2,
    LLDP_ORG_SPEC_VLAN_NAME         = 3,
    LLDP_ORG_SPEC_PROTO_ID          = 4,
    LLDP_ORG_SPEC_VID_USAGE         = 5,
    LLDP_ORG_SPEC_MGMT_VID          = 6,
    LLDP_ORG_SPEC_LINK_AGGR         = 7,
};
#define LLDP_ORG_SPEC_VALID(t)  (((t) > 0) && ((t) <= 7))

void dpvs_lldp_enable(void);
void dpvs_lldp_disable(void);
bool dpvs_lldp_is_enabled(void);

int dpvs_lldp_init(void);
int dpvs_lldp_term(void);

#endif
