#!/bin/sh -
# raychen, Jan. 2018

WAN_IP="123.1.2.3"	# WAN IP can access Internet.
WAN_PREF=24             # WAN side network prefix length.
GATEWAY="123.1.2.254"	# WAN side gateway

LAN_IP="192.168.204.50"
LAN_PREF=24

# host want to access Internet via SNAT-GRE.
HOST_IP="192.168.204.55"

WAN_IFACE=dpdk1
LAN_IFACE=dpdk0
GRE_IFACE=gre0

GRE_IP="172.1.0.1"

# add WAN-side IP with sapool
# for SNAT must add sapool for WAN-side IP (the IP translated to)
./dpip addr add $WAN_IP/$WAN_PREF dev $WAN_IFACE sapool
# add LAN-side IP as well as LAN route (generated)
./dpip addr add $LAN_IP/$LAN_PREF dev $LAN_IFACE

# add GRE interface and related IP, route
./dpip tunnel add $GRE_IFACE mode gre local $LAN_IP remote $HOST_IP dev $LAN_IFACE
./dpip addr add $GRE_IP/30 dev $GRE_IFACE
./dpip route add $HOST_IP/32 src $LAN_IP dev $LAN_IFACE

# add default route for WAN interface
./dpip route add default via $GATEWAY dev $WAN_IFACE

# SNAT section
# -H MATCH       SNAT uses -H for "match" service instead of -t or -u
#                MATCH support "proto", "src-range", "oif" and "iif".
# -r <WIP:0>     used to specify the WAN IP after SNAT translation,
#                the "port" part must be 0.
# -J             for "SNAT" forwarding mode.
MATCH0="proto=tcp,src-range=172.1.0.0-172.1.255.255,oif=$WAN_IFACE"
MATCH1="proto=icmp,src-range=172.1.0.0-172.1.255.255,oif=$WAN_IFACE"

./ipvsadm -A -s rr -H $MATCH0
./ipvsadm -a -H $MATCH0 -r $WAN_IP:0 -w 100 -J

./ipvsadm -A -s rr -H $MATCH1
./ipvsadm -a -H $MATCH1 -r $WAN_IP:0 -w 100 -J
