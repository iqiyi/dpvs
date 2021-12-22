#!/bin/sh

### IP/Route ###
dpip addr add 2001::12/64 dev dpdk0 # host IP
dpip addr add 2001::1/128 dev dpdk0 # FullNAT vip
dpip addr add 2001::2/128 dev dpdk0 # DR vip
dpip addr add 2001::3/128 dev dpdk0 # Tunnel vip
dpip addr add 2002::1/64 dev dpdk0  # NAT vip

dpip addr add 192.168.88.12/24 dev dpdk0 # host IP
dpip addr add 192.168.88.1/32 dev dpdk0  # FullNAT vip
dpip addr add 192.168.88.2/32 dev dpdk0  # DR vip
dpip addr add 192.168.88.3/32 dev dpdk0  # Tunel vip
dpip addr add 172.27.88.1/24 dev dpdk0   # NAT vip

dpip addr add 2001::4/128 dev dpdk0 # NAT64 vip

### FullNAT ###
ipvsadm -A -t [2001::1]:8080 -j enable
ipvsadm -at [2001::1]:8080 -r [2001::51]:80 -b
ipvsadm -at [2001::1]:8080 -r [2001::52]:80 -b
ipvsadm -at [2001::1]:8080 -r [2001::53]:80 -b
ipvsadm -at [2001::1]:8080 -r [2001::54]:80 -b
ipvsadm -Pt [2001::1]:8080 -z 2001::1:11 -F dpdk0 
ipvsadm -Pt [2001::1]:8080 -z 2001::1:12 -F dpdk0 
ipvsadm -Pt [2001::1]:8080 -z 2001::1:13 -F dpdk0 

ipvsadm -A -u [2001::1]:80
ipvsadm -au [2001::1]:80 -r [2001::51]:6000 -b
ipvsadm -au [2001::1]:80 -r [2001::54]:6000 -b
ipvsadm -Pu [2001::1]:80 -z 2001::1:12 -F dpdk0

ipvsadm -A -t 192.168.88.1:8080 -j enable
ipvsadm -at 192.168.88.1:8080 -r 192.168.88.151:80 -b
ipvsadm -at 192.168.88.1:8080 -r 192.168.88.152:80 -b
ipvsadm -at 192.168.88.1:8080 -r 192.168.88.153:80 -b
ipvsadm -at 192.168.88.1:8080 -r 192.168.88.154:80 -b
ipvsadm -Pt 192.168.88.1:8080 -z 192.168.88.241 -F dpdk0
ipvsadm -Pt 192.168.88.1:8080 -z 192.168.88.242 -F dpdk0
ipvsadm -Pt 192.168.88.1:8080 -z 192.168.88.243 -F dpdk0

ipvsadm -A -u 192.168.88.1:80 -j enable
ipvsadm -au 192.168.88.1:80 -r 192.168.88.151:6000 -b
ipvsadm -au 192.168.88.1:80 -r 192.168.88.154:6000 -b
ipvsadm -Pu 192.168.88.1:80 -z 192.168.88.241 -F dpdk0

### NAT64 ###
ipvsadm -A -t [2001::4]:8080 -j enable
ipvsadm -at [2001::4]:8080 -r 192.168.88.151:80 -b
ipvsadm -at [2001::4]:8080 -r 192.168.88.152:80 -b
ipvsadm -at [2001::4]:8080 -r 192.168.88.153:80 -b
ipvsadm -at [2001::4]:8080 -r 192.168.88.154:80 -b
ipvsadm -Pt [2001::4]:8080 -z 192.168.88.241 -F dpdk0 
ipvsadm -Pt [2001::4]:8080 -z 192.168.88.242 -F dpdk0 
ipvsadm -Pt [2001::4]:8080 -z 192.168.88.243 -F dpdk0 

ipvsadm -A -u [2001::4]:80
ipvsadm -au [2001::4]:80 -r 192.168.88.151:6000 -b
ipvsadm -Pu [2001::4]:80 -z 192.168.88.241 -F dpdk0

### DR ###
ipvsadm -A -t [2001::2]:80 -s wlc
ipvsadm -at [2001::2]:80 -r [2001::51]:80 -g -w 100
ipvsadm -at [2001::2]:80 -r [2001::52]:80 -g -w 200

ipvsadm -A -u [2001::2]:6000 -s wlc
ipvsadm -au [2001::2]:6000 -r [2001::51]:6000 -g -w 50
ipvsadm -au [2001::2]:6000 -r [2001::52]:6000 -g -w 50

ipvsadm -A -t 192.168.88.2:80 -s rr
ipvsadm -at 192.168.88.2:80 -r 192.168.88.151:80 -g -w 10
ipvsadm -at 192.168.88.2:80 -r 192.168.88.152:80 -g -w 10

ipvsadm -A -u 192.168.88.2:6000 -s wrr
ipvsadm -au 192.168.88.2:6000 -r 192.168.88.151:6000 -g -w 10
ipvsadm -au 192.168.88.2:6000 -r 192.168.88.152:6000 -g -w 20

### Tunnel ###
ipvsadm -A -t [2001::3]:80
ipvsadm -at [2001::3]:80 -r [2001::51]:80 -i
ipvsadm -at [2001::3]:80 -r [2001::52]:80 -i

ipvsadm -A -u [2001::3]:6000
ipvsadm -au [2001::3]:6000 -r [2001::51]:6000 -i
ipvsadm -au [2001::3]:6000 -r [2001::52]:6000 -i

ipvsadm -A -t 192.168.88.3:80
ipvsadm -at 192.168.88.3:80 -r 192.168.88.151:80 -i
ipvsadm -at 192.168.88.3:80 -r 192.168.88.152:80 -i

ipvsadm -A -u 192.168.88.3:6000
ipvsadm -au 192.168.88.3:6000 -r 192.168.88.151:6000 -i
ipvsadm -au 192.168.88.3:6000 -r 192.168.88.152:6000 -i

### NAT ###
ipvsadm -A -t [2002::1]:8080
ipvsadm -at [2002::1]:8080 -r [2001::51]:80 -m
ipvsadm -at [2002::1]:8080 -r [2001::52]:80 -m

ipvsadm -A -u [2002::1]:80
ipvsadm -au [2002::1]:80 -r [2001::51]:6000 -m
ipvsadm -au [2002::1]:80 -r [2001::52]:6000 -m

ipvsadm -A -t 172.27.88.1:8080
ipvsadm -at 172.27.88.1:8080 -r 192.168.88.151:80 -m
ipvsadm -at 172.27.88.1:8080 -r 192.168.88.152:80 -m

ipvsadm -A -u 172.27.88.1:80
ipvsadm -au 172.27.88.1:80 -r 192.168.88.151:6000 -m
ipvsadm -au 172.27.88.1:80 -r 192.168.88.152:6000 -m

