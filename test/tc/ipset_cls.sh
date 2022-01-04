#!/bin/env bash

######
# Notes: 
# 1. restart dpvs first and then run the script
# 2. two linux servers are needed at least, one for dpvs, and one for both rs and client.
# 3. this is an interactive script, you should check the result of each set type
#    according to the commented command at each pause.
######

iface=dpdk0
dpip=../../bin/dpip
ipvsadm=../../bin/ipvsadm

trap cleanup SIGINT SIGTERM EXIT

function init()
{
    $dpip addr add 192.168.88.12/24 dev $iface
    $dpip addr add 192.168.88.112/24 dev $iface
    $dpip addr add 2001::112/64 dev $iface
    $dpip addr add 2001::1:112/64 dev $iface
    $dpip link set $iface tc-ingress on
    $dpip link set $iface tc-egress on

    $dpip addr add 192.168.88.1/32 dev $iface
    $ipvsadm -At 192.168.88.1:80 -s wrr
    $ipvsadm -at 192.168.88.1:80 -r 192.168.88.15:80 -w 100 -b
    $ipvsadm -at 192.168.88.1:80 -r 192.168.88.115:80 -w 100 -b
    $ipvsadm -Pt 192.168.88.1:80 -z 192.168.88.241 -F $iface
    $ipvsadm -At 192.168.88.1:8080 -s wrr
    $ipvsadm -at 192.168.88.1:8080 -r 192.168.88.15:80 -w 100 -b
    $ipvsadm -at 192.168.88.1:8080 -r 192.168.88.115:80 -w 100 -b
    $ipvsadm -Pt 192.168.88.1:8080 -z 192.168.88.242 -F $iface

    $dpip addr add 2001::1 dev $iface
    $ipvsadm -At [2001::1]:80 -s wlc
    $ipvsadm -at [2001::1]:80 -r 192.168.88.15:80 -b
    $ipvsadm -at [2001::1]:80 -r 192.168.88.115:80 -b
    $ipvsadm -Pt [2001::1]:80 -z 192.168.88.243 -F $iface
    $ipvsadm -At [2001::1]:8080 -s wlc
    $ipvsadm -at [2001::1]:8080 -r 192.168.88.15:80 -b
    $ipvsadm -at [2001::1]:8080 -r 192.168.88.115:80 -b
    $ipvsadm -Pt [2001::1]:8080 -z 192.168.88.244 -F $iface
}

function cleanup()
{
    $dpip link set $iface tc-ingress off
    $dpip link set $iface tc-egress off
    $dpip addr del 192.168.88.12/24 dev $iface
    $dpip addr del 192.168.88.112/24 dev $iface
    $dpip addr del 2001::112/64 dev $iface
    $dpip addr del 2001::1:112/64 dev $iface

    $dpip addr del 192.168.88.1/32 dev $iface
    $ipvsadm -Qt 192.168.88.1:80 -z 192.168.88.241 -F $iface
    $ipvsadm -Dt 192.168.88.1:80
    $ipvsadm -Qt 192.168.88.1:8080 -z 192.168.88.242 -F $iface
    $ipvsadm -Dt 192.168.88.1:8080

    $dpip addr del 2001::1 dev $iface
    $ipvsadm -Qt [2001::1]:80 -z 192.168.88.243 -F $iface
    $ipvsadm -Dt [2001::1]:80
    $ipvsadm -Qt [2001::1]:8080 -z 192.168.88.244 -F $iface
    $ipvsadm -Dt [2001::1]:8080
}

function next()
{
    while true
    do
        read -p "continue next test? (yes|no|exit) -- " ans
        if [ _$ans == _yes ]; then
            break
        elif [ _$ans == _exit ]; then
            exit
        else
            sleep 1
        fi
    done
}

function bitmap_ip()
{
    $dpip ipset create foo bitmap:ip range 192.168.0.0/16
    $dpip qsch add dev $iface ingress pfifo_fast
    $dpip cls add dev $iface qsch ingress handle 1:1 ipset match foo,src target drop
    $dpip cls add dev $iface qsch ingress handle 1:2 ipset match foo,dst target drop
    $dpip ipset add foo 192.168.88.15 # client
    $dpip ipset add foo 192.168.88.12 # dpvs
    # ping -c 3 192.168.88.12 -m 1 -I 192.168.88.15    # fail
    # ping -c 3 192.168.88.112 -m 1 -I 192.168.88.15   # fail
    # ping -c 3 192.168.88.12 -m 1 -I 192.168.88.115   # fail
    # ping -c 3 192.168.88.112 -m 1 -I 192.168.88.115  # ok
}

function bitmap_ip_clean()
{
    $dpip cls del dev $iface qsch ingress handle 1:1
    $dpip cls del dev $iface qsch ingress handle 1:2
    $dpip qsch del dev $iface ingress
    $dpip ipset destroy foo
}

function bitmap_port()
{
     $dpip ipset create foo bitmap:port range 0-65535
     $dpip qsch add dev $iface ingress pfifo limit 1024
     $dpip cls add dev $iface qsch ingress handle 1:1 ipset match foo,dst target drop
     # curl 192.168.88.1:80     # ok
     $dpip ipset add foo tcp:80
     # curl 192.168.88.1:80     # fail
     # curl 192.168.88.1:8080   # ok
     # curl -g [2001::1]:80     # ok
}

function bitmap_port_clean()
{
     $dpip cls del dev $iface qsch ingress handle 1:1
     $dpip qsch del dev $iface ingress
     $dpip ipset destroy foo
}

function bitmap_ip_mac()
{
    $dpip ipset create foo bitmap:ip,mac range 192.168.88.0/24
    $dpip qsch add dev $iface ingress pfifo limit 1024
    $dpip cls add dev $iface qsch ingress handle 1:1 ipset match foo,src target drop
    $dpip ipset add foo 192.168.88.15,a0:36:9f:9d:5d:10
    # ping -c 3 -m 1 192.168.88.112 -I 192.168.88.15    # fail
    # ping -c 3 -m 1 192.168.88.112 -I 192.168.88.115   # ok
}

function bitmap_ip_mac_clean()
{
    $dpip cls del dev $iface qsch ingress handle 1:1
    $dpip qsch del dev $iface ingress
    $dpip ipset destroy foo
}

function hash_ip()
{
    $dpip ipset -6 create bar hash:ip
    $dpip qsch add dev $iface ingress pfifo limit 4096
    $dpip cls add dev $iface qsch ingress handle 1:1 pkttype ipv6 prio 100 ipset match bar,src target drop
    $dpip cls add dev $iface qsch ingress handle 1:2 pkttype ipv6 prio 101 ipset match bar,dst target drop
    $dpip ipset add bar 2001::15     # client
    $dpip ipset add bar 2001::1:112  # dpvs
    # ping6 -c 3 2001::112 -m 1 -I 2001::15      # fail
    # ping6 -c 3 2001::112 -m 1 -I 2001::1:15    # ok
    # ping6 -c 3 2001::1:112 -m 1 -I 2001::1:15  # fail
    # ping6 -c 3 2001::1:112 -m 1 -I 2001::15    # fail
}

function hash_ip_clean()
{
    $dpip cls del dev $iface qsch ingress handle 1:1
    $dpip cls del dev $iface qsch ingress handle 1:2
    $dpip qsch del dev $iface ingress
    $dpip ipset destroy bar
}

function hash_ip_port()
{
    $dpip ipset create foo hash:ip,port
    $dpip ipset -6 create bar hash:ip,port
    $dpip qsch add dev $iface ingress pfifo_fast limit 1024
    $dpip cls add dev $iface qsch ingress handle 1:1 pkttype ipv4 prio 100 ipset match foo,dst target drop
    $dpip cls add dev $iface qsch ingress handle 1:2 pkttype ipv6 ipset prio 101 match bar,dst target drop
    $dpip ipset add foo 192.168.88.1,tcp:80
    $dpip ipset add bar 2001::1,tcp:8080
    # curl -g 192.168.88.1:80       # fail
    # curl -g 192.168.88.1:8080     # ok
    # curl -g [2001::1]:80          # ok
    # curl -g [2001::1]:8080        # fail
}

function hash_ip_port_clean()
{
    $dpip cls del dev $iface qsch ingress handle 1:1
    $dpip cls del dev $iface qsch ingress handle 1:2
    $dpip qsch del dev $iface ingress
    $dpip ipset destroy foo
    $dpip ipset destroy bar
}

function hash_ip_port_ip()
{
    $dpip ipset create foo hash:ip,port,ip
    $dpip ipset -6 create bar hash:ip,port,ip
    $dpip qsch add dev $iface ingress pfifo_fast limit 1024
    $dpip cls add dev $iface qsch ingress handle 1:1 pkttype ipv4 prio 100 ipset match foo,dst target drop
    $dpip cls add dev $iface qsch ingress handle 1:2 pkttype ipv6 ipset prio 101 match bar,dst target drop
    $dpip ipset add foo 192.168.88.15,tcp:80,192.168.88.1
    $dpip ipset add bar 2001::15,tcp:8080,2001::1
    # curl -g 192.168.88.1:80       # from 192.168.88.15,  fail
    # curl -g 192.168.88.1:80       # from 192.168.88.115, ok
    # curl -g 192.168.88.1:8080     # ok
    # curl -g [2001::1]:80          # ok
    # curl -g [2001::1]:8080        # from 2001::15,    fail
    # curl -g [2001::1]:8080        # from 2001::1:15,  ok
}

function hash_ip_port_ip_clean()
{
    $dpip cls del dev $iface qsch ingress handle 1:1
    $dpip cls del dev $iface qsch ingress handle 1:2
    $dpip qsch del dev $iface ingress
    $dpip ipset destroy foo
    $dpip ipset destroy bar
}

function hash_ip_port_net()
{
    $dpip ipset create foo hash:ip,port,net
    $dpip ipset -6 create bar hash:ip,port,net
    $dpip qsch add dev $iface ingress pfifo_fast limit 1024
    $dpip cls add dev $iface qsch ingress handle 1:1 pkttype ipv4 prio 100 ipset match foo,dst target drop
    $dpip cls add dev $iface qsch ingress handle 1:2 pkttype ipv6 ipset prio 101 match bar,dst target drop
    $dpip ipset add foo 192.168.88.1,tcp:80,192.168.88.0/26   # note: net always corespond to mbuf source!
    $dpip ipset add bar 2001::1,tcp:8080,2001::/120
    # curl -g 192.168.88.1:80       # from 192.168.88.15,  fail
    # curl -g 192.168.88.1:80       # from 192.168.88.115, ok
    # curl -g 192.168.88.1:8080     # ok
    # curl -g [2001::1]:80          # ok
    # curl -g [2001::1]:8080        # from 2001::15,    fail
    # curl -g [2001::1]:8080        # from 2001::1:15,  ok
}

function hash_ip_port_net_clean()
{
    $dpip cls del dev $iface qsch ingress handle 1:1
    $dpip cls del dev $iface qsch ingress handle 1:2
    $dpip qsch del dev $iface ingress
    $dpip ipset destroy foo
    $dpip ipset destroy bar
}

function hash_net()
{
    $dpip ipset create foo hash:net
    $dpip qsch add dev $iface ingress pfifo limit 4096
    $dpip cls add dev $iface qsch ingress handle 1:1 pkttype ipv4 prio 100 ipset match foo,src target drop
    $dpip cls add dev $iface qsch ingress handle 1:2 pkttype ipv4 prio 101 ipset match foo,dst target drop
    $dpip ipset add foo 192.168.88.0/26
    # ping -c 3 192.168.88.12 -m 1 -I 192.168.88.15      # fail
    # ping -c 3 192.168.88.12 -m 1 -I 192.168.88.115     # fail
    # ping -c 3 192.168.88.112 -m 1 -I 192.168.88.15     # fail
    # ping -c 3 192.168.88.112 -m 1 -I 192.168.88.115    # ok
}

function hash_net_clean()
{
    $dpip cls del dev $iface qsch ingress handle 1:1
    $dpip cls del dev $iface qsch ingress handle 1:2
    $dpip qsch del dev $iface ingress
    $dpip ipset destroy foo
}

function hash_net_port()
{
    $dpip ipset -6 create bar hash:net,port
    $dpip qsch add dev $iface ingress pfifo limit 4096
    $dpip cls add dev $iface qsch ingress handle 1:1 pkttype ipv6 ipset match bar,dst target drop
    $dpip ipset add bar 2001::/120,tcp:80
    # curl -g [2001::1]:8080    # ok
    # curl -g [2001::1]:80      # fail
}

function hash_net_port_clean()
{
    $dpip cls del dev $iface qsch ingress handle 1:1
    $dpip qsch del dev $iface ingress
    $dpip ipset destroy bar
}

function hash_net_port_iface()
{
    $dpip ipset create foo hash:net,port,iface
    $dpip qsch add dev $iface ingress pfifo_fast limit 1024
    $dpip cls add dev $iface qsch ingress handle 1:1 pkttype ipv4 ipset match foo,dst target drop
    $dpip ipset add foo 192.168.88.1,tcp:80,dpdk0
    # curl 192.168.88.1:80      # fail
    # curl 192.168.88.1:8080    # ok
}

function hash_net_port_iface_clean()
{
    $dpip cls del dev $iface qsch ingress handle 1:1
    $dpip qsch del dev $iface ingress
    $dpip ipset destroy foo
}

function hash_net_port_net()
{
    $dpip ipset create foo hash:net,port,net
    $dpip qsch add dev $iface ingress pfifo_fast limit 1024
    $dpip cls add dev $iface qsch ingress handle 1:1 pkttype ipv4 ipset match foo,dst target drop
    $dpip ipset add foo 192.168.88.0/26,tcp:8080,192.168.88.1/32
    # curl -g 192.168.88.1:80    # ok
    # curl -g 192.168.88.1:8080  # from 192.168.88.15,  fail
    # curl -g 192.168.88.1:8080  # from 192.168.88.115, ok
}

function hash_net_port_net_clean()
{
    $dpip cls del dev $iface qsch ingress handle 1:1
    $dpip qsch del dev $iface ingress
    $dpip ipset destroy foo
}

################################################

init

echo "---------> start tc cls ipset test <---------"
next

echo "bitmap:ip"
bitmap_ip
next
bitmap_ip_clean

echo "bitmap:port"
bitmap_port
next
bitmap_port_clean

echo "bitmap:ip,mac"
bitmap_ip_mac
next
bitmap_ip_mac_clean

echo "hash:ip"
hash_ip
next
hash_ip_clean

echo "hash:ip,port"
hash_ip_port
next
hash_ip_port_clean

echo "hash:ip,port,ip"
hash_ip_port_ip
next
hash_ip_port_ip_clean

echo "hash:ip,port,net"
hash_ip_port_net
next
hash_ip_port_net_clean

echo "hash:net"
hash_net
next
hash_net_clean

echo "hash:net,port"
hash_net_port
next
hash_net_port_clean

echo "hash:net,port,net"
hash_net_port_net
next
hash_net_port_net_clean

echo "hash:net,port,iface"
hash_net_port_iface
next
hash_net_port_iface_clean

echo "---------> end tc cls ipset test <---------"
