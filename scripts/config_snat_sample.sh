#!/bin/sh
#$Date: 2018-01-09
#$ID: icymoon

##### Basic configurations #####
##### NOTE: modify these according to your environment #####
WAN_IP_LIST=('192.168.10.2' '192.168.10.4' '192.168.10.5' '192.168.10.6')
WAN_PREF=24             # WAN side network prefix length.
GATEWAY=192.168.10.3    # WAN side gateway

LAN_IP=172.16.10.2
LAN_PREF=24

SRC_RANGE='172.16.0.0-172.16.255.254'

WAN_DEV=dpdk1 # device for WAN IP list to bind on
LAN_DEV=dpdk0 # device for LAN IP to bind on

PROTOCOLS=('tcp' 'udp' 'icmp')

DPVS_TOOL_PATH="."
DPIP_CMD="$DPVS_TOOL_PATH/dpip "
IPVSADM_CMD="$DPVS_TOOL_PATH/ipvsadm "

##### Basic functions and vars #####
## array of snat fwd rules
declare -a MATCHES

RULE_CNT=$[${#WAN_IP_LIST[@]}*${#PROTOCOLS[@]}-1]

# Check $1, and print 
check_result() {
    ret=$1
    if [ $ret -ne 0 ]; then
        echo "FAILED"
    else
        echo "SUCCEED"
    fi
}

# show usage
show_usage() {
     echo "$0 -h          show usage"
     echo "                 -c          only check network environment config"
     echo "                 -s [net]    only set network environment"
     echo "                 -s [dpvs]   only set dpvs fwd rules"
     echo "                 -s [all]    set network and dpvs rules, means net+dpvs"
     exit 0;
}

# print & run a command, then show result.
run_cmd() {
	if [ "x$2" != "x" ]; then
		echo -n "$2 ... "
	else
		echo -n "$1 ... "
	fi
	$1 > /dev/null 2>&1
	check_result $?
}

# bind WAN IP list to WAN device and LAN IP to LAN device
add_addrs_to_dev() {
    echo "====Add IP Address to devices===="
    for d in ${WAN_IP_LIST[@]}; do
        run_cmd "$DPIP_CMD addr add $d/$WAN_PREF dev $WAN_DEV sapool"
    done
    run_cmd "$DPIP_CMD addr add $LAN_IP/$LAN_PREF dev $LAN_DEV"
}

# Check whethre all the ips are bond to right devices
check_addrs_on_dev() {
    echo "Check addresses on devices..."
    echo "WAN Device: $WAN_DEV"
    echo "LAN Device: $LAN_DEV"
    for d in ${WAN_IP_LIST[@]}; do
        run_cmd "$DPIP_CMD addr show dev $WAN_DEV | grep inet \| grep $d/$WAN_PREF " \
            "Check $d/$WAN_PREF on dev $WAN_DEV"
  	done

    run_cmd "$DPIP_CMD addr show dev $LAN_DEV | grep inet | grep $LAN_IP/$LAN_PREF " \
        "Check $LAN_IP/$LAN_PREF on dev $LAN_DEV"
}

# Add default gw to $WAN_DEV
add_default_gw() {
    echo "====Add default gateway to devices===="
    run_cmd "$DPIP_CMD route add default via $GATEWAY dev $WAN_DEV"
}

check_default_gw() {
    echo "====Check default gateway to devices===="
    echo -n "Check default gateway $GATEWAY on $WAN_DEV..."
    $DPIP_CMD route show | grep 0.0.0.0/0 | awk '{print ","$4","$8","}' | \
        grep ",$GATEWAY,$WAN_DEV,"  > /dev/null 2>&1
    check_result $?
}

gen_matches() {
    i=0
    for p in ${PROTOCOLS[@]}; do
        MATCHES[$i]="proto=$p,src-range=$SRC_RANGE,oif=$WAN_DEV"
        i=$[$i+1]
    done
}

config_dpvs_rules() {
    for m in ${MATCHES[@]}; do
        run_cmd "$IPVSADM_CMD -A -s rr -H $m"
        for ip in ${WAN_IP_LIST[@]}; do
            run_cmd "$IPVSADM_CMD -a -H $m -r $ip:0 -w 100 -J"
        done
    done
}

#### Main process #####
while getopts "hcs:" arg; do
    case $arg in
    c )
        check_addrs_on_dev
        check_default_gw
        exit $?
        ;;
    h )
        show_usage
        ;;
    s )
        if [ "x$OPTARG" == "xnet" ]; then
            add_addrs_to_dev
            add_default_gw
        elif [ "x$OPTARG" == "xdpvs" ]; then
            gen_matches
            config_dpvs_rules
        elif [ "x$OPTARG" == "xall" ]; then
            add_addrs_to_dev
            add_default_gw
            gen_matches
            config_dpvs_rules
        else
            show_usage
        fi
        exit $?
        ;;
    * )
        show_usage
        ;;
    esac
done
