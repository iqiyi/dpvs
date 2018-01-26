#!/bin/sh
#$Date: 2018-01-19
#$ID: icymoon

##### Basic configurations #####
##### NOTE: modify these according to your environment #####
WAN_IP_LIST=('192.168.10.4' '192.168.10.5') 
WAN_TCP_PORT=80
WAN_UDP_PORT=53
WAN_NET='192.168.10.0/24'

LAN_IP_LIST=('172.16.10.2' '172.16.10.10' '172.16.10.11' '172.16.10.12' '172.16.10.13') 
LAN_PREF=24
LAN_NET="172.16.10.0/$LAN_PREF"

TCP_REAL_SERVER_LIST=('172.16.10.3:8080' '172.16.10.3:8081' '172.16.10.3:8082' '172.16.10.4:8080' '172.16.10.4:8081' '172.16.10.4:8082')
UDP_REAL_SERVER_LIST=('172.16.10.3:53' '172.16.10.4:53')

# Enable or Disable SYN PROXY
SYN_PROXY='Disable'

WAN_DEV=dpdk1 # device for WAN IP list to bind on
LAN_DEV=dpdk0 # device for LAN IP to bind on

## OSPF Info
OSPF_IP='' #'172.10.1.2'
OSPF_AREA='' #'172.10.1.2/30'
OSPF_GW='' #'172.10.1.1'


DPVS_TOOL_PATH="."
DPIP_CMD="$DPVS_TOOL_PATH/dpip "
IPVSADM_CMD="$DPVS_TOOL_PATH/ipvsadm "
IP_CMD=`which ip`

##### Basic functions and vars #####
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
    run_cmd "$IP_CMD link set ${WAN_DEV}.kni up"
    run_cmd "$IP_CMD link set ${LAN_DEV}.kni up"
    for d in ${WAN_IP_LIST[@]}; do
        run_cmd "$IP_CMD addr add $d/32 dev ${WAN_DEV}.kni"
    done

    if [ "x$OSPF_AREA" != "x" ]; then
        run_cmd "$IP_CMD addr add $OSPF_AREA dev ${WAN_DEV}.kni" \
            "Add OSPF addr $OSPF_AREA on ${WAN_DEV}.kni"
    fi
}

# Check whethre all the ips are bond to right devices
check_addrs_on_dev() {
    echo "====Check addresses on devices===="
    echo "WAN Device: $WAN_DEV"
    echo "LAN Device: $LAN_DEV"
    for d in ${WAN_IP_LIST[@]}; do
        echo -n "check $d/32 on ${WAN_DEV}.kni ..."
        $IP_CMD addr show dev ${WAN_DEV}.kni | grep inet | grep $d/32 > /dev/null 2>&1
        check_result $?
  	done
    if [ "x$OSPF_AREA" != "x" ]; then
        echo -n "Check OSPF addr $OSPF_AREA on ${WAN_DEV}.kni ..."
        $IP_CMD addr show dev ${WAN_DEV}.kni | grep inet | grep $OSPF_AREA > /dev/null 2>&1
        check_result $?
    fi
}

# Add gw to $WAN_DEV and $LAN
add_gw() {
    echo "====Add route entry on devices===="
    run_cmd "$DPIP_CMD route add $LAN_NET dev $LAN_DEV"

    if [ "x$OSPF_IP" != "x" ]; then
        run_cmd "$DPIP_CMD route add $OSPF_IP dev $WAN_DEV scope kni_host" \
             "Add OSPF route to kni device $WAN_DEV"
    fi
    if [ "x$OSPF_GW" != "x" ]; then
        run_cmd "$IP_CMD route add default via $OSPF_GW dev ${WAN_DEV}.kni" \
             "Add OSPF default gateway"
    fi
}

check_gw() {
    echo "====Check route on devices===="
    echo -n "Check $LAN_NET on $LAN_DEV..."
    $DPIP_CMD route show | grep 0.0.0.0 | awk '{print ","$2","$8","}' | \
        grep ",$LAN_NET,$LAN_DEV," > /dev/null 2>&1
    check_result $?

    if [ "x$OSPF_GW" != "x" ]; then
        echo -n "Check OSPF GataWay $OSPF_GW on ${WAN_DEV}.kni ..."
        # FIXME: Has NO OSPF net env to test
        $IP_CMD route show default | grep ${WAN_DEV}.kni | grep $OSPF_GW > /dev/null 2>&1
        check_result $?
    fi
}

config_dpvs_rules() {
    if [ "x$SYN_PROXY" == "xEnable" ]; then
        SYN_PROXY='-j enable'
    elif [ "x$SYN_PROXY" == "xDisable" ]; then
        SYN_PROXY='-j disable'
    fi
    if [ "x$WAN_TCP_PORT" != "x" ]; then
        for vip in ${WAN_IP_LIST[@]}; do
            run_cmd "$IPVSADM_CMD  -A -t $vip:$WAN_TCP_PORT -s rr $SYN_PROXY"
            for rs in ${TCP_REAL_SERVER_LIST[@]}; do
                run_cmd "$IPVSADM_CMD -a -t $vip:$WAN_TCP_PORT -r $rs -b"
            done
            for lip in ${LAN_IP_LIST[@]}; do
                run_cmd "$IPVSADM_CMD --add-laddr -z $lip -t $vip:$WAN_TCP_PORT -F $LAN_DEV"
            done
        done
    fi
    if [ "x$WAN_UDP_PORT" != "x" ]; then
        for vip in ${WAN_IP_LIST[@]}; do
            run_cmd "$IPVSADM_CMD  -A -u $vip:$WAN_UDP_PORT -s rr"
            for rs in ${UDP_REAL_SERVER_LIST[@]}; do
                run_cmd "$IPVSADM_CMD -a -u $vip:$WAN_UDP_PORT -r $rs -b"
            done
            for lip in ${LAN_IP_LIST[@]}; do
                run_cmd "$IPVSADM_CMD --add-laddr -z $lip -u $vip:$WAN_UDP_PORT -F $LAN_DEV"
            done
        done
    fi
}

#### Main process #####
while getopts "hcs:" arg; do
    case $arg in
    c )
        check_addrs_on_dev
        check_gw
        exit $?
        ;;
    h )
        show_usage
        ;;
    s )
        if [ "x$OPTARG" == "xnet" ]; then
            add_addrs_to_dev
            add_gw
        elif [ "x$OPTARG" == "xdpvs" ]; then
            config_dpvs_rules
        elif [ "x$OPTARG" == "xall" ]; then
            add_addrs_to_dev
            add_gw
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
