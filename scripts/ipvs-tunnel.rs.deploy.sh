#! /bin/sh
# March, 2018
# yuwenchao

# This script helps setup/clean IPIP tunnel for QLB tunnel forwarding mode.
# Platform:
#    Linux, Centos6 and Centos7
# Warning:
#    Configure file "ifcfg-tunl0" is modified when run the script.
#    Be careful when your system have using the tunl0 device.

sysctl_file="/etc/sysctl.d/http_tweak.conf"
tunl0_file="/etc/sysconfig/network-scripts/ifcfg-tunl0"

function valid_ip()
{
    local ip=$1
    local i=1
    local ret=$(echo $ip | grep \
    "^[[:digit:]]\{1,3\}.[[:digit:]]\{1,3\}.[[:digit:]]\{1,3\}.[[:digit:]]\{1,3\}$")
    if [ -z $ret ]; then
        return 1
    fi
    while [ $i -le 4 ]
    do
        local seg=$(echo $ip | cut -d '.' -f $i)
        if [ "$seg" == "" ]; then
            return 1
        fi
        if [ "$seg" -lt 0 -o "$seg" -gt 255 ]; then
            return 1
        fi
        i=$(($i+1))
    done
    return 0
}

function check_tunl0_cfg()
{
    [ ! -f $tunl0_file ] && return 0

    addrcnt=$(cat $tunl0_file | grep IPADDR -c)
    maskcnt=$(cat $tunl0_file | grep NETMASK -c)
    if [ $addrcnt != $maskcnt ]; then
        echo -e "bad tunl0 cfgfile $tunl0_file"
        return 1
    fi

    addrcfgs=$(cat $tunl0_file | grep IPADDR)
    for acf in $addrcfgs
    do
        ipaddr=$(echo $acf | cut -d = -f 2)
        valid_ip $ipaddr
        if [ $? -ne 0 ]; then
            echo -e "bad IP address($ipaddr) in tunl0 cfgfile $tunl0_file"
            return 2
        fi
        acf_id=$(echo $acf | cut -d = -f 1 | sed 's/IPADDR//')
        cat $tunl0_file | grep "NETMASK${acf_id}=255.255.255.255" > /dev/null
        if [ $? -ne 0 ]; then
            echo -e "bad netmask in tunl0 cfgfile $tunl0_file"
            return 3
        fi
    done

    return 0
}

function add_tunl0_cfg()
{
    local ip=$1

    valid_ip $ip
    [ $? -ne 0 ] && return 1

    check_tunl0_cfg
    [ $? -ne 0 ] && return 2

    if [ ! -f $tunl0_file ]; then
        echo "DEVICE=tunl0" > $tunl0_file
        echo "ONBOOT=yes" >> $tunl0_file
        echo "IPADDR0=$ip" >> $tunl0_file
        echo "NETMASK0=255.255.255.255" >> $tunl0_file
    else
        cat $tunl0_file | grep $ip > /dev/null
        [ $? -eq 0 ] && return 0

        addrlist=$(cat $tunl0_file | grep IPADDR | awk -F = '{print $2}')
        echo "DEVICE=tunl0" > $tunl0_file
        echo "ONBOOT=yes" >> $tunl0_file
        id=0
        for addr in $addrlist
        do
            echo "IPADDR${id}=$addr" >> $tunl0_file
            echo "NETMASK${id}=255.255.255.255" >> $tunl0_file
            id=$((id+1))
        done
        echo "IPADDR${id}=$ip" >> $tunl0_file
        echo "NETMASK${id}=255.255.255.255" >> $tunl0_file
    fi

    return 0
}

function del_tunl0_cfg()
{
    local ip=$1
    valid_ip $ip
    [ $? -ne 0 ] && return 1

    [ ! -f $tunl0_file ] && return 2

    check_tunl0_cfg
    [ $? -ne 0 ] && return 3

    acf=$(cat $tunl0_file | grep $ip)
    acf_id=$(echo $acf | cut -d = -f 1 | sed 's/IPADDR//')

    sed -i /"IPADDR${acf_id}=$ip"/d $tunl0_file
    sed -i /"NETMASK${acf_id}=255.255.255.255"/d $tunl0_file

    return 0
}

function usage()
{
    echo -e "[Usage] $0 start|stop VIP"
}

function check_input()
{
    [ $# -ne 2 ] && return 1

    [ _$1 != '_start' -a _$1 != '_stop' ] && return 2

    valid_ip $2
    [ $? -ne 0 ] && return 3

    return 0
}

#### main ####
check_input $@
if [ $? -ne 0 ]; then
    usage
    exit 1
fi

case $1 in
start)
    ip addr show | grep $2 > /dev/null
    [ $? -ne 0 ] && ip addr add $2/32 dev tunl0

    ip link set tunl0 up

    sysctl -w net.ipv4.conf.tunl0.arp_ignore=1 > /dev/null
    sysctl -w net.ipv4.conf.tunl0.rp_filter=2 > /dev/null

    [ ! -e $(dirname $sysctl_file) ] && mkdir -p $(dirname $sysctl_file)
    [ ! -f $sysctl_file ] && touch $sysctl_file
    sed -i /'net.ipv4.conf.tunl0.arp_ignore'/d  $sysctl_file
    sed -i /'net.ipv4.conf.tunl0.rp_filter'/d  $sysctl_file
    echo net.ipv4.conf.tunl0.arp_ignore=1 >>  $sysctl_file
    echo net.ipv4.conf.tunl0.rp_filter=2 >> $sysctl_file

    add_tunl0_cfg $2
    if [ $? -ne 0 ]; then
        #echo "Fail to add $ip to $tunl0_file!"
        echo "=== RS deploy for ipvs-tunnel failed ==="
        exit 1
    fi

    echo "=== RS deploy for ipvs-tunnel succeed ==="
    exit 0
;;

stop)
    ip addr show | grep $2 > /dev/null
    [ $? -eq 0 ] && ip addr del $2/32 dev tunl0

    del_tunl0_cfg $2
    if [ $? -ne 0 ]; then
        #echo "Fail to del $ip from $tunl0_file!"
        echo "=== RS cleanup for ipvs-tunnel failed ==="
        exit 1
    fi

    echo "=== RS cleanup for ipvs-tunnel succeed ==="
    exit 0
;;

*)
    usage
    exit 1
esac

