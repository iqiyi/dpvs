#!/bin/env bash

verbose=0               # decide if to print command errors, 0 for "no" and 1 for "yes"
result=""               # final result, "Fail" or "OK"
cmdout=""               # command output

while getopts "v:" opt;
do
    case $opt in
    v)
        if [ _$OPTARG = _v ]; then
            verbose=2
        else
            verbose=1
        fi
        #echo "set verbose: $verbose"
        shift
        ;;
    ?)
        echo -e "invalid option: $opt"
        exit 1
        ;;
    esac
done

[ $# -ne 1 ] && echo -e "Usage: $0 [-v|-vv] dpip-executable-file" && exit 1

[ ! -x $1 ] && echo -e "invalid dpip executable file" && exit 1
dpip=$1

alias ipset="run $1 ipset"
shopt -s expand_aliases

# print testing result when exit
trap print_result SIGINT SIGTERM EXIT
function print_result()
{
    local retval=1

    [ _$result = _ ] && result="PASS" && retval=0
    echo -e "\nIPSET TEST RESULT: $result"

    exit $retval
}

function run()
{
    local cmd=$*
    local expect=""
    local retval;
    echo "$cmd" | grep " EXPECT " > /dev/null
    if [ $? -eq 0 ]; then
        expect=${cmd##*EXPECT }
        cmd=${cmd% EXPECT*}
        #echo -e "expect: $expect\ncommand: $cmd"
    fi

    if [ $verbose -eq 1 ]; then
        cmdout=$($cmd)              # output errors only
    else
        cmdout=$($cmd 2>/dev/null)  # output nothing
    fi
    retval=$?

    if [ $verbose -gt 1  -a "_$cmdout" != "_" ]; then
        echo -e "$cmdout"           # output all
    fi

    if [ $retval -ne 0 ];
    then
        echo -e "[ Fail ] $*"
        result="Fail"
        return 1
    fi
    
    if [ "_$expect" != "_" ]; then
        if [ "_$cmdout" != "_$expect" ]; then
            echo -e "[ Fail ] $*"
            result="Fail"
            return 1
        fi
    fi

    echo -e "[  OK  ] $*"
    return 0
}


# global
echo -e "global"
ipset list
ipset show

# bitmap:ip
echo -e "bitmap:ip"
ipset create foo bitmap:ip range 192.168.0.0/16
ipset add foo 192.168.1.0/26
ipset test foo 192.168.1.32 EXPECT true
ipset test foo 192.168.2.1 EXPECT false
ipset add foo 192.168.2.1
ipset test foo 192.168.2.1 EXPECT true
ipset add foo 10.100.100.100
ipset test foo 10.100.100.100 EXPECT false
ipset destroy foo

# bitmap:port
echo -e "bitmap:port"
ipset create foo bitmap:port range 0-65535
ipset add foo tcp:80
ipset add foo tcp:8080
ipset test foo tcp:80 EXPECT true
ipset test foo tcp:8080 EXPECT true
ipset test foo udp:80 EXPECT false
ipset test foo tcp:41235 EXPECT false
ipset add foo udp:80
ipset test foo udp:80 EXPECT true
ipset del foo tcp:8080
ipset test foo tcp:8080 EXPECT false
ipset flush foo
ipset destroy foo

# bitmap:ip,mac
echo -e "bitmap:ip,mac"
ipset create foo bitmap:ip,mac range 192.168.0.0/16
ipset add foo 192.168.1.1,12:34:56:78:9A:BC
ipset add foo 192.168.2.2
ipset test foo 192.168.1.1,12:34:56:78:9A:BC EXPECT true
ipset test foo 192.168.1.1,12:34:56:78:A9:BC EXPECT false
ipset test foo 192.168.1.1,0:0:0:0:0:0 EXPECT true
ipset test foo 192.168.1.1 EXPECT true
ipset test foo 192.168.2.2 EXPECT true
ipset test foo 192.168.2.2,1:2:3:4:5:6 EXPECT true
ipset test foo 192.168.2.1 EXPECT false
ipset destroy foo

# hash:ip
echo -e "hash:ip"
ipset create foo hash:ip comment
ipset add foo 10.100.100.100 comment a-single-address
ipset add foo 192.168.1.0/24
ipset list foo
ipset test foo 10.100.100.100 EXPECT true
ipset test foo 192.168.1.12 EXPECT true
ipset test foo 192.168.2.0 EXPECT false
ipset test foo 0.0.0.0 EXPECT false
ipset destroy foo
ipset -6 create bar hash:ip hashsize 128 maxelem 4096
ipset add bar 2001::1
ipset add bar 2001::2:1
ipset add bar ::
ipset test bar 2001::2:1 EXPECT true
ipset test bar ::1 EXPECT false
ipset test bar :: EXPECT true
ipset destroy bar

# hash:ip,port
echo -e "hash:ip,port"
ipset create foo hash:ip,port
ipset add foo 192.168.1.0/30,tcp:80-82
ipset add foo 192.168.1.0/30,udp:80-82
ipset -v test foo 192.168.1.1,tcp:81 EXPECT "192.168.1.1,tcp:81 is in set foo"
ipset test foo 192.168.1.0,upd:80 EXPECT false
ipset add foo 172.27.1.3-172.27.1.5             # match ip only
ipset test foo 172.27.1.5 EXPECT true
ipset test foo 172.27.1.4,0 EXPECT true
ipset test foo 172.27.1.4,tcp:0 EXPECT false
ipset add foo 172.27.20.20-172.27.20.21,80-82   # zero proto match
ipset test foo 172.27.20.20,81 EXPECT true
ipset test foo 172.27.20.20,tcp:81 EXPECT false
ipset flush foo
ipset destroy foo
ipset -6 create bar hash:ip,port
ipset add bar 2001::1,tcp:8080-8082
ipset add bar 2001::1,udp:80
ipset add bar 2001::2,0                         # match ip only
ipset test bar 2001::1,tcp:8081 EXPECT true
ipset test bar 2001::1,udp:8081 EXPECT false
ipset test bar 2001::1,udp:80 EXPECT true
ipset test bar 2001::2 EXPECT true
ipset destroy bar

# hash:net
echo -e "hash:net"
ipset create foo hash:net
ipset add foo 192.168.0.0/24
ipset add foo 10.1.0.0/16
ipset add foo 192.168.0.100/30 nomatch
ipset test foo 10.1.100.100 EXPECT true
ipset test foo 192.168.0.104 EXPECT true
ipset test foo 192.168.0.102 EXPECT false
ipset add foo 10.1.1.1 nomatch
ipset test foo 10.1.1.1 EXPECT false
ipset del foo 10.1.1.1
ipset test foo 10.1.1.1 EXPECT true
ipset destroy foo
ipset -6 create bar hash:net
ipset add bar 2001::/64
ipset test bar 2001::4:3:2:1 EXPECT true
ipset test bar 2001:1::4:3:2:1 EXPECT false
ipset test bar 2001::1 EXPECT true
ipset add bar 2001::/120 nomatch
ipset test bar 2001::1 EXPECT false
ipset destroy bar

# hash:ip,port,ip
echo -e "hash:ip,port,ip"
ipset create foo hash:ip,port,ip comment
ipset add foo 192.168.1.16/30,tcp:8080-8082,192.168.2.100-192.168.2.105 comment "a-test-range"
ipset test foo 192.168.1.18,tcp:8081,192.168.2.101 EXPECT true
ipset test foo 192.168.1.16,tcp:8080,192.168.2.105 EXPECT true
ipset test foo 192.168.1.20,tcp:8081,192.168.2.101 EXPECT false
ipset test foo 192.168.1.18,tcp:8081,192.168.2.106 EXPECT false
ipset test foo 192.168.1.18,udp:8081,192.168.2.101 EXPECT false
ipset test foo 192.168.1.19,8081,192.168.2.101 EXPECT false
ipset del foo 192.168.1.18/31,tcp:8081,192.168.2.101
ipset test foo 192.168.1.18,tcp:8081,192.168.2.101 EXPECT false
ipset destroy foo
ipset -6 create bar hash:ip,port,ip
ipset add bar 2001::1,udp:80-82,2002::2
ipset add bar 2001::1,tcp:80-82,2002::2
ipset add bar 2001::1,80-82,2002::2
ipset test bar 2001::1,udp:81,2002::2 EXPECT true
ipset test bar 2001::1,tcp:80,2002::2 EXPECT true
ipset test bar 2001::1,82,2002::2 EXPECT true
ipset test bar 2001::2,81,2002::2 EXPECT false
ipset test bar 2001::1,tcp:8080,2002::2 EXPECT false
ipset test bar 2001::1,udp:80,2002::1 EXPECT false
ipset del bar 2001::1,80-82,2002::2
ipset test bar 2001::1,82,2002::2 EXPECT false
ipset destroy bar

# hash:net,port,net,port
echo -e "hash:net,port,net,port"
ipset create foo hash:net,port,net,port
ipset add  foo 192.168.10.0/24,0,192.168.20.0/24,0
ipset test foo 192.168.10.123,0,192.168.20.123,0 EXPECT true
ipset test foo 192.168.10.123,tcp:0,192.168.20.123,tcp:0 EXPECT false
ipset add  foo 192.168.10.123,tcp:0,192.168.20.123,tcp:0
ipset test foo 192.168.10.123,tcp:0,192.168.20.123,tcp:0 EXPECT true
ipset add  foo 192.168.10.64/26,0,192.168.20.64/26,0 nomatch
ipset test foo 192.168.10.123,0,192.168.20.123,0 EXPECT false
ipset add  foo 192.168.10.123,0,192.168.20.123,0
ipset test foo 192.168.10.123,0,192.168.20.123,0 EXPECT true
ipset flush foo
ipset add  foo 10.64.68.0-10.64.68.100,tcp:80-82,10.128.0.0/16,tcp:8080
ipset list -v foo
ipset test foo 10.64.68.66,tcp:81,10.128.11.22,tcp:8080 EXPECT true
ipset add  foo 10.64.68.64/29,tcp:81,10.128.11.0/24,tcp:8080 nomatch
ipset test foo 10.64.68.66,tcp:81,10.128.11.22,tcp:8080 EXPECT false
ipset destroy foo
ipset -6 create bar hash:net,port,net,port comment
ipset add bar 2001::a:b:c:d/64,udp:8080-8081,2002::/64,udp:6000-6001
ipset test bar 2001::1:2:3:4,udp:8080,2002::1:2:3:4,udp:6001 EXPECT true
ipset test bar 2001::1:2:3:4:5,udp:8080,2002::1:2:3:4,udp:6001 EXPECT false
ipset test bar 2001::1:2:3:4,udp:8080,2002::1:2:3:4:5,udp:6001 EXPECT false
ipset test bar 2001::1:2:3:4,udp:8082,2002::1:2:3:4,udp:6001 EXPECT false
ipset add bar 2001::/64,udp:8080,2002::1:2:0:0/96,udp:6000-6001 nomatch comment "bad-guys"
ipset test bar 2001::1:2:3:4,udp:8080,2002::1:2:3:4,udp:6001 EXPECT false
ipset test bar 2001::1:2:3:4,udp:8081,2002::1:2:3:4,udp:6001 EXPECT true
ipset test bar 2001::1:2:3:4,udp:8080,2002::2:3:4:5,udp:6001 EXPECT true
ipset destroy bar

# hash:net,port,iface
echo -e "hash:net,port,iface"
$dpip link show dpdk0 >/dev/null 2>&1
if [ $? -eq 0 ]; then
    ipset create foo hash:net,port,iface comment
    ipset add foo 10.64.13.131/16,tcp:80-82,dpdk0
    ipset test foo 10.64.111.222,tcp:81,dpdk0 EXPECT true
    ipset test foo 10.64.111.222,81,dpdk0 EXPECT false
    $dpip link show dpdk1 >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        ipset test foo 10.64.111.222,tcp:81,dpdk1 EXPECT false
    fi
    ipset add foo 10.64.88.100-10.64.88.200,tcp:82,dpdk0 nomatch comment "bad-guys"
    ipset list foo -v
    ipset test foo 10.64.88.111,tcp:81,dpdk0 EXPECT true
    ipset test foo 10.64.88.111,tcp:82,dpdk0 EXPECT false
    ipset add foo 10.64.88.111,tcp:82,dpdk0 comment "you-are-an-exception"
    ipset test foo 10.64.88.111,tcp:82,dpdk0 EXPECT true
    ipset flush foo
    ipset destroy foo
    ipset -6 create bar hash:net,port,iface hashsize 300 maxelem 1000
    ipset add  bar 2001:beef::/64,udp:100-102,dpdk0
    ipset test bar 2001:beef::abcd,udp:100,dpdk0 EXPECT true
    ipset add  bar 2001:beef::abcd/100,udp:100,dpdk0 nomatch
    ipset test bar 2001:beef::abcd,udp:100,dpdk0 EXPECT false
    ipset del  bar 2001:beef::abcd/100,udp:100,dpdk0
    ipset test bar 2001:beef::abcd,udp:100,dpdk0 EXPECT true
    ipset destroy bar
else
    echo -e "port dpdk0 not found, skipping hash:net,port,iface test"
fi

# hash:net,port
echo -e "hash:net,port"
ipset create foo hash:net,port comment
ipset add foo  192.168.100.0-192.168.102.30,tcp:10240
ipset test foo 192.168.100.111,tcp:10240 EXPECT true
ipset test foo 192.168.101.111,tcp:10240 EXPECT true
ipset test foo 192.168.101.111,tcp:10241 EXPECT false
ipset test foo 192.168.102.111,tcp:10241 EXPECT false
ipset test foo 192.168.102.30,tcp:10240  EXPECT true
ipset test foo 192.168.102.30,10240      EXPECT false
ipset test foo 192.168.102.31,tcp:10240  EXPECT false
ipset add  foo 192.168.100.101/25,tcp:10240 nomatch comment "bad-guys"
ipset test foo 192.168.100.111,tcp:10240 EXPECT false
ipset flush foo
ipset add  foo 10.128.34.211-10.128.37.189,3000-3001
ipset test foo 10.128.35.141,3001 EXPECT true
ipset add  foo 10.128.35.100-10.128.35.150,3000-3001 nomatch
ipset test foo 10.128.34.210,3000 EXPECT false
ipset test foo 10.128.34.211,3000 EXPECT true
ipset test foo 10.128.37.185,3001 EXPECT true
ipset test foo 10.128.37.190,3001 EXPECT false
ipset test foo 10.128.35.141,3001 EXPECT false
ipset destroy foo
ipset -6 create bar hash:net,port maxelem 1024
ipset add  bar 2001::/64,tcp:80-88
ipset test bar 2001::1:2:3:4,tcp:85 EXPECT true
ipset test bar 2001::1111:2222:3333:4444,tcp:88 EXPECT true
ipset test bar 2001::1:2:3:4,tcp:89 EXPECT false
ipset test bar 2001::1:2:3:4:5,tcp:85 EXPECT false
ipset test bar 2001::eeee:aaaa:1:6,tcp:85 EXPECT true
ipset add bar 2001::eeee:aaaa:1243:6789/96,tcp:84-86 nomatch
ipset test bar 2001::eeee:aaaa:1:6,tcp:85 EXPECT false
ipset destroy bar

# hash:net,port,net
echo -e "hash:net,port,net"
ipset create foo hash:net,port,net
ipset add  foo 192.168.188.20-192.168.190.36,2021-2022,192.168.33.223-192.168.34.123
ipset flush foo
ipset add  foo 10.60.0.0/16,tcp:10240-10242,10.130.0.0/16
ipset test foo 10.60.12.34,tcp:10241,10.130.56.78 EXPECT true
ipset test foo 10.60.0.0,tcp:10242,10.130.255.255 EXPECT true
ipset test foo 10.61.0.0,tcp:10240,10.130.255.255 EXPECT false
ipset test foo 10.60.0.0,udp:10240,10.130.255.255 EXPECT false
ipset test foo 10.60.100.168,tcp:10242,10.130.100.192 EXPECT true
ipset add foo 10.60.100.100-10.60.100.200,tcp:10242,10.130.100.100-10.130.100.200 nomatch
ipset test foo 10.60.100.168,tcp:10242,10.130.100.192 EXPECT false
ipset test foo 10.60.100.168,tcp:10241,10.130.100.192 EXPECT true
ipset test foo 10.60.100.201,tcp:10242,10.130.100.192 EXPECT true
ipset destroy foo
ipset -6 create bar hash:net,port,net hashsize 1024 maxelem 4096 comment
ipset add  bar 210e:36a9::aa:bbbb/96,udp:8080-8082,2408:a91e::cc:dddd/96 comment "test-entries"
ipset test bar 210e:36a9::12:3456,udp:8080,2408:a91e::78:9abc EXPECT true
ipset test bar 210e:36a9::ff:ffff,udp:8080,2408:a91e:: EXPECT true
ipset test bar 210e:36a9::,udp:8082,2408:a91e::ff:ffff EXPECT true
ipset add  bar 210e:36a9::12:3456/102,udp:8080,2408:a91e::78:9abc/102 nomatch
ipset test bar 210e:36a9::12:3456,udp:8080,2408:a91e::78:9abc EXPECT false
ipset del  bar 210e:36a9::12:3456/102,udp:8080,2408:a91e::78:9abc/102
ipset test bar 210e:36a9::ff:ffff,udp:8080,2408:a91e:: EXPECT true
ipset test bar 210e:36a9::12:3456,udp:8080,2408:a91e::78:9abc EXPECT true
ipset destroy bar

# hash:ip,port,net
echo -e "hash:ip,port,net"
ipset create foo hash:ip,port,net comment
ipset add  foo 192.168.12.1/24,tcp:8080,192.168.100.0/24
ipset test foo 192.168.12.211,tcp:8080,192.168.100.211 EXPECT true
ipset test foo 192.168.12.0,tcp:8080,192.168.100.255 EXPECT true
ipset test foo 192.168.12.211,tcp:8080,192.168.101.0 EXPECT false
ipset test foo 192.168.13.0,tcp:8080,192.168.100.211 EXPECT false
ipset test foo 192.168.12.211,8080,192.168.100.211 EXPECT false
ipset add foo 192.168.12.200-192.168.12.255,tcp:8080,192.168.100.200-192.168.100.255 nomatch
ipset list -v
ipset test foo 192.168.12.211,tcp:8080,192.168.100.111 EXPECT true
ipset test foo 192.168.12.211,tcp:8080,192.168.100.211 EXPECT false
ipset add  foo 192.168.12.211,tcp:8080,192.168.100.211/32 comment "I'm-innocent"
ipset test foo 192.168.12.211,tcp:8080,192.168.100.211 EXPECT true
ipset del  foo 192.168.12.200-192.168.12.255,tcp:8080,192.168.100.200-192.168.100.255
ipset flush foo
ipset add foo 10.61.240.1-10.61.240.9,udp:10240-10242,10.110.123.102/21
ipset test foo 10.61.240.3,udp:10240,10.110.123.123 EXPECT true
ipset test foo 10.61.240.6,udp:10241,10.110.120.1 EXPECT true
ipset test foo 10.61.240.9,udp:10242,10.110.127.255 EXPECT true
ipset test foo 10.61.240.3,udp:10243,10.110.123.123 EXPECT false
ipset destroy foo
ipset -6 create bar hash:ip,port,net
ipset add bar 2001::1,8080-8082,2002::/64
ipset add bar 2001::2,8080-8082,2002::/64
ipset add bar 2001::3,8080-8082,2002::/64
ipset add bar 2001::1,8080-8082,2002::aaaa:bbbb:ccc1:2222/108 nomatch
ipset test bar 2001::1,8081,2002::1:2:3:4 EXPECT true
ipset test bar 2001::1,8081,2002::1:2:3:4:5 EXPECT false
ipset test bar 2001::2,8080,2002:: EXPECT true
ipset test bar 2001::1,8081,2002::aaaa:bbbb:ccc1:2345 EXPECT false
ipset test bar 2001::1,8081,2002::aaaa:bbbb:cc11:2345 EXPECT true
ipset destroy bar
