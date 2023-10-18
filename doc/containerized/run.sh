#!/bin/sh

## install host requirements
if [ $# -ge 1 -a _$1 = _initial ]; then
    ## FIXME: use proper dpdk drivers for different nics
    modprobe uio
    modprobe uio_pci_generic
    dpdk-devbind -b uio_pci_generic 0000:01:00.1
    
    echo 8192 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
    echo 8192 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages
    
    mkdir /var/run/dpvs
    mkdir -p /var/run/dpvs/logs/dpvs-agent
    mkdir -p /var/run/dpvs/logs/healthcheck
fi

## stop and clean the running containers
docker stop dpvs && docker rm dpvs
docker stop keepalived && docker rm keepalived
docker stop dpvs-agent && docker rm dpvs-agent
docker stop healthcheck && docker rm healthcheck
rm -f /var/run/dpvs/{*.pid,dpvs.ipc}

## TODO: prepare config file: /var/run/dpvs/dpvs.conf

## start dpvs
docker run --name dpvs \
      -d --privileged --network host \
      -v /dev:/dev \
      -v /sys:/sys \
      -v /lib/modules:/lib/modules \
      -v /var/run/dpvs:/dpvs \
      github.com/iqiyi/dpvs:v1.9.5 \
      -c /dpvs/dpvs.conf -p /dpvs/dpvs.pid -x /dpvs/dpvs.ipc \
      -- -a 0000:01:00.1
sleep 10

## start dpvs-agent
docker run --name dpvs-agent \
      --cap-add=NET_ADMIN \
      -d --network host \
      -v /var/run/dpvs:/dpvs \
      --entrypoint=/usr/bin/dpvs-agent \
      github.com/iqiyi/dpvs:v1.9.5 \
      --log-dir=/dpvs/logs/dpvs-agent \
      --ipc-sockopt-path=/dpvs/dpvs.ipc\
      --host=0.0.0.0 --port=6601
sleep 3


## set command line tools
alias ipvsadm='docker run --name ipvsadm --rm --network none -v /var/run/dpvs:/dpvs -e DPVS_IPC_FILE=/dpvs/dpvs.ipc --entrypoint=/usr/bin/ipvsadm github.com/iqiyi/dpvs:v1.9.5'
#docker run --name ipvsadm \
#      --rm --network none \
#      -v /var/run/dpvs:/dpvs \
#      -e DPVS_IPC_FILE=/dpvs/dpvs.ipc \
#      --entrypoint=/usr/bin/ipvsadm \
#      github.com/iqiyi/dpvs:v1.9.5 \
#      ...
alias dpip='docker run --name dpip --rm --network none -v /var/run/dpvs:/dpvs -e DPVS_IPC_FILE=/dpvs/dpvs.ipc --entrypoint=/usr/bin/dpip github.com/iqiyi/dpvs:v1.9.5'
#docker run --name dpip \
#      --rm --network none \
#      -v /var/run/dpvs:/dpvs \
#      -e DPVS_IPC_FILE=/dpvs/dpvs.ipc \
#      --entrypoint=/usr/bin/dpip \
#      github.com/iqiyi/dpvs:v1.9.5 \
#      ...

## configure host network
#dpip vlan add dpdk0.102 link dpdk0 id 102
#dpip addr add 192.168.88.28/24 dev dpdk0.102
#dpip addr add 2001::28/64 dev dpdk0.102
#ip addr add 192.168.88.28/24 dev dpdk0.102.kni
#ip addr add 2001::28/64 dev dpdk0.102.kni
#ip link set dpdk0.102.kni up
curl -X PUT "http://127.0.0.1:6601/v2/device/dpdk0.102/vlan" -H "Content-type:application/json" -d "{\"device\":\"dpdk0\", \"id\":\"102\"}"
curl -X PUT "http://127.0.0.1:6601/v2/device/dpdk0.102/addr" -H "Content-type:application/json" -d "{\"addr\":\"192.168.88.28/24\"}"
curl -X PUT "http://127.0.0.1:6601/v2/device/dpdk0.102/addr" -H "Content-type:application/json" -d "{\"addr\":\"2001::28/64\"}"
curl -X PUT "http://127.0.0.1:6601/v2/device/dpdk0.102.kni/netlink/addr" -H "Content-type:application/json" -d "{\"addr\":\"192.168.88.28/24\"}"
curl -X PUT "http://127.0.0.1:6601/v2/device/dpdk0.102.kni/netlink/addr" -H "Content-type:application/json" -d "{\"addr\":\"2001::28/64\"}"
curl -X PUT "http://127.0.0.1:6601/v2/device/dpdk0.102.kni/netlink"

## start keepalived and deploy test services
docker run --name keepalived \
      -d --privileged --network host  \
      --cap-add=NET_ADMIN --cap-add=NET_BROADCAST --cap-add=NET_RAW \
      -v /var/run/dpvs:/dpvs \
      -e DPVS_IPC_FILE=/dpvs/dpvs.ipc \
      --entrypoint=/usr/bin/keepalived github.com/iqiyi/dpvs:v1.9.5 \
      -D -n -f /dpvs/keepalived.conf \
      --log-console --log-facility=6 \
      --pid=/dpvs/keepalived.pid \
      --vrrp_pid=/dpvs/vrrp.pid \
      --checkers_pid=/dpvs/checkers.pid

## deploy a test service with dpvs-agent api
curl -X PUT "http://127.0.0.1:6601/v2/vs/2001::2-80-tcp" -H "Content-type:application/json" -d "{\"SchedName\":\"wrr\"}"
curl -X PUT "http://127.0.0.1:6601/v2/device/dpdk0.102/addr" -H "Content-type:application/json" -d "{\"addr\":\"2001::2\"}"
curl -X PUT "http://127.0.0.1:6601/v2/vs/2001::2-80-tcp/laddr" -H "Content-type:application/json" -d "{\"device\":\"dpdk0.102\", \"addr\":\"192.168.88.241\"}" 
curl -X PUT "http://127.0.0.1:6601/v2/vs/2001::2-80-tcp/laddr" -H "Content-type:application/json" -d "{\"device\":\"dpdk0.102\", \"addr\":\"192.168.88.242\"}"
curl -X PUT "http://127.0.0.1:6601/v2/device/dpdk0.102/addr?sapool=true" -H "Content-type:application/json" -d "{\"addr\":\"192.168.88.241\"}" 
curl -X PUT "http://127.0.0.1:6601/v2/device/dpdk0.102/addr?sapool=true" -H "Content-type:application/json" -d "{\"addr\":\"192.168.88.242\"}" 
curl -X PUT "http://127.0.0.1:6601/v2/vs/2001::2-80-tcp/rs" -H "Content-type:application/json" -d "{\"Items\":[{\"ip\":\"192.168.88.30\", \"port\":80, \"weight\":100}]}"
curl -X PUT "http://127.0.0.1:6601/v2/vs/2001::2-80-tcp/rs" -H "Content-type:application/json" -d "{\"Items\":[{\"ip\":\"192.168.88.130\", \"port\":8080, \"weight\":100}]}"
curl -X PUT "http://127.0.0.1:6601/v2/vs/2001::2-80-tcp/rs" -H "Content-type:application/json" -d "{\"Items\":[{\"ip\":\"10.1.1.1\", \"port\":80, \"weight\":100}]}"

## start healthcheck for dpvs-aegnt
docker run --name healthcheck \
      -d --network host \
      -v /var/run/dpvs:/dpvs \
      --entrypoint=/usr/bin/healthcheck \
      github.com/iqiyi/dpvs:v1.9.5 \
      -log_dir=/dpvs/logs/healthcheck \
      -lb_iface_addr=localhost:6601

