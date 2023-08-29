**Run DPVS in Container**
------

The document presents a solution to run DPVS and its related tools in docker containers. It's a step-by-step tutorial that breaks down the whole topic into serveral small parts shown as below.

* Build DPVS container images with Dockerfile.
* Run DPVS in container.
* Configure services with keepalived or dpvs-agent, which also run in containers.
* Set up devel environments using DPVS container image.

We run a container for each DPVS component with the docker tool. Container orchestrations like Kubernetes or Docker Swarm are not used. The containers use host network and loose restrictions in runtime capability and volume mapping. So the solution is pretty experimental, and extral efforts are required if you want to make it productive.

# 1. Build DPVS Container Image

DPVS provides a [Dockerfile](../../Dockerfile) that employs the `centos:centos7.9.2009` as base image. It resolves all dependencies except the pkgconfig RPM and Mellanox OFED tarball to compile DPDK/DPVS from source codes and build DPVS container images. Refer to the comments in the Dockerfile to resolve the two broken dependencies manually, and after that, run the command

```sh
docker build -t github.com/iqiyi/dpvs:{version} .
```
in the directory of Dockerfile to build DPVS docker image, where `{version}` is the DPVS version, v1.9.5 for example.

# 2. Install Host Requirements

### 2.1. Install kernel modules on the host and bind NIC drivers

All DPVS required kernel modules should be installed on the host, including uio and NIC specific dpdk drivers. Notes that toa and uoa kernel modules are used on backend servers, and aren't required on the DPVS host. Bind NICs to the required kernel drivers if needed, for example, use the following commands to bind the intel ixgbe NIC at `0000:01:00.1` with `uio_pci_generic` driver.

```sh
modprobe uio
modprobe uio_pci_generic
dpdk-devbind -b uio_pci_generic 0000:01:00.1
```

### 2.2. Configure hugepage memory

We should reserve hugepages for DPVS on the host. For example, the command below reserves 16GB hugepage memory of 2MB size on each numa node of the host.

```sh
echo 8192 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
echo 8192 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages
```
Refer to [Quick Start](../../README.md) doc for more details.

### 2.3. Prepare a work directory

The work directory contains config files, running files, and log files for DPVS. The directory is mapped into multiple containers, such as dpvs, keepalived, and dpvs-agent, simplifying data sharing across containers. In this tutorial, we create `/var/run/dpvs/` as the work directory.

```sh
mkdir -p /var/run/dpvs
mkdir -p /var/run/dpvs/logs/dpvs-agent
mkdir -p /var/run/dpvs/logs/healthcheck
```

# 3. Run DPVS in Container

### 3.1 Start a DPVS container

Firstly, prepare a dpvs config file and place it in the work directory `/var/run/dpvs/dpvs.conf`. Refer to [dpvs sample configs](../../conf) to customize your config file. Then start dpvs container with the docker command below.

```sh
docker run --name dpvs \
      -d --privileged --network host \
      -v /dev:/dev \
      -v /sys:/sys \
      -v /lib/modules:/lib/modules \
      -v /var/run/dpvs:/dpvs \
      github.com/iqiyi/dpvs:v1.9.5 \
      -c /dpvs/dpvs.conf -p /dpvs/dpvs.pid -x /dpvs/dpvs.ipc \
      -- -a 0000:01:00.1
```
It starts a container named `dpvs` in the host network namespace on a single NIC port, and maps host directories `/dev`, `/sys`, `/lib/modules` and the work directory into the container.

Finally, confirm that the dpvs container is running in the background.

```sh
[dpvs]# docker ps -f name=dpvs$
CONTAINER ID        IMAGE                          COMMAND                  CREATED             STATUS              PORTS               NAMES
f71c30c6d8a1        github.com/iqiyi/dpvs:v1.9.5   "/usr/bin/dpvs -c /d…"   2 seconds ago       Up 1 second                             dpvs
```

### 3.2 Use dpip/ipvsadm tools in DPVS image

Although discouraged, we can also execute the `dpip` and `ipvsadm` command in container.

```sh
docker run --name dpip \
      --rm --network none \
      -v /var/run/dpvs:/dpvs \
      -e DPVS_IPC_FILE=/dpvs/dpvs.ipc \
      --entrypoint=/usr/bin/dpip \
      github.com/iqiyi/dpvs:v1.9.5 \
      ...
docker run --name ipvsadm \
      --rm --network none \
      -v /var/run/dpvs:/dpvs \
      -e DPVS_IPC_FILE=/dpvs/dpvs.ipc \
      --entrypoint=/usr/bin/ipvsadm \
      github.com/iqiyi/dpvs:v1.9.5 \
      ...
```

For simplification, create the aliases,

```sh
alias dpip='docker run --name dpip --rm --network none -v /var/run/dpvs:/dpvs -e DPVS_IPC_FILE=/dpvs/dpvs.ipc --entrypoint=/usr/bin/dpip github.com/iqiyi/dpvs:v1.9.5'
alias ipvsadm='docker run --name ipvsadm --rm --network none -v /var/run/dpvs:/dpvs -e DPVS_IPC_FILE=/dpvs/dpvs.ipc --entrypoint=/usr/bin/ipvsadm github.com/iqiyi/dpvs:v1.9.5'
```
and then you can use the containerized `dpip` and `ipvsadm` commands the same way as using the binaries directly. However, the containerized commands are costy and slow, so it's advised use the binaries directly in the productive environments.

### 3.3 Setup the DPVS container network

Before running test services, we should configure the host network for both DPVS and KNI devices. The tests run in layer2 network of 192.168.88.0/24 of vlan 102, which can be configured with the aliased `dpip` and linux `ip` commands.

```sh
dpip vlan add dpdk0.102 link dpdk0 id 102
dpip addr add 192.168.88.28/24 dev dpdk0.102
dpip addr add 2001::28/64 dev dpdk0.102
ip addr add 192.168.88.28/24 dev dpdk0.102.kni
ip addr add 2001::28/64 dev dpdk0.102.kni
ip link set dpdk0.102.kni up
```
Alternatively, the goal can be also accomplished by HTTP APIs if you are using dpvs-agent. API is more suitable to integrate DPVS into your own service management platform. Refer to the next sector for how to run dpvs-agent in container. The following commands use `curl` to invoke the dpvs-agent APIs, and are equivalent to the `dpip` and `ip` commands listed above.

```sh
curl -X PUT "http://127.0.0.1:6601/v2/device/dpdk0.102/vlan" -H "Content-type:application/json" -d "{\"device\":\"dpdk0\", \"id\":\"102\"}"
curl -X PUT "http://127.0.0.1:6601/v2/device/dpdk0.102/addr" -H "Content-type:application/json" -d "{\"addr\":\"192.168.88.28/24\"}"
curl -X PUT "http://127.0.0.1:6601/v2/device/dpdk0.102/addr" -H "Content-type:application/json" -d "{\"addr\":\"2001::28/64\"}"
curl -X PUT "http://127.0.0.1:6601/v2/device/dpdk0.102.kni/netlink/addr" -H "Content-type:application/json" -d "{\"addr\":\"192.168.88.28/24\"}"
curl -X PUT "http://127.0.0.1:6601/v2/device/dpdk0.102.kni/netlink/addr" -H "Content-type:application/json" -d "{\"addr\":\"2001::28/64\"}"
curl -X PUT "http://127.0.0.1:6601/v2/device/dpdk0.102.kni/netlink"
```

### 3.4 Deploy services in the DPVS container

There are three ways to deloy services into DPVS: ipvsadm, keepalived, and dpvs-agent. `ipvsadm` is a command line tool, `keepalived` uses config files, and `dpvs-agent` provides a set of HTTP API. 

* **Deploy service with `ipvsadm`**
You can either use the aliased `ipvsadm` in DPVS container image, or deploy it in the host. To deploy services with `ipvsadm`, there are no differences from the corresponding case of non-containerized DPVS. So we are not going to elaborate on it. Refer to [Quick Start](../../README.md) for details.

* **Deploy service with `keepalived`**

In container, the keepalived must be run in foreground, privileged mode, and the same network (i.e. host network) as the dpvs container. Extra network capabilities such as NET_ADMIN, NET_BROADCAST and NET_RAW are required. 

```sh
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
```
The keepalived config file [keepalived.conf](./keepalived.conf) should be placed in the work directory beforehand. The config file contains two fullnat test services, one is pure IPv4, the other one is NAT64. Inspect the keepalived container and ensure it's running now.

```sh
[dpvs]# docker ps -f name=keepalived
CONTAINER ID        IMAGE                          COMMAND                  CREATED              STATUS              PORTS               NAMES
f52f4b1f4625        github.com/iqiyi/dpvs:v1.9.5   "/usr/bin/keepalived…"   About a minute ago   Up About a minute                       keepalived
```
Check the serivces deployed by keepalived.

```sh
[dpvs]# ipvsadm -ln
IP Virtual Server version 1.9.5 (size=0)
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port           Forward Weight ActiveConn InActConn
TCP  192.168.88.1:80 rr conn-timeout 60
  -> 192.168.88.30:80             FullNat 100    0          37        
  -> 192.168.88.130:80            FullNat 100    0          34        
TCP  [2001::1]:80 conhash sip
  -> 192.168.88.30:80             FullNat 100    0          0         
  -> 192.168.88.30:8080           FullNat 100    0          0         
  -> 192.168.88.130:8080          FullNat 100    0          3    
```

* **Deploy service with `dpvs-agent`**

The following docker command starts dpvs-agent in container on host network port 6601. NET_ADMIN capability is required to configure IPs on KNI device.

```sh
docker run --name dpvs-agent \
      --cap-add=NET_ADMIN \
      -d --network host \
      -v /var/run/dpvs:/dpvs \
      --entrypoint=/usr/bin/dpvs-agent \
      github.com/iqiyi/dpvs:v1.9.5 \
      --log-dir=/dpvs/logs/dpvs-agent \
      --ipc-sockopt-path=/dpvs/dpvs.ipc\
      --host=0.0.0.0 --port=6601
```

Verify the dpvs-agent container is running,

```sh
[dpvs]# docker ps -f name=dpvs-agent
CONTAINER ID        IMAGE                          COMMAND                  CREATED             STATUS              PORTS               NAMES
9b752bc7250f        github.com/iqiyi/dpvs:v1.9.5   "/usr/bin/dpvs-agent…"   2 seconds ago       Up 1 second                             dpvs-agent
```
then deploy a test service with dpvs-agent API,

```sh
curl -X PUT "http://127.0.0.1:6601/v2/vs/2001::2-80-tcp" -H "Content-type:application/json" -d "{\"SchedName\":\"wrr\"}"
curl -X PUT "http://127.0.0.1:6601/v2/device/dpdk0.102/addr" -H "Content-type:application/json" -d "{\"addr\":\"2001::2\"}"
curl -X PUT "http://127.0.0.1:6601/v2/vs/2001::2-80-tcp/laddr" -H "Content-type:application/json" -d "{\"device\":\"dpdk0.102\", \"addr\":\"192.168.88.241\"}"
curl -X PUT "http://127.0.0.1:6601/v2/vs/2001::2-80-tcp/laddr" -H "Content-type:application/json" -d "{\"device\":\"dpdk0.102\", \"addr\":\"192.168.88.242\"}"
curl -X PUT "http://127.0.0.1:6601/v2/device/dpdk0.102/addr?sapool=true" -H "Content-type:application/json" -d "{\"addr\":\"192.168.88.241\"}"
curl -X PUT "http://127.0.0.1:6601/v2/device/dpdk0.102/addr?sapool=true" -H "Content-type:application/json" -d "{\"addr\":\"192.168.88.242\"}"
curl -X PUT "http://127.0.0.1:6601/v2/vs/2001::2-80-tcp/rs" -H "Content-type:application/json" -d "{\"Items\":[{\"ip\":\"192.168.88.30\", \"port\":80, \"weight\":100}]}"
curl -X PUT "http://127.0.0.1:6601/v2/vs/2001::2-80-tcp/rs" -H "Content-type:application/json" -d "{\"Items\":[{\"ip\":\"192.168.88.130\", \"port\":8080, \"weight\":100}]}"
curl -X PUT "http://127.0.0.1:6601/v2/vs/2001::2-80-tcp/rs" -H "Content-type:application/json" -d "{\"Items\":[{\"ip\":\"10.1.1.1\", \"port\":80, \"weight\":100}]}"
```

and check the test service we deployed just now.

```sh
[dpvs]# ipvsadm -ln -t [2001::2]:80
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port           Forward Weight ActiveConn InActConn
TCP  [2001::2]:80 wrr
  -> 192.168.88.30:80             FullNat 100    0          0         
  -> 192.168.88.130:8080          FullNat 100    0          1         
  -> 10.1.1.1:80                  FullNat 100    0          7         
[dpvs]# ipvsadm -G -t [2001::2]:80  
VIP:VPORT            TOTAL    SNAT_IP              CONFLICTS  CONNS     
[2001::2]:80         2        
                              192.168.88.241       0          5         
                              192.168.88.242       0          6 
```

Finally, start the healthcheck service for dpvs-agent, which also runs in container.

```sh
docker run --name healthcheck \
      -d --network host \
      -v /var/run/dpvs:/dpvs \
      --entrypoint=/usr/bin/healthcheck \
      github.com/iqiyi/dpvs:v1.9.5 \
      -log_dir=/dpvs/logs/healthcheck \
      -lb_iface_addr=localhost:6601
```
Check the test service again,

```sh
[dpvs]# ipvsadm -ln -t [2001::2]:80
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port           Forward Weight ActiveConn InActConn
TCP  [2001::2]:80 wrr
  -> 192.168.88.30:80             FullNat 100    0          1         
  -> 192.168.88.130:8080          FullNat 100    0          1         
  -> 10.1.1.1:80              	  FullNat 0      0          6          inhibited
```
then we find that the invalid backend `10.1.1.1:80` is removed from the service successfully.

**Summury**

Now let's have a look at all the containerized process and test services we've deployed.

```sh
[dpvs]# docker ps
CONTAINER ID        IMAGE                          COMMAND                  CREATED             STATUS              PORTS               NAMES
e43d8ec1700d        github.com/iqiyi/dpvs:v1.9.5   "/usr/bin/healthchec…"   9 minutes ago       Up 9 minutes                            healthcheck
9b752bc7250f        github.com/iqiyi/dpvs:v1.9.5   "/usr/bin/dpvs-agent…"   19 minutes ago      Up 19 minutes                           dpvs-agent
f52f4b1f4625        github.com/iqiyi/dpvs:v1.9.5   "/usr/bin/keepalived…"   36 minutes ago      Up 36 minutes                           keepalived
f71c30c6d8a1        github.com/iqiyi/dpvs:v1.9.5   "/usr/bin/dpvs -c /d…"   15 hours ago        Up 15 hours                             dpvs

[dpvs]# ipvsadm -ln
IP Virtual Server version 1.9.5 (size=0)
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port           Forward Weight ActiveConn InActConn
TCP  192.168.88.1:80 rr conn-timeout 60
  -> 192.168.88.30:80             FullNat 100    0          42        
  -> 192.168.88.130:80            FullNat 100    0          40        
TCP  [2001::1]:80 conhash sip
  -> 192.168.88.30:80             FullNat 100    0          0         
  -> 192.168.88.30:8080           FullNat 100    0          0         
  -> 192.168.88.130:8080          FullNat 100    0          15        
TCP  [2001::2]:80 wrr
  -> 192.168.88.30:80             FullNat 100    0          7         
  -> 192.168.88.130:8080          FullNat 100    0          7         
  -> 10.1.1.1:80                  FullNat 0      0          0          inhibited

[dpvs]# ipvsadm -G
VIP:VPORT            TOTAL    SNAT_IP              CONFLICTS  CONNS     
[2001::2]:80         2        
                              192.168.88.241       0          8         
                              192.168.88.242       0          7         
[2001::1]:80         2        
                              192.168.88.240       0          7         
                              192.168.88.241       0          8         
192.168.88.1:80      2        
                              192.168.88.240       0          41        
                              192.168.88.241       0          39  
[dpvs]# dpip addr show
inet6 2001::28/64 scope global dpdk0.102
     valid_lft forever preferred_lft forever
inet 192.168.88.242/32 scope global dpdk0.102
     valid_lft forever preferred_lft forever
inet6 2001::1/128 scope global dpdk0.102
     valid_lft forever preferred_lft forever
inet 192.168.88.1/32 scope global dpdk0.102
     valid_lft forever preferred_lft forever
inet6 2001::2/128 scope global dpdk0.102
     valid_lft forever preferred_lft forever
inet 192.168.88.240/32 scope global dpdk0.102
     valid_lft forever preferred_lft forever
inet 192.168.88.28/24 scope global dpdk0.102
     valid_lft forever preferred_lft forever
inet 192.168.88.241/32 scope global dpdk0.102
     valid_lft forever preferred_lft forever

[dpvs]# dpip route show
inet 192.168.88.1/32 via 0.0.0.0 src 0.0.0.0 dev dpdk0.102 mtu 1500 tos 0 scope host metric 0 proto auto 
inet 192.168.88.28/32 via 0.0.0.0 src 0.0.0.0 dev dpdk0.102 mtu 1500 tos 0 scope host metric 0 proto auto 
inet 192.168.88.240/32 via 0.0.0.0 src 0.0.0.0 dev dpdk0.102 mtu 1500 tos 0 scope host metric 0 proto auto 
inet 192.168.88.241/32 via 0.0.0.0 src 0.0.0.0 dev dpdk0.102 mtu 1500 tos 0 scope host metric 0 proto auto 
inet 192.168.88.242/32 via 0.0.0.0 src 0.0.0.0 dev dpdk0.102 mtu 1500 tos 0 scope host metric 0 proto auto 
inet 192.168.88.0/24 via 0.0.0.0 src 192.168.88.28 dev dpdk0.102 mtu 1500 tos 0 scope link metric 0 proto auto 
[dpvs]# dpip -6 route show 
inet6 2001::1/128 dev dpdk0.102 mtu 1500 scope host
inet6 2001::2/128 dev dpdk0.102 mtu 1500 scope host
inet6 2001::28/128 dev dpdk0.102 mtu 1500 scope host
inet6 2001::/64 src 2001::28 dev dpdk0.102 mtu 1500 scope link

[dpvs]# ip addr show dpdk0.102.kni
560: dpdk0.102.kni: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 24:6e:96:75:7c:fa brd ff:ff:ff:ff:ff:ff
    inet 192.168.88.28/24 scope global dpdk0.102.kni
       valid_lft forever preferred_lft forever
    inet6 2001::28/64 scope global 
       valid_lft forever preferred_lft forever
    inet6 fe80::266e:96ff:fe75:7cfa/64 scope link 
       valid_lft forever preferred_lft forever
```
The whole test procedures described above are written into the [run.sh](./run.sh) script. Read the script and then run it, you may gain insights into solutions to the integration of DPVS multiple componets into a container group such as kubernete Pod.

# 4. Develop DPVS in Container

We also provide a container image for DPVS developers. You can build an image for devel environments by specifying the build target as `builder`.

```sh
docker build --target builder -t github.com/iqiyi/dpvs-builder:{version} .
```
Once the dpvs-builder container image built successfully, run

```sh
docker run --name=dpvs-devel -it github.com/iqiyi/dpvs-builder:v1.9.5 
```
, and you enter a DPVS devel container, which installs the source codes and all dependencies for DPVS, include DPDK library and development tool chains. It's an easy place to make changes to DPVS codes for beginners.

