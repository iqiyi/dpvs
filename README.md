DPVS
----

![dpvs.png](./pic/dpvs.png)

# Introduction

`DPVS` is a high performance **Layer-4 load balancer** based on [DPDK](http://dpdk.org). It's derived from Linux [LVS](http://www.linuxvirtualserver.org/) and it's modification [alibaba/LVS](https://github.com/alibaba/LVS).

>  the name `DPVS` comes from "DPDK-LVS".

Different techniques are applied for high performance:

* *Kernel by-pass* (user space implementation)
* *Share-nothing*, per-CPU for key data (Lockless)
* *RX Steering* and *CPU affinity* (avoid context switch)
* *Batching* TX/RX
* *Zero Copy* (avoid packet copy and syscalls).
* *Polling* instead of interrupt.
* *lockless message* for high performance ICP.
* other techs enhanced by *DPDK*

Major features of `DPVS` including:

* *L4 Load Balancer*, including FNAT, DR mode, etc.
* Different *schedule algorithm* like RR, WLC, WRR, etc.
* User-space *Lite IP stack* (IPv4, Routing, ARP, ICMP ...).
* *SNAT* mode for Internet access from internal network.
* Support *KNI*, *VLAN*, *Bonding* for different IDC environment.
* Security aspect, support *TCP syn-proxy*, *Conn-Limit*, *black-list*
* QoS: *Traffic Control* (Ongoing)

`DPVS` feature modules are illustrated as following picture.

![modules](./pic/modules.png)

# Quick Start

## Test Environment

This *quick start* is tested with the environment below.

* Linux Distribution: CentOS 7.2
* Kernel: 3.10.0-327.el7.x86_64
* CPU: Intel(R) Xeon(R) CPU E5-2650 v3 @ 2.30GHz
* NIC: Intel X540
* Memory: 64G and NUMA system.
* GCC: gcc version 4.8.5 20150623 (Red Hat 4.8.5-4)

Other environment should also OK if DPDK works, pls check [dpdk.org](http://www.dpdk.org) for more info.

## Clone DPVS

```bash
$ git clone https://github.com/iqiyi/dpvs.git
$ cd dpvs
```

Well, let's start from DPDK then.

## DPDK setup.

Currently, `DPDK-16.07` is used for `DPVS` and latest `DPDK` stable version will be integrated soon.

> You can skip this section if experienced with DPDK, and refer the [link](http://dpdk.org/doc/guides/linux_gsg/index.html) for details.

```bash
$ wget http://fast.dpdk.org/rel/dpdk-16.07.2.tar.xz   # download from dpdk.org if link failed.
$ tar vxf dpdk-16.07.2.tar.xz
```

There's a patch for DPDK `kni` driver for hardware multicast, apply it if needed (for example, launch `ospfd` on `kni` device).

> assuming we are in DPVS root dir and dpdk-stable-16.07.2 is under it, pls note it's not mandatory, just for convenience.

```
$ cd <path-of-dpvs>
$ cp patch/dpdk-16.07/0001-kni-use-netlink-event-for-multicast-driver-part.patch dpdk-stable-16.07.2/
$ cd dpdk-stable-16.07.2/
$ patch -n 1 < 0001-kni-use-netlink-event-for-multicast-driver-part.patch
```

Now build DPDK and export `RTE_SDK` env variable for DPDK app (DPVS).

```bash
$ cd dpdk-stable-16.07.2/
$ make config T=x86_64-native-linuxapp-gcc
Configuration done
$ make # or make -j40 to save time, where 40 is the cpu core number.
$ export RTE_SDK=$PWD
```

In our tutorial, `RTE_TARGET` is not set, the value is "build" by default, thus DPDK libs and header files can be found in `dpdk-stable-16.07.2/build`. It could be other values.

Now to set up DPDK hugepage, our test environment is NUMA system. For single-node system pls refer the [link](http://dpdk.org/doc/guides/linux_gsg/sys_reqs.html).

```bash
$ # for NUMA machine
$ echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
$ echo 1024 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages

$ mkdir /mnt/huge
$ mount -t hugetlbfs nodev /mnt/huge
```

Install Kernel modules and bind NIC with `igb_uio` driver. Quick start uses only one NIC, normally we use 2 for Full-NAT cluster, even 4 for bonding mode. Assuming `eth0` will be used for DPVS/DPDK, and another standalone Linux NIC for debug, for example, `eth1`.

```bash
$ modprob uio
$ cd dpdk-stable-16.07.2/

$ insmod build/kmod/igb_uio.ko
$ insmod build/kmod/rte_kni.ko

$ ./tools/dpdk-devbind.py --st
$ ifconfig eth0 down  # assuming eth0 is 0000:06:00.0
$ ./tools/dpdk-devbind.py -b igb_uio 0000:06:00.0
```

`dpdk-devbind.py -u` can be used to unbind driver and switch it back to Linux driver like `ixgbe`. You can also use `lspci` or `ethtool -i eth0` to check the NIC PCI bus-id. Pls see [DPDK site](http://www.dpdk.org) for details.

## Build DPVS

It's simple, just set `RTE_SDK` and build it.

```bash
$ cd dpdk-stable-16.07.2/
$ export RTE_SDK=$PWD
$ cd <path-of-dpvs>

$ make # or "make -j40" to speed up.
$ make install
```

> may need install dependencies, like `openssl` and `popt`.

Output files are installed to `dpvs/bin`.

```bash
$ ls bin/
dpip  dpvs  ipvsadm  keepalived
```

* `dpvs` is the main program.
* `dpip` is the tool to set IP address, route, vlan, neigh etc.
* `ipvsadm` and `keepalived` come from LVS, both are modified.

## Launch DPVS

Now, `dpvs.conf` must be put at `/etc/dpvs.conf`, just copy it from `conf/dpvs.conf.single-nic.sample`.

```bash
$ cp conf/dpvs.conf.single-nic.sample /etc/dpvs.conf
```

and start DPVS,

```bash
$ cd <path-of-dpvs>/bin
$ ./dpvs &
```

Check if it's get started ?

```bash
$ ./dpip link show
1: dpdk0: socket 0 mtu 1500 rx-queue 8 tx-queue 8
    UP 10000 Mbps full-duplex fixed-nego promisc-off
    addr A0:36:9F:9D:61:F4 OF_RX_IP_CSUM OF_TX_IP_CSUM OF_TX_TCP_CSUM OF_TX_UDP_CSUM
```

If you see this message. Well done, `DPVS` is working with NIC `dpdk0`!

> Don't worry if you see this error,
```
EAL: Error - exiting with code: 1
  Cause: ports in DPDK RTE (2) != ports in dpvs.conf(1)
```
it means the NIC used by DPVS is not match `/etc/dpvs.conf`. Pls use `dpdk-devbind` to adjust the NIC number or modify `dpvs.conf`. We'll improve this part to make DPVS more "clever" to avoid modify config file when NIC count is not match.


## Test Full-NAT Load Balancer

The test topology looks like,

![fnat-single-nic](./pic/fnat-single-nic.png)

Set VIP and Local IP (LIP, needed by Full-NAT mode) on DPVS. Let's put commands into `setup.sh`. You do some check by `./ipvsadm -ln`, `./dpip addr show`.

```bash
$ cat setup.sh
VIP=192.168.100.100
LIP=192.168.100.200
RS=192.168.100.2

./dpip addr add ${VIP}/24 dev dpdk0
./ipvsadm -A -t ${VIP}:80 -s rr
./ipvsadm -a -t ${VIP}:80 -r ${RS} -b

./ipvsadm --add-laddr -z ${LIP} -t 192.168.100.100:80 -F dpdk0
$

$ ./setup.sh
```

Access VIP from Client, it looks good!

```bash
client $ curl 192.168.100.100
Your ip:port : 192.168.100.3:56890
```

# Performance Test

Our test shows the forwarding speed (pps) of DPVS is several times than LVS and as good as Google's [Maglev](https://research.google.com/pubs/pub44824.html).

![performance](./pic/performance.png)

# License

Pls see the [License](./LICENSE.md) file.

# Contact Us

`DPVS` is developing by [iQiYi](https://www.iqiyi.com) [QLB](mailto:qlb-devel@dev.qiyi.com) team since Arpil 2016 and now open-sourced. It's already widely used in iQiYi IDC for L4 load balancer and SNAT clusters, and we plan to replace all our LVS clusters with DPVS. We are very happy that **more people can get involved** in this project. Welcome to try, report issues and submit pull requests. And pls feel free to contact us through **Github** or [Email](mailto:qlb-devel@dev.qiyi.com).
