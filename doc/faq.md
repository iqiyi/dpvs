DPVS Frequently Asked Questions (FAQ)
=============

### Contents

* [Fail to launch DPVS ?](#launch)
* [Does my NIC support DPVS ?](#nic)
* [How to achieve high availability ? How to upgrade DPVS ?](#high-avail)
* [Does DPVS support TOA, which TOA version is used?](#toa)
* [Does DPVS support UDP ? How to get UDP Client Real IP/port ?](#udp)
* [Does DPVS support IP fragment ?](#fragment)
* [How to launch DPVS on Virtual Machine ?](#vm)
* [How to monitor or get statistics of DPVS ?](#monitor)
* [Where can I find the support ?](#support)
* [How to test the performance of DPVS ?](#test)
* [How to resolve sa_miss when using DPVS FullNAT mode ?](#sa-miss)
* [Where can I find DPVS's log ? Is timestamp supported ?](#log)
* [Does DPVS support Bonding/VLAN/Tunnel ?](#vir-dev)
* [Why CPU usages are 100% when running DPVS ?](#cpu-100)
* [Does iptables conflict with DPVS ?](#iptables)

-------------------------------------------------

<a id="launch" />

### Fail to launch DPVS ?

Please try to follow `README.md` and `doc/tutorial.md` first. And if you still have problem, possible reasons are:

1. NIC does not support DPDK or *flow control* (`rte_flow`), please check this [answer](#nic).
2. DPDK is not compatible with Kernel Version, it cause build error, please refer to [DPDK.org](https://www.dpdk.org/) or consider upgrade the Kernel.
3. CPU core (`lcore`) and NIC queue's configure is miss-match.
   Please read `conf/*.sample`, note worker-CPU/NIC-queue are 1:1 mapping and you need one more cpu for master.
4. DPDK NIC's link is not up ? please check NIC cable first.
5. `curl` VIP in FullNAT mode fails (or sometime fails)? Please check if NIC support [rte_flow](#nic).
6. `curl` still fails. Please check route and arp by `dpip route show`, `dpip neigh show`.
6. The patchs in `patch/` are not applied.

And you may find other similar issues and solutions from Github's issues list.

<a id="nic" />

### Does my NIC support DPVS ?

Actaully, it's the question about if the NIC support DPDK as well as "flow control(rte_flow)".

First, please make sure the NIC support `DPDK`, you can check the [link](https://core.dpdk.org/supported/). Second, DPVS's FullNAT/SNAT mode need flow control(rte_flow) feature, *unless you configure only one worker*. For `rte_flow` support, this [link](http://doc.dpdk.org/guides/nics/overview.html#id1) can be checked.

Please find the DPDK driver name according to your NIC by the first link. And check `rte_flow` support for each drivers from the matrix in the second link.

1. https://core.dpdk.org/supported/
2. http://doc.dpdk.org/guides/nics/overview.html#id1

The PMD of your NIC should support the following rte_flow items,

* ipv4
* ipv6
* tcp
* udp

and the following rte_flow actions at least.

* queue
* drop

> If you are using only one worker, you can turn off dpvs flow control by setting `sa_pool/flow_enable` to `off` in dpvs.conf.

<a id="high-avail" />

### How to achieve high availability ? How to upgrade DPVS ?

Like `LVS`, DPVS should be deployed in **ECMP** *Cluster Mode*. If one director went down, others still keep working, new connections are not affected. When using *Cluster Mode* (for both one-arm and two arms), `keeplived` can still be used for VIP (LIP) configuration and RS health check purpose. Note the `keeplived`'s VIP *backup (`VRRP`)* feature is not used.

When upgrade directors (`DPVS`), we can "stop" `ospfd`, upgrade it, and start `ospfd` again. Yes, some existing connection may broken, however, applications may have fail-over (re-try) mechanism.

To address the issue director crash or getting upgraded, some implementation introduce *session sharing/sync* between directors. Honestly, this is not easy, because,

1. LIPs are not same for each DPVS director.
2. connection-table is per-lcore, when sync-ed to another DPVS, how to handle per-lcore table in another machine?
3. "Session-Sharing" works well for "long-connection" but not "short-connection", since the connection's creation/destruction are too frequently to be sync-ed to other directors.

As I know, some L4 LB implemented "session sharing" or "session synchronization", they are configuring same LIPs for each LB director. And each LIP is configured for one CPU core. Both cases are quite different from DPVS's implementation and deployment.

On the other hand, for the high availability of Real Servers, DPVS leverage `keepalived` for health check on RS, both TCP/UDP services can be checked, you can also write your own checking scripts. For more info about health-check, please refer to `LVS`'s document.

<a id="toa" />

### Does  DPVS support `TOA`, which `TOA` version is used?

Yes, and DPVS's `TOA` derives from the open-sourced [alibaba/LVS](https://github.com/alibaba/LVS). The RS's TOA kernel module implementation is at [kmod/toa](../kmod/toa). Compared to the original TOA, DPVS's TOA add supports for IPv6 and Nat64. TOA format on the side of DPVS is defined in [proto_tcp.h](../include/ipvs/proto_tcp.h), while option code is `254`, option length is 8.

  ```C
  // include/ipvs/proto_tcp.h
  enum {
     TCP_OPT_EOL         = 0,
     TCP_OPT_ADDR        = 254,
  };
  ... ...
  struct tcpopt_addr {
      uint8_t opcode;
      uint8_t opsize;
      __be16 port;
      uint8_t addr[16];
  } __attribute__((__packed__));
  ```

> In case of nat64, RS's codes need a few changes to get real client's IP/port. DPVS provide an example TCP server and a nginx patch for nat64 toa. Please refer to [example_nat64](../kmod/toa/example_nat64).

<a id="udp" />

### Does DPVS support UDP ? How to get the real IP/port of a UDP Client?

Yes, it does support UDP. In order to get the real client IP/port in FullNAT mode, you need to install UOA module on RS, and make a few code changes. UOA supports two modes: `opp` for private protocol mode, which supports IPv4/IPv6/Nat64, and `ipo` for ip option mode, which support IPv4 only. Please refer to [uoa.md](../kmod/uoa/uoa.md) and [udp_serv.c](../kmod/uoa/example/udp_serv.c).

> Which UOA mode should we choose? Honestly speaking, choose the one that works, because unlike TCP option, either IP option or private IP protocol is often restricted by network devices or policies. Thus consider your network environments and choose the best suitable one.

<a id="fragment" />

### Does DPVS support IP fragment ?

No, since connection table is per-lcore (per-CPU), and RSS/rte_flow are used for FNAT. Assuming RSS mode is TCP and rte_flow uses L4 info `<lip, lport>`. Considered that IP fragment doesn't have L4 info, it needs reassembling first and re-schedule the packet to **correct** lcore which the 5-tuple flow (connection) belongs to.

May be someday in the future, we will support "packet re-schedule" on lcores or use L3 (IP) info only for `RSS` or `flow control`, then we may support fragment. But even we support fragment, it may hurt the performance (reassemble, re-schedule effort) or security.

Actually, IPv4 fragment is not recommended, while IPv6 even not support fragment by fixed header, and do not allow re-fragment on middle-boxes. The applications, especially for the datagram-oriented apps, like UDP-apps, should perform PMTU discover algorithm to avoid fragment. TCP is sending sliced *segments*, notifying MSS to peer side and *PMTU discover* is built-in, TCP-app should not need worry about fragment.

<a id="vm" />

### How to launch DPVS on Virtual Machine ?

Please refer to the [tutorial.md](../doc/tutorial.md), there's an exmaple to run DPVS on `Ubuntu`. Basically, you may need to reduce memory usage. And for VM's NIC, `rte_flow` is not supported, so if you want to config FullNAT/SNAT mode, you have to configure **only one** worker (cpu), and another CPU core for master.

<a id="monitor" />

### How to monitor or get statistics of DPVS ?

You can use `ipvsadm` and `dpip` tools. For example,

```
$ ipvsadm -ln --stats
$ dpip -s link show
$ dpip -s link show cpu
```

For example, to get the throughput for each VIP/RS, you can use `ipvsadm -ln --stats`, and `ipvsadm -Z` to clear the statistics.

Note `--rate` option of `ipvsadm` is not supported.

It may need to write scripts to parse the outputs or integrated with your local admin-system.

<a id="support" />

### Where can I find supports if docs do not help?

If any question, please make sure you have read the [docs](../doc) first, and `LVS`'s [documents](https://github.com/alibaba/LVS/tree/master/docs) are also helpful. It's better to have some experience about networking configuration (e.g., routing, neigbour, ...) since DPVS is kernel-bypass, basic routing, IP address configurations are needed to be setup from scratch.

We have Chinese `QQ-Group` or `WeChat-Group`, you can ask questions, raise issues, talk about design, help others or discuss everything else about DPVS. Here's the [entry](https://github.com/iqiyi/dpvs/issues/147) for WeChar-Group (微信群) and [entry](https://github.com/iqiyi/dpvs/issues/83) for QQ-Group (QQ群). Emailing to `iig_cloud_qlb #at# qiyi #dot# com` is another way to contact us.

At last, remember, you can find answer of all kind of questions from the codes, DPVS is open-sourced :).

<a id="test" />

### How to test the performance of DPVS ?

We use `wrk` as HTTP client and `f-stack/nginx` as Real Server. When we testing the performance of DPVS, at least 6 physical machines are used as Client (`wrk`), and 4 physical machines for `f-stack/nginx`.

For the machine running `wrk`, IRQ affinity should be set to make sure all CPUs are used. You can find the scripts like `set_irq_affinity_ixgbe` from Internet.

To get the test result for QPS, please check the output of `wrk`. To calculate *Packet Per-Second* (`pps`), *Bytes Per-Second* (`bps`), you can use `ipvsadm -ln --stats` or `dpip -s link show`.

We have tested 10G NIC only, and the result shows DPVS can reach the line-speed of 10G NIC with small packets. We have not test 25G/40G/100G NIC yet. Although it's in plan.

The test result can be found in [README.md](../README.md). We have no chance to use professional instruments for test.

<a id="vir-dev" />

### Does DPVS support Bonding/VLAN/Tunnel ?

Yes. To use bonding device, please check [conf/dpvs.bond.conf.sample](../conf/dpvs.bond.conf.sample). To set up VLAN/Tunnel device, you can refer to [tutorial.md](./tutorial.md) or `dpip vlan help`.

<a id="config-dpvs" />

### How to configure DPVS ?

There're several ways:

* `/etc/dpvs.conf`

You can modify `dpvs.conf`, and refer to `conf/xxx.sample`. Some parameters are configurable during
 run-time (on-fly), while others are configurable in initialization stage only. Refer to [conf/dpvs.conf.items](../conf/dpvs.conf.items) for all available parameters and corresponding type, default value and supported value range. Please use `kill -SIGHUP <DPVS-PID>` to reload the former on-fly kind of parameters in `dpvs.conf`.

* `ipvsadm`, `keepalived`, `quagga`/`ospfd`/`bgpd`

You should read `LVS`'s documents for `ipvsadm`/`keepalived` first, and note `ipvsadm` and `keepalived` of `DPVS` are slightly different, please check [tutorial.md](./tutorial.md) for details. For the configuration about `quagga`/`zebra`/`ospfd`/`bgpd`, please refer to `quagga`'s documents.

* `dpip` tool

`dpip` tool is developed to configure DPVS "on-fly". It's like `ip` command of Linux `iproute2` suites.
It can be used to configure IP address, neighbour (arp), routes, DPDK devices (link), virtual-devices (vlan/tunnel), and traffic control (qsch/cls). And it's also helpful to get statistics. Please check [tutorial.md](./tutorial.md) and `dpip help` for details.

<a id="log" />

### Where can I find DPVS's log ? Is timestamp supported ?

DPVS's logging is using DPDK's `RTE_LOG`. By default, `syslogd` is used by DPDK `RTE_LOG`, so DPVS's log should be find in `/var/log/message`, with time-stamp printed. You may change `syslogd`'s configure as you like, for example change the log file path, or put different programs' log to different files, or limit the log file size, etc.

DPVS log file path and level can also be changed by `/etc/dpvs.conf`, if the path changed, it means no time-stamp, no `syslogd`'s feature.

<a id="sa-miss" />

### How to resolve `sa_miss` when using DPVS FullNAT mode?

Add more LIPs. Increase sapool's `pool_hash_size` config may also be helpful if RS count of a virtual server is greater than the count of LIPs. You can refer to [#72](https://github.com/iqiyi/dpvs/issues/72#issuecomment-354034017) for more details.

<a id="cpu-100" />

### Why CPU usages are 100% when running DPVS ?

It's normal, not issue. Since DPDK application is using busy-polling mode. Every CPU core configured to DPVS are 100% usage, including Master and Worker CPU cores.

<a id="iptables" />

### Does iptables conflict with DPVS ?

Yes, DPDK is kernel-bypass solution, all forwarding traffic in data plane do not get into the Linux Kernel, it means `iptables`(Netfilter) won't work for that kind of traffic.
