DPVS Frequently Asked Questions (FAQ)
=============

### Contents

* [Fail to launch DPVS ?](#launch)
* [Is my NIC support DPVS ?](#nic)
* [How to achieve high availability ? How to upgrade DPVS ?](#high-avail)
* [Is DPVS support TOA, which TOA version is used?](#toa)
* [Is DPVS support UDP ? How to get UDP Client Real IP/port ?](#udp)
* [Is DPVS support IP fragment ?](#fragment)
* [How to launch DPVS on Virtual Machine ?](#vm)
* [How to monitor or get statistics of DPVS ?](#monitor)
* [Where can I found the support ?](#support)
* [How to test the performance of DPVS ?](#test)
* [How to resolve sa_miss when using DPVS FullNAT mode ?](#sa-miss)
* [Where can I find DPVS's log ? Is timestamp supported ?](#log)
* [Is DPVS support Bonding/VLAN/Tunnel ?](#vir-dev)
* [Why CPU usages are 100% when running DPVS ?](#cpu-100)
* [Is iptables conflict with DPVS ?](#iptables)

-------------------------------------------------

<a id="launch" />

### Fail to launch DPVS ?

Pls try follow `README.md` and `doc/tutorial.md` first. And if still have problem, possible reasons are,

1. NIC do not support DPDK or *flow-director* (`fdir`), pls check this [answer](#nic).
2. DPDK not compatible with Kernel Version, it cause build error, pls refer [DPDK.org](https://www.dpdk.org/) or consider upgrade the Kernel.
3. CPU core (`lcore`) and NIC queue's configure is miss-match.
   Pls read `conf/*.sample`, note worker-CPU/NIC-queue are 1:1 mapping and you need one more cpu for master.
4. DPDK NIC's link is not up ? pls check NIC cable first.
5. `curl` VIP in FullNAT mode fails (or sometime fails)? Pls check if NIC support [fdir](#nic).
6. `curl` still fails. Pls check route and arp by `dpip route show`, `dpip neigh show`.
6. The patchs in `patch/` are not applied.

And you may find other similar issues and solutions from Github's issues list.

<a id="nic" />

### Is my NIC support DPVS ?

Actaully, it's the question about if the NIC support DPDK as well as "flow-director (fdir)".

First, pls make sure the NIC support `DPDK`, you can check the [link](https://core.dpdk.org/supported/). Second, DPVS's FullNAT/SNAT mode need flow-director feature, *unless you configure only one worker*. For `fdir` support, this [link](http://doc.dpdk.org/guides/nics/overview.html#id1) can be checked.

Pls found the DPDK driver name according to your NIC by the first link. And check `fdir` support  for each drivers from the matrix in second link.

1. https://core.dpdk.org/supported/
2. http://doc.dpdk.org/guides/nics/overview.html#id1


<a id="high-avail" />

### How to achieve high availability ? How to upgrade DPVS ?

Like `LVS`, DPVS should be deployed in **ECMP** *Cluster Mode*. If one director went down, others still keep working, new connections are not affected. When using *Cluster Mode* (for both one-arm and two arms), `keeplived` can still be used for VIP (LIP) configuration and RS health check purpose. Note the `keeplived`'s VIP *backup (`VRRP`)* feature is not used.

When upgrade directors (`DPVS`), we can "stop" `ospfd`, upgrade it, and start `ospfd` again. Yes, some existing connection may broken, however, applications may have fail-over (re-try) mechanism.

To address the issue director crash or getting upgraded, some implementation introduce *session sharing/sync* between directors. Honestly, this is not easy, because,

1. LIPs are not same for each DPVS director.
2. connection-table is per-lcore, when sync-ed to another DPVS, how to handle per-lcore table in another machine?
3. "Session-Sharing" works well for "long-connection" but not "short-connection", since the connection's creation/destruction are too frequently to be sync-ed to other directors.

As I know, some L4 LB implemented "session sharing" or "session synchronization", they are configuring same LIPs for each LB director. And each LIP is confgured for one CPU core. Both cases are quite different for DPVS implementation and deployment.

On the other hand, for the high availability of Real Servers, DPVS leverage `keepalived` for health check on RS, both TCP/UDP services can be checked, you can also write your own checking scripts. For more info about health-check, pls refer `LVS`'s document.

<a id="toa" />

### Is DPVS support `TOA`, which `TOA` version is used?

Yes, and we use same `toa` version as [alibaba/LVS](https://github.com/alibaba/LVS). It's open-sourced, to fetch Real Server `toa.ko` module, pls check [#issue-70](https://github.com/iqiyi/dpvs/issues/70).
DPVS side TOA format is defined in `include/ipvs/proto_tcp.h`, while option code is `254`, option length is 8.

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
     uint16_t port;
     uint32_t addr;
  } __attribute__((__packed__));
  ```

<a id="udp" />

### Is DPVS support UDP ? How to get UDP Client Real IP/port ?

Yes, it do support UDP. In order to get real client IP/port in FullNAT mode, you need install UOA module on RS, and do a little code change. Pls refer `uoa/uoa.md` and `uoa/example/udp_serv.c`.

<a id="fragment" />

### Is DPVS support IP fragment ?

No, since connection table is per-lcore (per-CPU), and RSS/fdir are used for FNAT. By default RSS mode is TCP and fdir also use L4 info `<lip, lport>`. Consider IP fragment do not have L4 info, it need reassemble first and re-schedule the pkt to **correct** lcore, which the 5-tuple flow (connection) belongs to.

May be someday in the future, we will support "pkt re-schedule" on lcores or use L3 (IP) info only for `RSS`/`FDIR`, then we may support fragment. But even we support fragment, it may hurt the performance (reassemble, re-schedule effort) or security.

Actually, IPv4 fragment is not recommended, while IPv6 even not support fragment by fixed header, and do not allow re-fragment on middle-boxes. The applications, especially for the datagram-oriented apps, like UDP-apps, should perform PMTU discover algorithm to avoid fragment. TCP is sending sliced *segments*, notifying MSS to peer side and *PMTU discover* is built-in, TCP-app should not need worry about fragment.

<a id="vm" />

### How to launch DPVS on Virtual Machine ?

Pls refer the `doc/tutorial.md`, there's an exmaple to run DPVS on `Ubuntu`. Basically, you may need to reduce memory usage. And for VM's NIC, `fdir` is not supported, so if you want to config FullNAT/SNAT mode, you have to configure **only one** worker (cpu), and another CPU core for master.

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

### Where can I found the support ? if doc not helps.

If any question, pls make sure you have read the `doc/` first, and `LVS`'s [documents](https://github.com/alibaba/LVS/tree/master/docs) are also helpful. It's the better to have some experience about networking configuration (e.g., routing, neigbour, ...) since DPVS is kernel-bypass, basic routing, IP address configurations are needed to be setup from scratch.

We have Chinese `QQ-Group` or `WeChat-Group`, you can ask questions, raise issues, talk about design, help others or discuss everything else about DPVS. Here's the [entry](https://github.com/iqiyi/dpvs/issues/147) for WeChar-Group (微信群) and [entry](https://github.com/iqiyi/dpvs/issues/83) for QQ-Group (QQ群). Email to `qlb-devel #at# qiyi #dot# com` is another way.

At last, remember, you can find answer of all kind of questions from the codes, DPVS is open-sourced :).

<a id="test" />

### How to test the performance of DPVS ?

We use `wrk` as HTTP client and `f-stack/nginx` as Real Server. When we testing the performance of DPVS, at least 6 physical machines are used as Client (`wrk`), and 4 physical machines for `f-stack/nginx`.

For the machine running `wrk`, IRQ affinity should be set to make sure all CPUs are used. You can find the scripts like `set_irq_affinity_ixgbe` from Internet.

To get the test result for QPS, pls check the output of `wrk`. To calculate *Packet Per-Second* (`pps`), *Bytes Per-Second* (`bps`), you can use `ipvsadm -ln --stats` or `dpip -s link show`.

We have tested 10G NIC only, and the result shows DPVS can reach the line-speed of 10G NIC with small packets. We have not test 25G/40G/100G NIC yet. Although it's in plan.

The test result can be found in `README.md`. We have no chance to use professional instruments for test.

<a id="vir-dev" />

### Is DPVS support Bonding/VLAN/Tunnel ?

Yes. To use bonding device, pls check `conf/dpvs.bond.conf.sample`. To set up VLAN/Tunnel device, you can refer `tutorial.md` or `dpip vlan help`.

<a id="config-dpvs" />

### How to configure DPVS ?

There're several ways:

* `/etc/dpvs.conf`

You can modify `dpvs.conf`, and refer `conf/xxx.sample`. Some parameters are configurable during
 run-time (on-fly), while others are configurable in initialization stage only. Refer to `conf/dpvs.conf.items` for all available parameters and corresponding type, default value and supported value range. Pls use `kill -SIGHUP <DPVS-PID>` to reload the former on-fly kind of parameters in `dpvs.conf`.

* `ipvsadm`, `keepalived`, `quagga`/`ospfd`/`bgpd`

You should read `LVS`'s documents for `ipvsadm`/`keepalived` first, and note DPVS's version `ipvsadm`/`keepalived` are slightly different, pls check `tutorial.md` for details. For the configuration about `quagga`/`zebra`/`ospfd`/`bgpd`, pls refer `quagga`'s documents.

* `dpip` tool

`dpip` tool is developed to configure DPVS "on-fly". It's like `ip` command of Linux `iproute2` suites.
It can be used to configure IP address, neighbour (arp), routes, DPDK devices (link), virtual-devices (vlan/tunnel), and traffic control (qsch/cls). And it's also helpful to get statistics. Pls check `tutorial.md` and `dpip help` for details.

<a id="log" />

### Where can I find DPVS's log ? Is timestamp supported ?

DPVS's logging is using DPDK's `RTE_LOG`. By default, `syslogd` is used by DPDK `RTE_LOG`, so DPVS's log should be find in `/var/log/message`, with time-stamp printed. You may change `syslogd`'s configure as you like, for example change the log file path, or put different programs' log to different files, or limit the log file size, etc.

DPVS log file path and level can also be changed by `/etc/dpvs.conf`, if the path changed, it means no time-stamp, no `syslogd`'s feature.

<a id="sa-miss" />

### How to resolve `sa_miss` when using DPVS FullNAT mode?

Add more LIPs. Can refer to [#72](https://github.com/iqiyi/dpvs/issues/72#issuecomment-354034017) for details.

<a id="cpu-100" />

### Why CPU usages are 100% when running DPVS ?

It's normal, not issue. Since DPDK application is using busy-polling mode. Every CPU core configured to DPVS are 100% usage, including Master and Worker CPU cores.

<a id="iptables" />

### Is iptables conflict with DPVS ?

Yes, DPDK is kernel-bypass solution, all forwarding traffic in data plane do not get into the Linux Kernel, it means `iptables`(Netfilter) won't work for that kind of traffic.
