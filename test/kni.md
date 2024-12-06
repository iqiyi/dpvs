KNI Performance Test
-----

We tested KNI's performance with `iperf`, a network throughput tool. Read/Write performances of TCP/UDP were evaluated.

```sh
# TCP Server (the read end)
iperf -s -l 128K -i 1
# TCP Client (the write end)
iperf -c [server-address] -e -t 30

# UDP Server (the read end)
iperf -u -s -i 1
# UDP Client (the write end)
iperf -u -c [server-address] -b 10g -e -t 30
```

In the tests, we tried to send as much traffic as possible with `iperf` and observe how much of it was processed by KNI. The tests ran on two servers equipped with 10G NIC and Centos7.6 system, one for DPVS, another for the peer endpoint of iperf traffic. All test traffic
was directed to kni port, either by not configuring any address and route in DPVS, or by adding rte_flow rules to dedicated kni address.

For contrasts, 5 groups of tests were done:
* linux network port <-> linux network port
* linux network port <-> rte_kni port
* linux network port <-> rte_kni port with dedicated rx/tx queue and DPVS worker
* linux network port <-> virtio-user port
* linux network port <-> virtio-user port with dedicaated rx/tx queue and DPVS worker

The reults are shown in table below.

|                   | TCP 读/Gbps | TCP 写/Gbps | TCP 读/pps | TCP 写/pps | UDP 读/Gbps | UDP 写/Gbps | UDP 读/pps | UDP 写/pps |
| ----------------- | ----------- | ----------- | ---------- | ---------- | ----------- | ----------- | ---------- | ---------- |
| linux             | 9.47        | 9.46        | 25273      | 18450      | 4.63        | 4.89        | 485582     | 455772     |
| rte_kni           | 4.88        | 4.19        | 432654     | 431132     | 4.98        | 4.58        | 425568     | 426773     |
| rte_kni(flow)     | 8.91        | 4.59        | 810006     | 410579     | 5.48        | 5.46        | 486336     | 563660     |
| virtio-user       | 2.61        | 3.04        | 237117     | 260832     | 2.48        | 3.98        | 212642     | 330968     |
| virtio-user(flow) | 2.65        | 3.67        | 240067     | 327227     | 2.47        | 4.66        | 212652     | 407891     |

>Note:
 Following the DPDK technical board decision and refinement, the KNI kernel module, library and PMD has been removed since the DPDK 23.11 release.
 Refer to [ABI and API Deprecation (DPDK 22.11)](https://doc.dpdk.org/guides-22.11/rel_notes/deprecation.html).
