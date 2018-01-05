DPVS TODO list
==============

Short-term
----------

* merge DPDK-17.05.2 [done]
* basic traffic control [done]
* neighbour (ARP) refactor [done]
* Tunnel Interface (gre/ipip) [on-going]
* NAT/Tunnel forwarding mode [on-going]
* Get real client IP for UDP, like TCP TOA. [on-going]
* performance optimization for 25G/40G NIC.
* documents update.

Long-term
---------

* packet sampling
* consistent hashing
* ALG (ftp, sip, ...)
* VxLAN Support
* NIC without Flow-Director (fdir)
  - packet redirect for cpus.
  - rss pre-calcuate.
* IPv6 Support
