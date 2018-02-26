DPVS TODO list
==============

Short-term
----------

* Get real client IP for UDP, like TCP TOA. [on-going]
* performance optimization for 25G/40G NIC.
* documents update.

Long-term
---------

* keepalive support SNAT config
* packet logging (log to mem first then dump to file in sep core)
* VM support
* non-numa support
* packet sampling
* ALG (ftp, sip, ...)
* VxLAN Support
* NIC without Flow-Director (fdir)
  - packet redirect for cpus.
  - rss pre-calcuate.
* UDP fragment support
* IPv6 Support

Done
----

* merge DPDK-17.05.2 [done]
* basic traffic control [done]
* neighbour (ARP) refactor [done]
* Tunnel Interface (gre/ipip) [done]
* NAT/Tunnel forwarding mode [done]
* consistent hashing [done]
