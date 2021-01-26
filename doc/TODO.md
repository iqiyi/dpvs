DPVS TODO list
==============

* [x] IPv6 Support
* [x] Documents update
* [ ] NIC without Flow-Director (FDIR)
  - [x] Packet redirect to workers
  - [ ] RSS pre-calcuating
* [x] Merge DPDK stable 18.11
* [ ] Merge DPDK stable 20.11
* [ ] Service whitelist ACL
* [ ] SNAT ACL
* [x] Refactor Keepalived (porting latest stable keepalived)
* [x] Packet Capture and Tcpdump Support
* [ ] Logging
    - [ ] Packet based logging
    - [ ] Session based logging (creation, expire, statistics)
* [ ] CI, Test Automation Setup
* [ ] Performance Optimization
    - [x] CPU Performance Tuning
    - [x] Memory Performance Tuning
    - [ ] Numa-aware NIC
    - [ ] Minimal Running Resource
    - [x] KNI performance Tuning
    - [ ] Multi-core Performance Tuning
    - [ ] TC performance Tuning
* [x] 25G/40G NIC Supports
* [ ] VxLAN Support
* [ ] IPv6 Tunnel Device 
* [x] VM Support
* [ ] IP Fragment Support, for UDP APPs
* [ ] Session Sharing
* [ ] ALG (ftp, sip, ...)
