DPVS TODO list
==============

* [x] IPv6 Support
* [x] Documents update
* [ ] NIC without Flow-Director (FDIR)
  - [x] Packet redirect to workers
  - [ ] RSS pre-calcuating
  - [ ] Replace fdir with Generic Flow(rte_flow)
* [x] Merge DPDK stable 18.11
* [ ] Merge DPDK stable 20.11
* [x] Service whitelist ACL
* [ ] IPset Support
  - [ ] SNAT ACL with IPset
  - [ ] TC policing with IPset
* [x] Refactor Keepalived (porting latest stable keepalived)
* [ ] Keepalived stability test and optimization.
* [x] Packet Capture and Tcpdump Support
* [ ] Logging
    - [ ] Packet based logging
    - [ ] Session based logging (creation, expire, statistics)
* [x] CI, Test Automation Setup
* [ ] Performance Optimization
    - [ ] Performance test tools and docs
    - [x] CPU Performance Tuning
    - [x] Memory Performance Tuning
    - [ ] Numa-aware NIC
    - [ ] Minimal Running Resource
    - [x] KNI performance Tuning
    - [ ] Multi-core Performance Tuning
    - [x] TC performance Tuning
* [x] 25G/40G NIC Supports
* [ ] VxLAN Support
* [ ] IPv6 Tunnel Device 
* [x] VM Support
* [ ] IP Fragment Support, for UDP APPs
* [ ] Session Sharing
* [ ] ALG (ftp, sip, ...)
