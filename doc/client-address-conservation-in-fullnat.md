Client Address Conservation in Fullnat
---

The original client addresses are substituted with DPVS's local addresses in Fullnat forwarding mode so that auxiliary means is required to pass them to realservers. Three solutions have been developed in DPVS for the problem -- *TOA*, *UOA*, and *Proxy Protocol*, with each having its own pros and cons. The document is to elaborate on them.

* **TOA**

Client address is encapsulated in a private TCP option (opcode 254) by DPVS, and parsed into the connected TCP socket on realserver by a kernel module named [toa.ko](../kmod/toa/). By default, it requires no changes in realserver application programs for fnat44, fnat66. But an extra syscall to `getsockopt` with parameters `IPPROTO_IP` and `TOA_SO_GET_LOOKUP` is required for fnat64 to retrieve the original IPv6 client address from toa.

* **UOA**

UOA is the counterpart in UDP protocol. It supports two modes: *IP Option Mode* (ipo) and *Private Protocol Mode* (opp). Client address is encapsulated into a private IPv4 option (opcode 31) in ipo mode, and into a private layer4 protocol named "option protocol" (protocol number 248) in opp mode respectively. Similarly, a kernel module name [uoa.ko](../kmod/uoa/) is required to parse the original client address from raw packets on realserver. Realserver application programs should use `getsockopt` with parameters `IPPROTO_IP` and `UOA_SO_GET_LOOKUP` immediately after user data reception to retrieve the original address from uoa. Note that not all kinds of network switches or routers support private IPv4 options or layer4 private protocols. Be aware of your network restrictions before using UOA.

* **Proxy Protocol**:
 
[Proxy Protocol](https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt) is a widely-used protocol for client address conservation on reverse proxies. It's been drafted by haproxy.org and supported two versions up to now. The version v1 is a human-readable format which supports TCP only, while version v2 is a binary format supporting both TCP and UDP. DPVS implements both versions and users can choose which one to use on basis of a per-service configuration. Moreover, if configured to the insecure mode, DPVS allows for clients that have already carried proxy protocol data, which is often the case when DPVS's virtual IP is behind of other reverse proxies such as nginx, envoy, or another DPVS, where DPVS doesn't insert client address by itself, but just retains the client address encapsulated in the packet, and makes protocol version translation if necessary. Proxy protocol has advantages of broad and uniform supports for layer3 and layer4 protocols(including IP, IPv6, TCP, UDP), both source and destination addresses conveying, no dependency on kernel modules, tolerance of network infrastructure differences. The client addresses are encapsulated into the very begginning position of layer4 payload. Application programs on realservers must receive the data and parse it to obtain the original client addresses immediately on establishment of TCP/UDP connection. Otherwise, the client address data may be taken as application data by mistake, resulting in unexpected behavior in the application program. Fortunately, parsing the client address from proxy protocol is quite straightforward, and a variety of well-known proxy servers have supported it. Actually, proxy protocol is becoming a defato standard in this area.

Next ,let's compare the three client address conservation solutions in detail in the following two tables.

The first table below lists the forwarding modes (FNAT44/FNAT66/FNAT64) and L4 protocols (TCP/UDP) supported by different solutions.

|        | toa  | uoa (ipo) | uoa (opp) | proxy protocol  (v1)  | proxy protocol (v2)   |
| ------ | ---- | --------- | --------- | --------------------- | --------------------- |
| FNAT44 | √    | √         | √         | √                     | √                     |
| FNAT66 | √    | ×         | √         | √                     | √                     |
| FNAT64 | √    | ×         | √         | √                     | √                     |
| TCP    | √    | ×         | ×         | √                     | √                     |
| UDP    | ×    | √         | √         | ×                     | √                     |

The second table details differences among toa, uoa and proxy protocol from aspects of functional features, configuraitons, application adaption and examples.

|                                         | toa                                                          | uoa (ipo mode)                          | uoa (opp mode)                          | proxy protocol (v1 & v2)                                   |
| --------------------------------------- | ------------------------------------------------------------ | --------------------------------------- | --------------------------------------- | ---------------------------------------------------------- |
| configuration switch                    | always on                                                    | global, default off                     | global, default on                      | per-service, toa/uoa mutal exclusive                       |
| where client address resides            | tcp option                                                   | ipv4 option                             | private ip protocol                     | tcp/udp beginnig payload                                   |
| standardization                         | private standard                                             | private implementation                  | private implementation                  | defacto standard                                           |
| application intrusiveness               | transparent                                                  | transparent (only fnat44 supported)     | transparent when uoa.ko installed       | intrusive                                                  |
| client address resolution intrusiveness | transparent for fnat44/fnat66; intrusive for fnat64          | intrusive                               | intrusive                               | intrusive                                                  |
| client source address resolution        | support                                                      | support                                 | support                                 | support                                                    |
| client destination address resolution   | not support                                                  | not support                             | not support                             | support                                                    |
| kernel module requirement on realserver | toa.ko, not compulsory when client addresses aren't concerned | uoa.ko                                 | uoa.ko                                  | no kernel module required                                  |
| load balancer cascading                 | not support                                                  | not support                             | not support                             | support                                                    |
| retransmission                          | support                                                      | fixed times, default 3                  | fixed times, default 3                  | support for tcp, not support for udp                       |
| underlay network supports               | good                                                         | bad                                     | medium                                  | good                                                       |
| client address loss cases               | when no enough tcp option room in first ack seg              | general udp packet loss                 | general udp packet loss                 | no loss for tcp, general udp packet loss for udp           |
| well-known application supports         | -                                                            | -                                       | -                                       | haproxy, nginx, envoy, ...                                 |
| intrusive application server examples   | [fnat64](../kmod/toa/example_nat64/server.c)                 | [udp_serv](../kmod/uoa/example/udp_serv.c) | [udp_serv](../kmod/uoa/example/udp_serv.c) | [tcp_server](../test/proxy_protocol/tcp_server.c),   [udp_server](../test/proxy_protocol/udp_server.c), [official sample code](https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt) |
