Checklist
=========

> notes:
> * [x]: test passed
> * [ ]: not support or untested

* [x] PPv2 + FNAT44 + TCP
* [x] PPv2 + FNAT44 + TCP + Synproxy
* [x] PPv2 + FNAT44 + UDP
* [x] PPv1 + FNAT44 + TCP
* [x] PPv1 + FNAT44 + TCP + Synproxy
* [x] standalone PPv2 + FNAT44 + TCP 
* [x] standalone PPv2 + FNAT44 + TCP
* [x] standalone PPv2 + FNAT44 + UDP
* [x] standalone PPv1 + FNAT44 + TCP
* [x] standalone PPv1 + FNAT44 + TCP

* [x] PPv2 + FNAT64 + TCP
* [x] PPv2 + FNAT64 + TCP + Synproxy
* [x] PPv2 + FNAT64 + UDP
* [x] PPv1 + FNAT64 + TCP
* [x] PPv1 + FNAT64 + TCP + Synproxy
* [x] standalone PPv2 + FNAT64 + TCP
* [x] standalone PPv2 + FNAT64 + TCP + Synproxy
* [x] standalone PPv2 + FNAT64 + UDP
* [x] standalone PPv1 + FNAT64 + TCP
* [x] standalone PPv1 + FNAT64 + TCP + Synproxy

* [x] PPv2 + FNAT66 + TCP
* [x] PPv2 + FNAT66 + TCP + Synproxy
* [x] PPv2 + FNAT66 + UDP
* [x] PPv1 + FNAT66 + TCP
* [x] PPv1 + FNAT66 + TCP + Synproxy
* [x] standalone PPv2 + FNAT66 + TCP 
* [x] standalone PPv2 + FNAT66 + TCP + Synproxy
* [x] standalone PPv2 + FNAT66 + UDP
* [x] standalone PPv1 + FNAT66 + TCP
* [x] standalone PPv1 + FNAT66 + TCP + Synproxy

* [x] tools/keepalived HTTP_CHECKER + IPv4 backends
* [x] tools/keepalived UDP_CHECKER with payload + IPv4 backends
* [x] tools/keepalived HTTP_CHECKER + IPv6 backends
* [x] tools/eepalived UDP_CHECKER with payload + IPv6 backends
* [x] tools/healthcheck http_checker + IPv4 backends
* [x] tools/healthcheck tcp_checker with payload + IPv4 backends
* [x] tools/healthcheck udp_checker with payload + IPv4 backends
* [x] tools/healthcheck udpping_checker with payload + IPv4 backends
* [x] tools/healthcheck http_checker + IPv6 backends
* [x] tools/healthcheck tcp_checker with payload + IPv6 backends
* [x] tools/healthcheck udp_checker with payload + IPv6 backends
* [x] tools/healthcheck udpping_checker with payload + IPv6 backends
* [x] tools/ipvsadm "--proxy-protocol" config option
* [x] tools/keepalived "proxy-protocol" config keyword (v1|v2|disable)
* [ ] tools/dpvs-agent proxy-protocol service config api: NOT SUPPORT

* [x] client with PPv2 data + FNAT44 + TCP + PPv2 backends (lb cascading)
* [x] client with PPv1 data + FNAT44 + TCP + PPv1 backends (lb cascading)
* [x] client with PPv2 data + FNAT44 + UDP + PPv2 backends (lb cascading)
* [x] client with PPv2 data + FNAT44 + TCP + PPv1 backends (lb cascading)
* [x] client with PPv1 data + FNAT44 + TCP + PPv2 backends (lb cascading)

* [x] client with PPv2 data + FNAT66 + TCP + PPv2 backends (lb cascading)
* [x] client with PPv1 data + FNAT66 + TCP + PPv1 backends (lb cascading)
* [x] client with PPv2 data + FNAT66 + UDP + PPv2 backends (lb cascading)
* [x] client with PPv2 data + FNAT66 + TCP + PPv1 backends (lb cascading)
* [x] client with PPv1 data + FNAT66 + TCP + PPv2 backends (lb cascading)

* [x] client with PPv2 data + FNAT64 + TCP + PPv2 backends (lb cascading)
* [x] client with PPv1 data + FNAT64 + TCP + PPv1 backends (lb cascading)
* [x] client with PPv2 data + FNAT64 + UDP + PPv2 backends (lb cascading)
* [x] client with PPv2 data + FNAT64 + TCP + PPv1 backends (lb cascading)
* [x] client with PPv1 data + FNAT64 + TCP + PPv2 backends (lb cascading)

* [x] client with PPv2 data + FNAT44 + TCP + standalone PPv2 backends (lb cascading)
* [x] client with PPv1 data + FNAT44 + TCP + standalone PPv1 backends (lb cascading)
* [x] client with PPv2 data + FNAT44 + UDP + standalone PPv2 backends (lb cascading)
* [x] client with PPv2 data + FNAT44 + TCP + standalone PPv1 backends (lb cascading)
* [x] client with PPv1 data + FNAT44 + TCP + standalone PPv2 backends (lb cascading): zero-length duplicated ack may appear

* [x] client with PPv2 data + FNAT66 + TCP + standalone PPv2 backends (lb cascading)
* [x] client with PPv1 data + FNAT66 + TCP + standalone PPv1 backends (lb cascading)
* [x] client with PPv2 data + FNAT66 + UDP + standalone PPv2 backends (lb cascading)
* [x] client with PPv2 data + FNAT66 + TCP + standalone PPv1 backends (lb cascading)
* [x] client with PPv1 data + FNAT66 + TCP + standalone PPv2 backends (lb cascading): zero-length duplicated ack may appear

* [x] client with PPv2 data + FNAT64 + TCP + standalone PPv2 backends (lb cascading)
* [x] client with PPv1 data + FNAT64 + TCP + standalone PPv1 backends (lb cascading)
* [x] client with PPv2 data + FNAT64 + UDP + standalone PPv2 backends (lb cascading)
* [x] client with PPv2 data + FNAT64 + TCP + standalone PPv1 backends (lb cascading)
* [x] client with PPv1 data + FNAT64 + TCP + standalone PPv2 backends (lb cascading): zero-length duplicated ack may appear

