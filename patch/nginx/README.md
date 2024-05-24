Nginx Patches for DPVS
-----

The directory is arranged to place nginx patch files for DPVS. More specifically, it contains the following patches.

* TOA patch for originating client IP/port derived from DPVS NAT64 translation
* UOA patch for originating client IP/port derived from DPVS UDP FNAT/NAT64 translation in QUIC/HTTP3
* QUIC Server Connection ID patch for connection migration

## TOA NAT64

Nginx can get the originating client IP address and Port NAT64'ed by DPVS by utilizing nginx variables 'toa_remote_addr' and 'toa_remote_port' respectively. It works when and only when the TOA kernel module has already installed successfully on the nginx server.

This is an exampe configuration of nginx with TOA patch for NAT64.

```
http {
    include       mime.types;
    default_type  application/octet-stream;

    log_format nat64 '$remote_addr $toa_remote_addr :$toa_remote_port - $remote_user [$time_local] '
        '"$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for" '
        '$request_length $upstream_response_time $upstream_addr';

    access_log  logs/access.log nat64;

    # more other configs ......

}
```

## UOA QUIC/HTTP3

Nginx can get the originating client IP address and Port NAT'ed by DPVS by utilizing nginx variables 'uoa_remote_addr' and 'uoa_remote_port' respectively. Both IPv4-IPv4 and IPv6-IPv6 NAT and NAT64(IPv6-IPv4 NAT) as well are supported. It works when and only when the UOA kernel module has already installed sucessfully on the nginx server.

This is an exampe configuration of nginx with UOA patch.

```
http {
    include       mime.types;
    default_type  application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] '
        '"$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http3" '
        '"$http_x_forwarded_for" $request_length $upstream_response_time $upstream_addr';

    log_format quic '$remote_addr $uoa_remote_addr :$uoa_remote_port - $remote_user [$time_local] '
        '"$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http3" '
        '"$http_x_forwarded_for" $request_length $upstream_response_time $upstream_addr';

    access_log  logs/access.log main;

    # more other configs ......


    server {
        listen 443 quic reuseport;
        listen 443 ssl;

        server_name qlb-test.qiyi.domain;

        access_log  logs/quic.access.log  quic;

        ssl_certificate     certs/cert.pem;
        ssl_certificate_key certs/key.pem;

        location / {
            add_header Alt-Svc 'h3=":2443"; ma=86400';
            root   html;
            index  index.html index.htm;
        }
    }
}
```

##  Quic Server Connection ID

It requires changes to Quic Server Connection ID(SCID) both in DPVS and Nginx to support the feature of QUIC connection migration. DPVS depends on Server IP/Port information encoded in SCID to schedule a migrating connection to the right nginx server where the previous connection resides, and Nginx relies on the socket cookie compiled in SCID to make a migrating connection be processed on the same listening socket as the previous one. Note that eBPF (bpf_sk_select_reuseport) is used in Nginx for QUIC connection migration, which requires Linux 5.7+.

The patch adds Nginx server address information into SCID, and fixes its collision problem with Nginx's socket cookie. The server address contains 24 least significant bits(LSB) for IPv4, and 32 LSB for IPv6, and compliant with DPVS DCID format specification defined in [ipvs/quic.h](../../include/ipvs/quic.h). The server port is not included in SCID.
