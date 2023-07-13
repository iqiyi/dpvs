Demo: Setup a DPVS Virtual Service
------

> This is a demo to setup a miminal fullnat virtual service with dpvs-agent API. Not all supported APIs are involved. We haven't document the dpvs-agent API yet. Refer to [dpvs-agent openapi definition](./dpvs-agent-api.yaml) for a full view of supported API.

The demo shows how to setup the service from scratch with dpvs-agent API.

```
[root@dpvs-devel 17:53:46 dpvs-agent]# ipvsadm -ln
IP Virtual Server version 1.9.5 (size=0)
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port           Forward Weight ActiveConn InActConn
TCP  192.168.88.100:80 wrr
  -> 192.168.88.30:80             FullNat 101    0          0
[root@dpvs-devel 17:53:54 dpvs-agent]# ipvsadm -G
VIP:VPORT            TOTAL    SNAT_IP              CONFLICTS  CONNS
192.168.88.100:80    1
                              192.168.88.241       0          0
[root@dpvs-devel 17:53:56 dpvs-agent]# dpip addr show -s
inet 192.168.88.100/32 scope global dpdk0.102
     valid_lft forever preferred_lft forever
inet 192.168.88.28/24 scope global dpdk0.102
     valid_lft forever preferred_lft forever
inet 192.168.88.241/32 scope global dpdk0.102
     valid_lft forever preferred_lft forever sa_used 0 sa_free 1032176 sa_miss 0
[root@dpvs-devel 17:53:59 dpvs-agent]# ip addr show dev dpdk0.102.kni
172: dpdk0.102.kni: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 24:6e:96:75:7c:fa brd ff:ff:ff:ff:ff:ff
    inet 192.168.88.128/24 brd 192.168.88.255 scope global dpdk0.102.kni
       valid_lft forever preferred_lft forever
    inet 192.168.88.100/32 scope global dpdk0.102.kni
       valid_lft forever preferred_lft forever
    inet6 fe80::266e:96ff:fe75:7cfa/64 scope link
       valid_lft forever preferred_lft forever
```

- Create a vlan device (dpip vlan add dpdk0.102 link dpdk0 id 102)

```sh
curl -X PUT "http://127.0.0.1:53225/v2/device/dpdk0.102/vlan" -H "Content-type:application/json" -d "{\"device\":\"dpdk0\", \"id\":\"102\"}"
```

- Set kni device up (ip link set dpdk0.102.kni up)

```sh
curl -X PUT "http://127.0.0.1:53225/v2/device/dpdk0.102.kni/netlink"
```

- Config host IP for dpdk0.102 (dpip addr add 192.168.88.28/24 dev dpdk0.102)

```sh
curl -X PUT "http://127.0.0.1:53225/v2/device/dpdk0.102/addr" -H "Content-type:application/json" -d "{\"addr\":\"192.168.88.28/24\"}"
```

- Config host IP for dpdk0.102.kni (dpip addr add 192.168.88.128/24 dev dpdk0.102.kni)

```sh
curl -X PUT "http://127.0.0.1:53225/v2/device/dpdk0.102.kni/netlink/addr" -H "Content-type:application/json" -d "{\"addr\":\"192.168.88.128/24\"}"
```

- Config kni route for host IP of dpdk0.102.kni (dpip route add 192.168.88.128/32 dev dpdk.102 scope kni_host)

```sh
curl -X PUT "http://127.0.0.1:53225/v2/device/dpdk0.102/route" -H "Content-type:application/json" -d "{\"dst\":\"192.168.88.128\", \"scope\":\"kni_host\"}"
```

- Add a virtual service (ipvsadm -At 192.168.88.100:80 -s wrr)

```sh
curl -X PUT "http://127.0.0.1:53225/v2/vs/192.168.88.100-80-tcp" -H "Content-type:application/json" -d "{\"SchedName\":\"wrr\"}"
```

- Add vip onto dpdk0.102 (dpip addr add 192.168.88.100 dev dpdk0.102)

```sh
curl -X PUT "http://127.0.0.1:53225/v2/device/dpdk0.102/addr" -H "Content-type:application/json" -d "{\"addr\":\"192.168.88.100\"}"
```

- Add vip onto dpdk0.102.kni (ip addr add 192.168.88.100 dev dpdk0.102.kni)

```sh
curl -X PUT "http://127.0.0.1:53225/v2/device/dpdk0.102.kni/netlink/addr" -H "Content-type:application/json" -d "{\"addr\":\"192.168.88.100\"}"
```
- Set laddr for the service (ipvsadm --add-laddr -z  192.168.88.241  -t 192.168.88.100:80 -F dpdk0.102)

```sh
curl -X PUT "http://127.0.0.1:53225/v2/vs/192.168.88.100-80-tcp/laddr" -H "Content-type:application/json" -d "{\"device\":\"dpdk0.102\", \"addr\":\"192.168.88.241\"}"
```

- Add laddr onto dpdk0.102 (dpip addr add 192.168.88.241/32 dev dpdk0.102)

```sh
curl -X PUT "http://127.0.0.1:53225/v2/device/dpdk0.102/addr?sapool=true" -H "Content-type:application/json" -d "{\"addr\":\"192.168.88.241\"}"
```

- Add backend server(s) to the service (ipvsadm -at 192.168.88.100:80 -r 192.168.88.30:80 -w 101 -b)

```sh
curl -X PUT "http://127.0.0.1:53225/v2/vs/192.168.88.100-80-tcp/rs" -H "Content-type:application/json" -d "{\"Items\":[{\"ip\":\"192.168.88.30\", \"port\":80, \"weight\":101}]}"
```

Finally, deploy a http service on backend server `192.168.88.30:80`, and make a request to virtual service `192.168.88.100:80` from another server in this network. Hopefully, you may get a success response.
