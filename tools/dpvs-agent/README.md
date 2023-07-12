##setup a dpvs virtual service

- set dpdk device (dpip vlan add dpdk0.102 link dpdk0 id 102)
```
curl -X PUT "http://127.0.0.1:53225/v2/device/dpdk0.102/vlan" -H "Content-type:application/json" -d "{\"device\":\"dpdk0\", \"id\":\"102\"}"
```

- set linux device up (ip link set dpdk0.102.kni up)
```
curl -X PUT "http://127.0.0.1:53225/v2/device/dpdk0.102.kni/netlink"
```
- add virtual service (ipvsadm -At 192.168.177.130:80 -s wrr)
```
curl -X PUT "http://127.0.0.1:53225/v2/vs/192.168.177.130-80-tcp" -H "Content-type:application/json" -d "{\"SchedName\":\"wrr\"}"
```

- add vip to dpdk device (dpip addr add 192.168.77.130 dev dpdk0.102)
```
curl -X PUT "http://127.0.0.1:53225/v2/device/dpdk0.102/addr" -H "Content-type:application/json" -d "{\"addr\":\"192.168.177.130\"}"
```

- add vip to kni device (ip addr add 192.168.177.130 dev dpdk0.102.kni)
```
curl -X PUT "http://127.0.0.1:53225/v2/device/dpdk0.102.kni/netlink/addr" -H "Content-type:application/json" -d "{\"addr\":\"192.168.177.130\"}"

- set laddr of service (ipvsadm --add-laddr -z  192.168.188.247  -t 192.168.177.130:80 -F dpdk0.102)
```
curl -X PUT "http://127.0.0.1:53225/v2/vs/192.168.177.130-80-tcp/laddr" -H "Content-type:application/json" -d "{\"device\":\"dpdk0.102\", \"addr\":\"192.168.188.247\"}"
```
- set laddr to device (dpip addr add 192.168.188.247/32 dev dpdk0.102)
```
curl -X PUT "http://127.0.0.1:53225/v2/device/dpdk0.102/addr?sapool=true" -H "Content-type:application/json" -d "{\"addr\":\"192.168.188.247\"}"
```

- add rss to service  (ipvsadm -at 192.168.177.130:80 -r 192.168.188.101:80 -b)
```
curl -X PUT "http://127.0.0.1:53225/v2/vs/192.168.177.130-80-tcp/rs" -H "Content-type:application/json" -d "{\"Items\":[{\"ip\":\"192.168.188.101\", \"port\":80, \"weight\":101}]}"
```
