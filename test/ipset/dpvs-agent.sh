#!/bin/env sh
#

## <<bitmap:ip,mac>>
curl -X PUT  http://127.0.0.1:8866/v2/ipset/ttt -H "Content-Type: application/json" -d '{"Type":"bitmap:ip,mac","Name":"ttt","CreationOptions":{"Family":"ipv4","Comment":true,"Range":"192.168.88.0/24"}}'
curl -X POST http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"bitmap:ip,mac","Name":"ttt","Entries":[{"Entry":"192.168.88.1,AA:bb:CC:11:22:33"},{"Entry":"192.168.88.100","Comment":"no mac","Options":{"Force":false}}]}'
curl -X GET  http://127.0.0.1:8866/v2/ipset/ttt | jq | more
curl -X POST  http://127.0.0.1:8866/v2/ipset/ttt/cell -H "Content-Type: application/json" -d '{"Type":"bitmap:ip,mac","Member":{"Entry":"192.168.88.1,AA:bb:CC:11:22:33"}}'
curl -X PUT http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"bitmap:ip,mac","Name":"ttt","Entries":[{"Entry":"192.168.88.100,AA:bb:CC:11:22:33"}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"bitmap:ip,mac","Name":"ttt","Entries":[{"Entry":"192.168.88.100","Options":{"Force":false}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt

## <<bitmap:port>>

curl -X PUT  http://127.0.0.1:8866/v2/ipset/ttt -H "Content-Type: application/json" -d '{"Type":"bitmap:port","Name":"ttt","CreationOptions":{"Comment":true,"Range":"10000-20000"}}'
curl -X POST http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"bitmap:port","Name":"ttt","Entries":[{"Entry":"tcp:10000-10002"},{"Entry":"tcp:10888","Comment":"single","Options":{"Force":false}}]}'
curl -X GET  http://127.0.0.1:8866/v2/ipset/ttt | jq | more
curl -X POST  http://127.0.0.1:8866/v2/ipset/ttt/cell -H "Content-Type: application/json" -d '{"Type":"bitmap:port","Member":{"Entry":"tcp:12222"}}'
curl -X PUT http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"bitmap:port","Name":"ttt","Entries":[{"Entry":"tcp:10000-10008"}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"bitmap:port","Name":"ttt","Entries":[{"Entry":"tcp:10003","Options":{"Force":false}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt

## <<hash:ip>>
curl -X PUT  http://127.0.0.1:8866/v2/ipset/ttt -H "Content-Type: application/json" -d '{"Type":"hash:ip","Name":"ttt","CreationOptions":{"Comment":true,"Family":"ipv4","HashSize": 128,"HashMaxElem": 10001}}'
curl -X POST http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:ip","Name":"ttt","Entries":[{"Entry":"192.168.88.100/30","Comment":"a cidr"},{"Entry":"10.64.68.1-10.64.68.3","Comment":"a range","Options":{"Force":false}}]}'
curl -X GET  http://127.0.0.1:8866/v2/ipset/ttt | jq | more
curl -X POST  http://127.0.0.1:8866/v2/ipset/ttt/cell -H "Content-Type: application/json" -d '{"Type":"hash:ip","Member":{"Entry":"192.168.88.100"}}'
curl -X PUT http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:ip","Name":"ttt","Entries":[{"Entry":"192.168.88.100/30","Comment":"a cidr"},{"Entry":"10.64.68.10-10.64.68.14","Comment":"a range","Options":{"Force":false}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:ip","Name":"ttt","Entries":[{"Entry":"192.168.88.100-192.168.88.128","Options":{"Force":false}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt

curl -X PUT  http://127.0.0.1:8866/v2/ipset/ttt -H "Content-Type: application/json" -d '{"Type":"hash:ip","Name":"ttt","CreationOptions":{"Comment":true,"Family":"ipv6","HashSize": 256,"HashMaxElem": 20001}}'
curl -X POST http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:ip","Name":"ttt","Entries":[{"Entry":"2001::B","Options":{"Force":false}}]}'
curl -X GET  http://127.0.0.1:8866/v2/ipset/ttt | jq | more
curl -X POST  http://127.0.0.1:8866/v2/ipset/ttt/cell -H "Content-Type: application/json" -d '{"Type":"hash:ip","Member":{"Entry":"2001::a"}}'
curl -X PUT http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:ip","Name":"ttt","Entries":[{"Entry":"2001::b","Comment":"replace","Options":{"Force":false}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:ip","Name":"ttt","Entries":[{"Entry":"2001::a","Options":{"Force":false}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt

## <<hash:net>>
curl -X PUT  http://127.0.0.1:8866/v2/ipset/ttt -H "Content-Type: application/json" -d '{"Type":"hash:net","Name":"ttt","CreationOptions":{"Comment":true,"Family":"ipv4"}}'
curl -X POST http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net","Name":"ttt","Entries":[{"Entry":"192.168.88.128/26","Comment":"net1"},{"Entry":"10.64.0.10-10.64.0.20","Comment":"a net range","Options":{"Force":false}}]}'
curl -X GET  http://127.0.0.1:8866/v2/ipset/ttt | jq | more
curl -X POST  http://127.0.0.1:8866/v2/ipset/ttt/cell -H "Content-Type: application/json" -d '{"Type":"hash:net","Member":{"Entry":"192.168.88.100"}}'
curl -X PUT http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net","Name":"ttt","Entries":[{"Entry":"192.168.88.128/26","Comment":"net1"},{"Entry":"192.168.88.164/30","Comment":"net1 nomatch","Options":{"NoMatch":true}},{"Entry":"10.64.0.10-10.64.0.20","Comment":"a net range","Options":{"Force":false}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net","Name":"ttt","Entries":[{"Entry":"192.168.88.192/28","Options":{"Force":false}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt

curl -X PUT  http://127.0.0.1:8866/v2/ipset/ttt -H "Content-Type: application/json" -d '{"Type":"hash:net","Name":"ttt","CreationOptions":{"Comment":true,"Family":"ipv6"}}'
curl -X POST http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net","Name":"ttt","Entries":[{"Entry":"2001::/64","Options":{"Force":false}}]}'
curl -X GET  http://127.0.0.1:8866/v2/ipset/ttt | jq | more
curl -X POST  http://127.0.0.1:8866/v2/ipset/ttt/cell -H "Content-Type: application/json" -d '{"Type":"hash:net","Member":{"Entry":"2001::66"}}'
curl -X PUT http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net","Name":"ttt","Entries":[{"Entry":"2002::/64","Comment":"replace","Options":{"Force":false}},{"Entry":"2002::ff:0:0/96","Comment":"net1 nomatch","Options":{"NoMatch":true}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net","Name":"ttt","Entries":[{"Entry":"2002::/64","Options":{"Force":false}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt

## <<hash:net,port>>
curl -X PUT  http://127.0.0.1:8866/v2/ipset/ttt -H "Content-Type: application/json" -d '{"Type":"hash:net,port","Name":"ttt","CreationOptions":{"Comment":true,"Family":"ipv4"}}'
curl -X POST http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net,port","Name":"ttt","Entries":[{"Entry":"192.168.88.0/24,tcp:8080","Comment":"net cidr"},{"Entry":"10.64.0.10-10.64.0.20","Comment":"net range","Options":{"Force":false}}]}'
curl -X GET  http://127.0.0.1:8866/v2/ipset/ttt | jq | more
curl -X POST  http://127.0.0.1:8866/v2/ipset/ttt/cell -H "Content-Type: application/json" -d '{"Type":"hash:net,port","Member":{"Entry":"192.168.88.100,tcp:8080"}}'
curl -X PUT http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net,port","Name":"ttt","Entries":[{"Entry":"192.168.88.128/26,udp:80-82","Comment":"net1"},{"Entry":"192.168.88.164/30,udp:80","Comment":"net1 nomatch","Options":{"NoMatch":true}},{"Entry":"10.64.0.10-10.64.0.20,tcp:6600","Comment":"a net range","Options":{"Force":false}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net,port","Name":"ttt","Entries":[{"Entry":"192.168.88.128/26,udp:81","Options":{"Force":false}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt

curl -X PUT  http://127.0.0.1:8866/v2/ipset/ttt -H "Content-Type: application/json" -d '{"Type":"hash:net,port","Name":"ttt","CreationOptions":{"Comment":true,"Family":"ipv6"}}'
curl -X POST http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net,port","Name":"ttt","Entries":[{"Entry":"2001::/64,tcp:8080-8083","Options":{"Force":false}}]}'
curl -X GET  http://127.0.0.1:8866/v2/ipset/ttt | jq | more
curl -X POST  http://127.0.0.1:8866/v2/ipset/ttt/cell -H "Content-Type: application/json" -d '{"Type":"hash:net,port","Member":{"Entry":"2001::66,tcp:8082"}}'
curl -X PUT http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net,port","Name":"ttt","Entries":[{"Entry":"2002::/64,udp:80-83","Comment":"replace","Options":{"Force":false}},{"Entry":"2002::ff:0:0/96,udp:80","Comment":"net1 nomatch","Options":{"NoMatch":true}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net,port","Name":"ttt","Entries":[{"Entry":"2002::/64,udp:82","Options":{"Force":false}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt

## <<hash:net,port,iface>>
curl -X PUT  http://127.0.0.1:8866/v2/ipset/ttt -H "Content-Type: application/json" -d '{"Type":"hash:net,port,iface","Name":"ttt","CreationOptions":{"Comment":true,"Family":"ipv4"}}'
curl -X POST http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net,port,iface","Name":"ttt","Entries":[{"Entry":"192.168.88.0/24,tcp:8080,dpdk0","Comment":"net cidr"},{"Entry":"10.64.0.10-10.64.0.20,tcp:80-82,dpdk0","Comment":"net range","Options":{"Force":false}}]}'
curl -X GET  http://127.0.0.1:8866/v2/ipset/ttt | jq | more
curl -X POST  http://127.0.0.1:8866/v2/ipset/ttt/cell -H "Content-Type: application/json" -d '{"Type":"hash:net,port,iface","Member":{"Entry":"192.168.88.100,tcp:8080,dpdk0"}}'
curl -X PUT http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net,port,iface","Name":"ttt","Entries":[{"Entry":"192.168.88.0/24,tcp:80-82,dpdk0","Comment":"net cidr"},{"Entry":"10.64.0.10-10.64.0.20,tcp:8080,dpdk0","Comment":"net range","Options":{"Force":false}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net,port,iface","Name":"ttt","Entries":[{"Entry":"192.168.88.0/24,tcp:81,dpdk0","Options":{"Force":false}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt

curl -X PUT  http://127.0.0.1:8866/v2/ipset/ttt -H "Content-Type: application/json" -d '{"Type":"hash:net,port,iface","Name":"ttt","CreationOptions":{"Comment":false,"Family":"ipv6"}}'
curl -X POST http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net,port,iface","Name":"ttt","Entries":[{"Entry":"2001::/64,tcp:8080-8083,dpdk0","Options":{"Force":false}},{"Entry":"2002::/64,udp:6600,dpdk0","Comment":"xxxxx","Options":{"Force":false}}]}'
curl -X GET  http://127.0.0.1:8866/v2/ipset/ttt | jq | more
curl -X POST  http://127.0.0.1:8866/v2/ipset/ttt/cell -H "Content-Type: application/json" -d '{"Type":"hash:net,port,iface","Member":{"Entry":"2001::66,tcp:8082,dpdk0"}}'
curl -X PUT http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net,port,iface","Name":"ttt","Entries":[{"Entry":"2002::/64,udp:80-83,dpdk0","Comment":"zzzzz","Options":{"Force":false}},{"Entry":"2002::ff:0:0/96,udp:80,dpdk0","Comment":"net1 nomatch","Options":{"NoMatch":true}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net,port,iface","Name":"ttt","Entries":[{"Entry":"2002::/64,udp:82,dpdk0","Options":{"Force":false}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt

## <<hash:ip,port,ip>>
curl -X PUT  http://127.0.0.1:8866/v2/ipset/ttt -H "Content-Type: application/json" -d '{"Type":"hash:ip,port,ip","Name":"ttt","CreationOptions":{"Comment":true,"Family":"ipv4"}}'
curl -X POST http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:ip,port,ip","Name":"ttt","Entries":[{"Entry":"192.168.1.16/31,tcp:8080-8081,192.168.2.100-192.168.2.102","Comment":"net-port-range"},{"Entry":"10.64.0.10-10.64.0.20,udp:6600,112.112.112.112","Comment":"udp","Options":{"Force":false}}]}'
curl -X GET  http://127.0.0.1:8866/v2/ipset/ttt | jq | more
curl -X POST  http://127.0.0.1:8866/v2/ipset/ttt/cell -H "Content-Type: application/json" -d '{"Type":"hash:ip,port,ip","Member":{"Entry":"192.168.1.17,tcp:8080,192.168.2.100"}}'
curl -X PUT http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:ip,port,ip","Name":"ttt","Entries":[{"Entry":"192.168.1.16/31,tcp:8080-8081,192.168.2.100-192.168.2.102","Comment":"net-port-range"},{"Entry":"10.64.88.0,udp:6600,112.112.112.112","Comment":"udp","Options":{"Force":false}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:ip,port,ip","Name":"ttt","Entries":[{"Entry":"192.1681.16/31,tcp:8081,192.168.2.101","Options":{"Force":false}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt

curl -X PUT  http://127.0.0.1:8866/v2/ipset/ttt -H "Content-Type: application/json" -d '{"Type":"hash:ip,port,ip","Name":"ttt","CreationOptions":{"Comment":false,"Family":"ipv6"}}'
curl -X POST http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:ip,port,ip","Name":"ttt","Entries":[{"Entry":"2001::4444,tcp:8080-8083,2002::7777","Options":{"Force":false}}]}'
curl -X GET  http://127.0.0.1:8866/v2/ipset/ttt | jq | more
curl -X POST  http://127.0.0.1:8866/v2/ipset/ttt/cell -H "Content-Type: application/json" -d '{"Type":"hash:ip,port,ip","Member":{"Entry":"2001::4444,tcp:8082,2002::7777"}}'
curl -X PUT http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:ip,port,ip","Name":"ttt","Entries":[{"Entry":"2002::aaaa,udp:80-83,2001::6666","Comment":"xxxxx","Options":{"Force":false}},{"Entry":"2002::ff:1,tcp:80,2001::ee:2","Comment":"net1 nomatch","Options":{"NoMatch":true}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:ip,port,ip","Name":"ttt","Entries":[{"Entry":"2002::aaaa,udp:82,2001::6666","Options":{"Force":false}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:ip,port,ip","Name":"ttt","Entries":[{"Entry":"2002::aaaa,udp:80-83,2001::6666","Comment":"xxxxx","Options":{"Force":true}},{"Entry":"2002::ff:1,tcp:80,2001::ee:2","Comment":"net1 nomatch","Options":{"NoMatch":true}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt

## <<hash:ip,port,net>>
curl -X PUT  http://127.0.0.1:8866/v2/ipset/ttt -H "Content-Type: application/json" -d '{"Type":"hash:ip,port,net","Name":"ttt"}'
curl -X POST http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:ip,port,net","Name":"ttt","Entries":[{"Entry":"192.168.1.5-192.168.1.6,tcp:8081-8082,192.168.88.0/24"},{"Entry":"10.64.100.100/30,udp:6600,10.64.200.0/24","Comment":"udp","Options":{"Force":false}}]}'
curl -X GET  http://127.0.0.1:8866/v2/ipset/ttt | jq | more
curl -X POST  http://127.0.0.1:8866/v2/ipset/ttt/cell -H "Content-Type: application/json" -d '{"Type":"hash:ip,port,net","Member":{"Entry":"192.168.1.6,tcp:8081,192.168.88.111"}}'
curl -X PUT http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:ip,port,net","Name":"ttt","Entries":[{"Entry":"192.168.1.4/30,80,192.168.88.0/24"},{"Entry":"10.64.100.100/30,udp:6688,10.64.100.0/24","Comment":"udp","Options":{"Force":false}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:ip,port,net","Name":"ttt","Entries":[{"Entry":"192.168.1.6/31,80,192.168.88.0/24"}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt

curl -X PUT  http://127.0.0.1:8866/v2/ipset/ttt -H "Content-Type: application/json" -d '{"Type":"hash:ip,port,net","Name":"ttt","CreationOptions":{"Comment":true,"Family":"ipv6","HashSize":64,"HashMaxElem":20000}}'
curl -X POST http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:ip,port,net","Name":"ttt","Entries":[{"Entry":"2001::1,tcp:8080-8083,2002::0/64"},{"Entry":"2001::1,tcp:8080,2002::FFFF:0/112","Options":{"NoMatch":true}}]}'
curl -X GET  http://127.0.0.1:8866/v2/ipset/ttt | jq | more
curl -X POST  http://127.0.0.1:8866/v2/ipset/ttt/cell -H "Content-Type: application/json" -d '{"Type":"hash:ip,port,net","Member":{"Entry":"2001::1,tcp:8082,2002::FFFF:1"}}'
curl -X PUT http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:ip,port,net","Name":"ttt","Entries":[{"Entry":"2001::1,tcp:8080-8083,2002::0/64"},{"Entry":"2001::1,tcp:8080,2001:FFFF::0/80","Comment":"replaced","Options":{"NoMatch":true}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:ip,port,net","Name":"ttt","Entries":[{"Entry":"2001::1,tcp:8080,2002::0/64"}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt

## <<hash:net,port,net>>
curl -X PUT  http://127.0.0.1:8866/v2/ipset/ttt -H "Content-Type: application/json" -d '{"Type":"hash:net,port,net","Name":"ttt"}'
curl -X POST http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net,port,net","Name":"ttt","Entries":[{"Entry":"192.168.1.0/24,tcp:8080-8083,192.168.2.0/24"},{"Entry":"10.64.96.0/21,udp:6600,10.132.80.0/21","Comment":"udp","Options":{"Force":false}}]}'
curl -X GET  http://127.0.0.1:8866/v2/ipset/ttt | jq | more
curl -X POST  http://127.0.0.1:8866/v2/ipset/ttt/cell -H "Content-Type: application/json" -d '{"Type":"hash:net,port,net","Member":{"Entry":"192.168.1.4,tcp:8080,192.168.2.254"}}'
curl -X PUT http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net,port,net","Name":"ttt","Entries":[{"Entry":"192.168.1.0/24,tcp:8080-8083,192.168.2.0/24"},{"Entry":"10.64.96.0/21,udp:6600,10.132.80.0/21","Comment":"udp","Options":{"Force":false}},{"Entry":"10.64.97.0/24,udp:6600,10.132.82.0/24","Comment":"udp","Options":{"NoMatch":true}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net,port,net","Name":"ttt","Entries":[{"Entry":"192.168.1.0/24,tcp:8082,192.168.2.0/24"}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt

curl -X PUT  http://127.0.0.1:8866/v2/ipset/ttt -H "Content-Type: application/json" -d '{"Type":"hash:net,port,net","Name":"ttt","CreationOptions":{"Comment":true,"Family":"ipv6"}}'
curl -X POST http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net,port,net","Name":"ttt","Entries":[{"Entry":"2001::/64,tcp:8080-8083,2002::0/64"},{"Entry":"2001::/120,tcp:8080,2002::FFFF:0/112","Options":{"NoMatch":true}}]}'
curl -X GET  http://127.0.0.1:8866/v2/ipset/ttt | jq | more
curl -X POST  http://127.0.0.1:8866/v2/ipset/ttt/cell -H "Content-Type: application/json" -d '{"Type":"hash:net,port,net","Member":{"Entry":"2001::1,tcp:8082,2002::FFFF:1"}}'
curl -X PUT http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net,port,net","Name":"ttt","Entries":[{"Entry":"2001::/64,tcp:8080-8083,2002::0/64"},{"Entry":"2001::/112,tcp:8080,2002::FFFF:0/112","Comment":"replaced","Options":{"NoMatch":true}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net,port,net","Name":"ttt","Entries":[{"Entry":"2001::/64,tcp:8081,2002::/64"}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt

## <<hash:net,port,net,port>>
curl -X PUT  http://127.0.0.1:8866/v2/ipset/ttt -H "Content-Type: application/json" -d '{"Type":"hash:net,port,net,port","Name":"ttt","CreationOptions":{"Comment":true}}'
curl -X POST http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net,port,net,port","Name":"ttt","Entries":[{"Entry":"192.168.1.0/24,tcp:8080-8083,192.168.2.0/24,tcp:12345"},{"Entry":"10.64.96.0/21,udp:53,10.132.80.0/21,udp:6600-6601","Comment":"udp","Options":{"Force":false}}]}'
curl -X GET  http://127.0.0.1:8866/v2/ipset/ttt | jq | more
curl -X POST  http://127.0.0.1:8866/v2/ipset/ttt/cell -H "Content-Type: application/json" -d '{"Type":"hash:net,port,net,port","Member":{"Entry":"192.168.1.4,tcp:8080,192.168.2.254,tcp:12345"}}'
curl -X PUT http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net,port,net,port","Name":"ttt","Entries":[{"Entry":"192.168.1.0/24,tcp:8080-8083,192.168.2.0/24,tcp:12345"},{"Entry":"10.64.96.0/21,udp:53,10.132.80.0/21,udp:6600-6601","Comment":"udp","Options":{"Force":false}},{"Entry":"10.64.96.0/24,udp:53,10.132.80.86/24,udp:6601","Comment":"add exceptions","Options":{"Nomatch":true}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net,port,net,port","Name":"ttt","Entries":[{"Entry":"10.64.96.0/21,udp:53,10.132.80.0/21,udp:6600-6601"}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt

curl -X PUT  http://127.0.0.1:8866/v2/ipset/ttt -H "Content-Type: application/json" -d '{"Type":"hash:net,port,net,port","Name":"ttt","CreationOptions":{"Family":"ipv6"}}'
curl -X POST http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net,port,net,port","Name":"ttt","Entries":[{"Entry":"2001::/64,tcp:8080-8083,2002::0/64,tcp:80","Options":{"Force":true}},{"Entry":"2001::/120,tcp:8080,2002::FFFF:0/112,tcp:80","Options":{"NoMatch":true,"Force":true}}]}'
curl -X GET  http://127.0.0.1:8866/v2/ipset/ttt | jq | more
curl -X POST  http://127.0.0.1:8866/v2/ipset/ttt/cell -H "Content-Type: application/json" -d '{"Type":"hash:net,port,net,port","Member":{"Entry":"2001::1,tcp:8082,2002::FFFF:1,tcp:80"}}'
curl -X PUT http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net,port,net,port","Name":"ttt","Entries":[{"Entry":"2001::/64,tcp:8080-8083,2002::0/64,tcp:80"},{"Entry":"2001::/112,tcp:8080,2002::FFFF:0/112,tcp:80","Comment":"replaced","Options":{"NoMatch":true}}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt/member -H "Content-Type: application/json" -d '{"Type":"hash:net,port,net,port","Name":"ttt","Entries":[{"Entry":"2001::/64,tcp:8082,2002::/64,tcp:80"}]}'
curl -X DELETE http://127.0.0.1:8866/v2/ipset/ttt
