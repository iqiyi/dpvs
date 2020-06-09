#dpvs start#
#dependencies:dpvs + dpdk-dependencies(drivers/  kmod/  lib/  usertools/  x86_64-native-linuxapp-gcc/) 
A,start with DPDK only
python dpvs-setup-ctrl-bond.py v1.7.8 eth0,eth3 bond0
B,start with DPDK and bond,with one CPU to test NAT mode
python dpvs-setup-ctrl.py v1.7.8 eth0,eth3

#usage of DPVS test case:
1,one arm FNAT case:
script filename: /root/dpvs-dip-files/dpvs_fnat_onearm.py
Usage:
      python dpvs_fnat_onearm.py  ip1,ip2(ifconfig ips) vip:vport
      rip1:port:wi,rip2:port:wi(rs ips)   -t/-u(default -t) rr/wrr/sh/lc(default rr)
Sample:
    python dpvs_fnat_onearm.py "192.168.1.46" 192.168.1.250:80 "192.168.1.40:80:100,192.168.1.20:80:90" -t wrr
    python dpvs_fnat_onearm.py "192.168.1.43" 192.168.1.251:80 "192.168.1.40:80,192.168.1.20:80" -t
2,keepalived master and backup -- one arm FNAT case:
script filename: /root/dpvs-dip-files/keepalived_mback_onearm.py
Usage:
      python keepalived_mback_onearm.py  ip1,ip2(ifconfig ips) vip:vport
      rip1:port:wi,rip2:port:wi(rs ips)   1/0(master/backup) TCP/UDP,rr/wrr/sh/lc,FNAT/DR(default  TCP, rr, FNAT)
Sample:
      python keepalived_mback_onearm.py 192.168.2.46,192.168.2.48 192.168.2.254:80 192.168.2.81:80:100, 192.168.2.80:80:100 1    

3,keepalived SNAT -- one dpdk interface:
script filename: /root/dpvs-dip-files/keepalived_snat_onekni.py
Usage:
      python keepalived_snat_onekni.py "src-range"  wan_ip:weight gateway oif(default dpdk0) 
                  TCP/UDP/ALL,rr/wrr/sh/lc(default TCP,rr)
Sample:
      python keepalived_snat_onekni.py "192.168.20.47-192.168.20.48"  192.168.100.1:4 192.168.20.254/24 dpdk0

4,two arm FNAT case:
script filename: /root/dpvs-dip-files/dpvs_fnat_twoarm.py
Usage:
      python dpvs_fnat_twoarm.py  (local ips) vip:vport"
             (rs ips)   -t/-u (default -t) rr/wrr/sh/lc... (default rr)"
Sample:
      python dpvs_fnat_twoarm.py 192.168.5.47 192.168.6.250:80 192.168.5.61:80:100,192.168.5.60:80:100 -t

5,nat64 FNAT case:
script filename: /root/dpvs-dip-files/dpvs_nat64.py
Usage:
      python dpvs_nat64.py  (local ips) vip vport bits"
             (rs ips) route1,route2  -t/-u (default -t) rr/wrr/sh/lc... (default rr)"
Sample:
      python dpvs_fnat_twoarm.py  192.168.11.47 2001::6 80 128 192.168.11.48:80:100 2001::/64,192.168.11.0/24 -t

6,onearm DR case:
script filename: /root/dpvs-dip-files/dpvs_dr_onearm.py
Usage:
      python dpvs_dr_onearm.py  (LAN ips) vip:vport
             (rs ips)  -t/-u (default -t) rr/wrr/sh/lc... (default rr)"
Sample:
      python dpvs_dr_onearm.py 192.168.7.46/24 192.168.7.254:80 192.168.7.48


7,onearm TUN case:
script filename: /root/dpvs-dip-files/dpvs_tun_dpdkdef.py
Usage:
      python dpvs_tun_dpdkdef.py  (LAN ips) vip:vport
             (rs ips) dpdk-n WAN_IP  -t/-u (default -t) rr/wrr/sh/lc... (default rr)
Sample:
      python dpvs_tun_dpdkdef.py 192.168.9.46 192.168.9.234:80 192.168.8.60 dpdk1 192.168.8.46      

8,onearm NAT case:
script filename: /root/dpvs-dip-files/dpvs_nat_dpdkdef.py
Usage:
      python dpvs_nat_dpdkdef.py  (WAN/LAN ips) vip:vport
             (rs ips) dpdk-n  -t/-u (default -t) rr/wrr/sh/lc... (default rr)
Sample:
      python dpvs_nat_dpdkdef.py 192.168.11.48,192.168.10.48 192.168.11.214:80 192.168.10.60,192.168.10.61 bond0

#rollback env
python cleanup.py (rollbackXX.sh generated during case seting) 1
