usage of DPVS RS service config script:
script filename: /root/dpvs-rs-files/dpvs_rs_setup.py
                                     dpvs_rs_run.py
                                     dpvs_tunrs_setup.py
                                     dpvs_natrs_setup.py
                                     dpvs_DR_rs_setup.py 
dpvs_rs_run.py:if RS 80 port is not available,start server program on 80 port
dpvs_rs_setup.py: for ordinary scene,config IP on Linux with ifconfig
dpvs_tunrs_setup.py:TUN mode,config IP,set up tunl iface,can expand for IPV6 further
dpvs_natrs_setup.py:NAT mode,config IP,add route to DPVS
dpvs_DR_rs_setup.py:DR mode,config IP,set ARP ignore,add vip to lo
Usage:
   python dpvs_rs_setup.py ip1,ip2(config ips) 
   python dpvs_tunrs_setup.py ip1,ip2(config ips) vip ip4/ip6
   python dpvs_natrs_setup.py ip1,ip2(config ips) route wan_ip
   python dpvs_DR_rs_setup.py ip1,ip2(config ips) vip 
   python dpvs_rs_run.py

#roback env
python cleanup.py (sh file generated during env setting)
