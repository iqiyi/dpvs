#!/usr/bin/python
#coding=utf-8
import os
import sys
import commands
import fcntl
import socket
import struct
import netifaces
import argparse
import requests
#-------------constant strings used----------------#
ENV_FILE_DIR     = "/root/old_env"
CONFIG_PASS      = "CONFIGED SUCCEED for "

def get_ip_addr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,
            struct.pack('256s', ifname[:15]))[20:24])

def file_writen(FILE_CONTENT, file_name):
    '''rollback script writing'''
    try:
        fd = file(file_name, "w")
        fcntl.flock(fd, fcntl.LOCK_EX)
        fd.write(FILE_CONTENT)
        fd.close()
    except Exception,err:
        return {"status":False, "detail":err}
    finally:
        return {"status":True, "detail":"writen rb_script SUCCEED"}         

if __name__ == '__main__':
    '''director dpip route set + ip ifconfig'''
    if len(sys.argv) < 7:
        print "usage:"
        print "  python dpvs_nat64.py  (local ips) vip vport bits"
        print " (rs ips) route1,route2  -t/-u (default -t) rr/wrr/sh/lc... (default rr)"
    '''params parser'''
    config_ip   = sys.argv[1]
    vip         = sys.argv[2]
    vport       = sys.argv[3]
    vip_bits    = sys.argv[4]
    rip_info    = sys.argv[5]
    route_info  = sys.argv[6]
    if len(sys.argv) >= 8:
        serv_type = sys.argv[7] + " "
    else:
        serv_type = '-t '
    if len(sys.argv) == 9:
        sch = sys.argv[8]
    else:
        sch = 'rr'

    if not os.path.exists(ENV_FILE_DIR):
        os.mkdir(ENV_FILE_DIR)
    file_name = ENV_FILE_DIR + "/rollback_nat64.sh"
    FILE_CONTENT = "#!/usr/bin/sh \n"

    '''check dpvs + dpdk nic status'''
    s, r = commands.getstatusoutput("/root/dpvs/bin/dpip link show")
    if s != 0 or r.count('UP') < 2:
        file_writen(FILE_CONTENT, file_name)
        print "WRONG DPDK vitrual iface config!",r.count('UP')
        sys.exit(-1)

    '''set dpip route and address'''
    ipvsadm_add_server = "/root/dpvs/bin/ipvsadm -a "
    ipvsadm_add_laddr = "/root/dpvs/bin/ipvsadm --add-laddr -z "
    ipvsadm_del_laddr = "/root/dpvs/bin/ipvsadm -Q -z "
    ipvsadm_add_vip = "/root/dpvs/bin/ipvsadm -A "
    ipvsadm_del_vip = "/root/dpvs/bin/ipvsadm -D "
    dpip_del_route6 = "/root/dpvs/bin/dpip route -6 del "
    dpip_add_route6 = "/root/dpvs/bin/dpip route -6 add "
    dpip_del_route = "/root/dpvs/bin/dpip route del "
    dpip_add_route = "/root/dpvs/bin/dpip route add "
    dpip_del_addr = "/root/dpvs/bin/dpip addr del "
    dpip_add_addr = "/root/dpvs/bin/dpip addr add "
    #add VIP to WAN interface
    if os.system(dpip_add_addr + vip + "/" + vip_bits + " dev dpdk1") !=0:
        file_writen(FILE_CONTENT, file_name)
        print "dpip addr add VIP failed!"
        sys.exit(-1)
    cmd0 = dpip_del_addr + vip + "/" + vip_bits + " dev dpdk1 \n"
    FILE_CONTENT = cmd0 + FILE_CONTENT
    #add route for WAN/LAN access
    routes = route_info.split(",")
    for route in routes:
        if route.find(":") == -1:
            if os.system(dpip_add_route + route + " dev dpdk0") !=0:
                file_writen(FILE_CONTENT, file_name)
                print "dpip route add on dpdk0 failed!"
                sys.exit(-1)
            cmd0 = dpip_del_route + route + " dev dpdk0 \n"
            FILE_CONTENT = cmd0 + FILE_CONTENT
        else:
            if os.system(dpip_add_route6 + route + " dev dpdk1") !=0:
                file_writen(FILE_CONTENT, file_name)
                print "dpip IPV6 route add on dpdk1 failed!"
                sys.exit(-1)
            cmd0 = dpip_del_route6 + route + " dev dpdk1 \n"
            FILE_CONTENT = cmd0 + FILE_CONTENT
    #add service <VIP:vport> to forwarding
    if os.system(ipvsadm_add_vip + serv_type + "[" + vip + "]:"
                    + vport + " -s " + sch) !=0:
        file_writen(FILE_CONTENT, file_name)
        print "dpip service <vip:vport> add failed!"
        sys.exit(-1)
    cmd0 = ipvsadm_del_vip + serv_type + "[" + vip + "]:" + vport + "\n"
    FILE_CONTENT = cmd0 + FILE_CONTENT
    #add RSs for service, forwarding mode is FNAT (-b)
    rip_list = rip_info.split(",")
    for rip_item in rip_list:
        rip      = rip_item.split(":")[0]
        rip_port = rip_item.split(":")[1]
        rip_wi   = rip_item.split(":")[2]
        if os.system(ipvsadm_add_server + serv_type + "["+vip+"]:" + vport
                      + " -r " + rip + ":" + rip_port + " -w " + rip_wi + " -b") !=0:
            file_writen(FILE_CONTENT, file_name)
            print "add RS failed!"
            sys.exit(-1)
    #add at least one Local-IP (LIP) for FNAT on LAN interface
    ip_list = config_ip.split(",")
    for lip in ip_list:
        if os.system(ipvsadm_add_laddr + lip + " "
            + serv_type + "["+vip+"]:" + vport + " -F dpdk0") !=0:
            file_writen(FILE_CONTENT, file_name)
            print "LIP add failed!"
            sys.exit(-1)
        cmd0 = (ipvsadm_del_laddr + lip + " " 
                 + serv_type + "["+vip+"]:" + vport + " -F dpdk0\n")
        FILE_CONTENT = cmd0 + FILE_CONTENT

    file_writen(FILE_CONTENT, file_name)
    print(CONFIG_PASS + "DPVS ")
