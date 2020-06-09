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
    if len(sys.argv) < 4:
        print "usage:"
        print "  python dpvs_fnat_twoarm.py  (local ips) vip:vport"
        print " (rs ips)   -t/-u (default -t) rr/wrr/sh/lc... (default rr)"
    '''params parser'''
    config_ip = sys.argv[1]
    vip_info  = sys.argv[2]
    rip_info  = sys.argv[3]
    if len(sys.argv) >= 5:
        serv_type = sys.argv[4] + " "
    else:
        serv_type = '-t '
    if len(sys.argv) == 6:
        sch = sys.argv[5]
    else:
        sch = 'rr'

    if not os.path.exists(ENV_FILE_DIR):
        os.mkdir(ENV_FILE_DIR)
    file_name = ENV_FILE_DIR + "/rollback_fnat_twoarm.sh"
    FILE_CONTENT = ""

    '''check dpvs + dpdk nic status'''
    s, r = commands.getstatusoutput("/root/dpvs/bin/dpip link show")
    if s != 0 or r.count('UP') < 2:
        file_writen(FILE_CONTENT, file_name)
        print "WRONG DPDK vitrual iface config!",r.count('UP')
        sys.exit(-1)

    '''set dpip route and address'''
    vip      = vip_info.split(":")[0]
    vip_port = vip_info.split(":")[1]
    #add VIP to WAN interface
    if os.system("/root/dpvs/bin/dpip addr add " + vip + "/32 dev dpdk1") !=0:
        file_writen(FILE_CONTENT, file_name)
        print "dpip addr add VIP failed!"
        sys.exit(-1)
    cmd0 = "/root/dpvs/bin/dpip addr del " + vip + "/32 dev dpdk1 \n"
    FILE_CONTENT = cmd0 + FILE_CONTENT
    #add route for WAN/LAN access
    rip_list = rip_info.split(",")
    ip_tmp   = rip_list[0].split(":")[0]
    ip_route = ""
    for i in range(3):
        ip_route = ip_route + ip_tmp.split(".")[i] + "."
    ip_route = ip_route + "0/24"
    if os.system("/root/dpvs/bin/dpip route add " + ip_route + " dev dpdk0") !=0:
        file_writen(FILE_CONTENT, file_name)
        print "dpip route add on dpdk0 failed!"
        sys.exit(-1)
    cmd0 = "/root/dpvs/bin/dpip route del " + ip_route + " dev dpdk0 \n"
    FILE_CONTENT = cmd0 + FILE_CONTENT

    ip_route = ""
    for i in range(3):
        ip_route = ip_route + vip.split(".")[i] + "."
    ip_route = ip_route + "0/24"
    if os.system("/root/dpvs/bin/dpip route add " + ip_route + " dev dpdk1") !=0:
        file_writen(FILE_CONTENT, file_name)
        print "dpip route add on dpdk1 failed!"
        sys.exit(-1)
    cmd0 = "/root/dpvs/bin/dpip route del " + ip_route + " dev dpdk1 \n"
    FILE_CONTENT = cmd0 + FILE_CONTENT
    #add service <VIP:vport> to forwarding
    if os.system("/root/dpvs/bin/ipvsadm -A " + serv_type + vip_info +
                                               " -s " + sch) !=0:
        file_writen(FILE_CONTENT, file_name)
        print "dpip service <vip:vport> add failed!"
        sys.exit(-1)
    cmd0 = "/root/dpvs/bin/ipvsadm -D " + serv_type + vip_info + "\n"
    FILE_CONTENT = cmd0 + FILE_CONTENT
    #add RSs for service, forwarding mode is FNAT (-b)
    for rip_item in rip_list:
        if sch == "wrr":
            rip      = rip_item.split(":")[0]
            rip_port = rip_item.split(":")[1]
            rip_wi   = rip_item.split(":")[2]
            if os.system("/root/dpvs/bin/ipvsadm -a " + serv_type + vip_info
                         + " -r " + rip + ":" + rip_port + " -w " + rip_wi + " -b") !=0:
                file_writen(FILE_CONTENT, file_name)
                print "add RS failed!"
                sys.exit(-1)
        else:
            rip      = rip_item.split(":")[0]
            rip_port = rip_item.split(":")[1]
            if os.system("/root/dpvs/bin/ipvsadm -a " + serv_type + vip_info
                         + " -r " + rip + ":" + rip_port + " -b") !=0:
                file_writen(FILE_CONTENT, file_name)
                print "add RS failed!"
                sys.exit(-1)
    #add at least one Local-IP (LIP) for FNAT on LAN interface
    ip_list = config_ip.split(",")
    for lip in ip_list:
        if lip.startswith(rip.split(".")[0]):
            if os.system("/root/dpvs/bin/ipvsadm --add-laddr -z " + lip + " "
                     + serv_type + vip_info + " -F dpdk0") !=0:
                file_writen(FILE_CONTENT, file_name)
                print "LIP add failed!"
                sys.exit(-1)
            cmd0 = ("/root/dpvs/bin/ipvsadm -Q -z " + lip + " " 
                     + serv_type + vip + ":" + vip_port + " -F dpdk0\n")
            FILE_CONTENT = cmd0 + FILE_CONTENT

    file_writen(FILE_CONTENT, file_name)
    print(CONFIG_PASS + "DPVS ")
