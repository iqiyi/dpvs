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
    if len(sys.argv) < 4:
        print "usage:"
        print "  python dpvs_fnat_onearm.py  (ifconfig ips) vip:vport"
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

    ip_list = config_ip.split(",")
    '''find iface to config ip --- iface to ssh login'''
    s, ifaces = commands.getstatusoutput("ls /sys/class/net")
    for iface in ifaces.split("\n"):
        if iface == 'lo' or iface.find('eth') == -1:
            continue
        try:
            res = get_ip_addr(iface)
        except:
            continue
        if res.startswith("10.") :
            break
    '''config ips'''
    if not os.path.exists(ENV_FILE_DIR):
        os.mkdir(ENV_FILE_DIR)
    file_name = ENV_FILE_DIR + "/rollback_fnat_onearm.sh"
    FILE_CONTENT = "#!/usr/bin/sh \n"
    num = 0
    for ip in ip_list:
        '''sample: ifconfig eth2:0 192.168.1.40'''
        cmd = "ifconfig " + iface + ":" + str(num) + " " + ip
        s, r = commands.getstatusoutput(cmd)
        if s != 0:
            file_writen(FILE_CONTENT, file_name)
            print "DPVS: linux ip config failed!"
            sys.exit(-1)
        cmd0 = "ifconfig " + iface + ":" + str(num) + " down\n"
        FILE_CONTENT = cmd0 + FILE_CONTENT
        num = num + 1
    '''check dpvs + dpdk nic status'''
    s, r = commands.getstatusoutput("/root/dpvs/bin/dpip link show | grep dpdk")
    if s != 0 or len(r.split("\n")) < 1 :
        file_writen(FILE_CONTENT, file_name)
        print "WRONG DPDK vitrual iface config!"
        sys.exit(-1)
    '''set dpip route and address'''
    vip      = vip_info.split(":")[0]
    vip_port = vip_info.split(":")[1]
    #add VIP to WAN interface
    if os.system("/root/dpvs/bin/dpip addr add " + vip + "/32 dev dpdk0") !=0:
        file_writen(FILE_CONTENT, file_name)
        print "dpip addr add VIP failed!"
        sys.exit(-1)
    cmd0 = "/root/dpvs/bin/dpip addr del " + vip + "/32 dev dpdk0 \n"
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
        print "dpip route add failed!"
        sys.exit(-1)
    cmd0 = "/root/dpvs/bin/dpip route del " + ip_route + " dev dpdk0 \n"
    FILE_CONTENT = cmd0 + FILE_CONTENT
    #add service <VIP:vport> to forwarding
    if os.system("/root/dpvs/bin/ipvsadm -A " + serv_type + vip + ":"
                 + vip_port + " -s " + sch) !=0:
        file_writen(FILE_CONTENT, file_name)
        print "dpip service <vip:vport> add failed!"
        sys.exit(-1)
    cmd0 = "/root/dpvs/bin/ipvsadm -D " + serv_type + vip + ":" + vip_port + "\n"
    FILE_CONTENT = cmd0 + FILE_CONTENT
    #add RSs for service, forwarding mode is FNAT (-b)
    for rip_item in rip_list:
        if sch == "wrr":
            rip      = rip_item.split(":")[0]
            rip_port = rip_item.split(":")[1]
            rip_wi   = rip_item.split(":")[2]
            if os.system("/root/dpvs/bin/ipvsadm -a " + serv_type + vip + ":" + vip_port
                         + " -r " + rip + ":" + rip_port + " -w " + rip_wi + " -b") !=0:
                file_writen(FILE_CONTENT, file_name)
                print "add RS failed!"
                sys.exit(-1)
        else:
            rip      = rip_item.split(":")[0]
            rip_port = rip_item.split(":")[1]
            if os.system("/root/dpvs/bin/ipvsadm -a " + serv_type + vip + ":" + vip_port
                         + " -r " + rip + ":" + rip_port + " -b") !=0:
                file_writen(FILE_CONTENT, file_name)
                print "add RS failed!"
                sys.exit(-1)
    #add at least one Local-IP (LIP) for FNAT on LAN interface
    if os.system("/root/dpvs/bin/ipvsadm --add-laddr -z " + ip_list[0] + " "
             + serv_type + vip + ":" + vip_port + " -F dpdk0") !=0:
        file_writen(FILE_CONTENT, file_name)
        print "LIP add failed!"
        sys.exit(-1)
    cmd0 = ("/root/dpvs/bin/ipvsadm -Q -z " + ip_list[0] + " " 
             + serv_type + vip + ":" + vip_port + " -F dpdk0\n")
    FILE_CONTENT = cmd0 + FILE_CONTENT

    file_writen(FILE_CONTENT, file_name)
    print(CONFIG_PASS + "DPVS " + res)
