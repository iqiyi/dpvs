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
    '''server ifconfig & service running'''
    if len(sys.argv) < 4:
        print "usage:"
        print "  python dpvs_tunrs_setup.py ip1,...,ipn vip ip4/ip6"
    config_ip = sys.argv[1]
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
    file_name = ENV_FILE_DIR + "/rollback_tunrs.sh"
    FILE_CONTENT = "#!/usr/bin/sh \n"
    num = 0
    for ip in ip_list:
        '''sample: ifconfig eth2:0 192.168.1.40'''
        if ip.find(":") == -1:
            cmd = "ifconfig " + iface + ":" + str(num) + " " + ip
            s, r = commands.getstatusoutput(cmd)
            if s != 0:
                file_writen(FILE_CONTENT, file_name)
                print "ip config failed!"
                sys.exit(-1)
            cmd0 = "ifconfig " + iface + ":" + str(num) + " down\n"
            FILE_CONTENT = cmd0 + FILE_CONTENT
            num = num + 1
        else:
            cmd = "ifconfig " + iface + " inet6 add " + ip
            s, r = commands.getstatusoutput(cmd)
            if s != 0:
                file_writen(FILE_CONTENT, file_name)
                print "ip6 config failed!"
                sys.exit(-1)
            cmd0 = "ifconfig " + iface + " inet6 del " + ip + " \n"
            FILE_CONTENT = cmd0 + FILE_CONTENT

    vip = sys.argv[2]
    inet = sys.argv[3]
    if inet == "ip4":
        cmd = "ifconfig tunl0 " + vip + " netmask 255.255.255.255 broadcast " + vip + " up"
        if os.system(cmd) != 0:
            file_writen(FILE_CONTENT, file_name)
            print "tunl0 config failed!"
            sys.exit(-1)
        cmd0 = "modprobe -r ipip \n"
        FILE_CONTENT = cmd0 + FILE_CONTENT
        cmd = "sysctl -w net.ipv4.conf.tunl0.arp_ignore=1"
        if os.system(cmd) != 0:
            file_writen(FILE_CONTENT, file_name)
            print "ignore ARP config failed!"
            sys.exit(-1)
        cmd = "sysctl -w net.ipv4.conf.tunl0.rp_filter=2"
        if os.system(cmd) != 0:
            file_writen(FILE_CONTENT, file_name)
            print "loose source validation config failed!"
            sys.exit(-1)

    file_writen(FILE_CONTENT, file_name)
    print(CONFIG_PASS + "server " + res) 
