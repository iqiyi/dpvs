#coding=utf-8
import os
import sys
import commands
import fcntl
import socket
import struct
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
    '''client ifconfig & stress test'''
    if len(sys.argv) < 2:
        print "usage:"
        print "python dpvs_snat_cli_setup.py route ip(defaul "")"
    route_info = sys.argv[1]
    '''find iface to config ip --- iface to ssh login'''
    try:
        import netifaces
    except Exception,err:
        if os.system("pip install netifaces || easy_install netifaces") != 0:
            print "netifaces module install failed!"
            sys.exit(-1)
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
    file_name = ENV_FILE_DIR + "/rollback_client_snat.sh"
    FILE_CONTENT = ""
    file_writen(FILE_CONTENT, file_name)
    cmd = "ip route add default via " + route_info + " dev " + iface
    s, r = commands.getstatusoutput(cmd)
    if s != 0 and r.find("File exists") == -1:
        print "default route config failed!"
        sys.exit(-1)
    elif s != 0 and r.find("File exists") != -1:
        "find existing route and del to add new"
        ss, rr = commands.getstatusoutput("route -n")
        for rline in rr.split("\n"):
            if(rline.split()[0] == "0.0.0.0"):
                if os.system("ip route del default via " + rline.split()[1]  + " dev " + iface) != 0:
                    print "default route config failed!"
                    sys.exit(-1)
                else:
                    cmd0 = "ip route add default via " + rline.split()[1]  + " dev " + iface + "\n"
                    FILE_CONTENT = cmd0 + FILE_CONTENT
                    if os.system(cmd) != 0:
                        file_writen(FILE_CONTENT, file_name)
                        print "default route config failed!"
                        sys.exit(-1)

    cmd0 = "ip route del default via " + route_info + " dev " + iface + "\n"
    FILE_CONTENT = cmd0 + FILE_CONTENT

    if len(sys.argv) >=3:
        num = 0
        ip_info = sys.argv[2]
        ip_list = ip_info.split(",")
        for ip in ip_list:
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

    file_writen(FILE_CONTENT, file_name)
    print(CONFIG_PASS + "client " + res) 
