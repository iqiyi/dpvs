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
        print "python dpvs_cli_run.py ip:port "
    ip_info    = sys.argv[1]
    '''ping & curl test'''
    r = requests.get("http://" + ip_info + "/")
    if r.status_code != 200:
        print "curl test vip:vport service failed!"
        sys.exit(-1)

    cmd = "ping -c 10 " + ip_info.split(":")[0] 
    s, r = commands.getstatusoutput(cmd)
    if s != 0:
        print "default route config failed!"
        sys.exit(-1)
    print(CONFIG_PASS + "client ") 
