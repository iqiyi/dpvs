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

def file_writen(FILE_CONTENT, file_name):
    try:
        fd = file(file_name, "w")
        fcntl.flock(fd, fcntl.LOCK_EX)
        fd.write(FILE_CONTENT)
        fd.close()
    except Exception,err:
        return {"status":False, "detail":err}
    finally:
        return {"status":True, "detail":"writen content to file SUCCEED"}         

if __name__ == '__main__':
    '''client ifconfig & stress test'''
    if len(sys.argv) < 2:
        print "usage:"
        print "python dpvs_cli_run.py vip:vport 1/0(default 0:donnot conduct stress test)"
    vip_info = sys.argv[1]
    '''stress test flag get''' 
    if len(sys.argv) == 3:
        str_flag = sys.argv[2]
        if str_flag == "0":
            stress = False
        else:
            stress = True
    else:
        stress = False

    '''whether conduct stress test'''
    if not stress:
        r = requests.get("http://" + vip_info + "/")
        if r.status_code != 200:
            print "test vip:vport service failed!"
            sys.exit(-1)
    else:
        '''stress test'''
        req_total = 0
        for i in range(2):
            s, r = commands.getstatusoutput("/root/wrk -c 1000 -d 30 -t 48 http://" + vip_info + "/")
            if s != 0:
                print "wrk stress test conduct failed!"
                sys.exit(-1)
            for line in r.split("\n"):
                if line.find("requests in") == -1:
                    continue
                req_total = req_total + long(line.split()[0])
                break
        QPS = "QPS:" + str(req_total /60.0 /1024) + "Kreq/s \n"
        fname = ENV_FILE_DIR + "/stress_test.txt"
        file_writen(QPS, fname)
        print QPS

    print(CONFIG_PASS + "client ") 
