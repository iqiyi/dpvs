#!/usr/bin/python
#coding=utf-8
import os
import sys
import commands
import fcntl
import requests
import re
#-------------constant strings used----------------#
ENV_FILE_DIR     = "/root/old_env"
CONFIG_PASS      = "CONFIGED SUCCEED for "

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
    if len(sys.argv) < 2:
        print "usage:"
        print "  python statis.py  vip:vport -t/-u(default -t)"
    '''params parser'''
    vip_info  = sys.argv[1]
    if len(sys.argv) > 2:
        conn_type = sys.argv[2] + " "
    else:
        conn_type = "-t " 
    '''find iface to config ip --- iface to ssh login'''
    s, r = commands.getstatusoutput("/root/dpvs/bin/ipvsadm -ln " + conn_type + vip_info + " --stats")
    CPS = ""
    BPS = ""
    PPS = ""
    for line in r.split("\n"):
        if line.find(vip_info) == -1:
            continue
        info = line.split()
        if info[2].isdigit():
            CPS = str(long(info[2]) / 60.0) + "conn/s"
        else:
            str_num = re.findall(r'\d+', info[2])
            str_unit = re.findall(r'[a-zA-Z]+', info[2])
            CPS = str(long(str_num[0]) / 60.0) + str_unit[0] + "conn/s"
        #PPS = info[3]+info[4]
        if info[3].isdigit() and info[4].isdigit():
            PPS = str((long(info[3])+long(info[4])) /60.0 /1024 /1024 ) + "Mpps"
        else:
            str_num1 = re.findall(r'\d+', info[3])
            str_unit1 = re.findall(r'[a-zA-Z]+', info[3])
            if str_unit1[0] == 'K':
                num1 = long(str_num1[0]) /1024
            elif str_unit1[0] == 'G':
                num1 = long(str_num1[0]) * 1024
            else:
                num1 = long(str_num1[0])
            str_num2 = re.findall(r'\d+', info[4])
            str_unit2 = re.findall(r'[a-zA-Z]+', info[4])
            if str_unit2[0] == 'K':
                num2 = long(str_num2[0]) /1024
            elif str_unit2[0] == 'G':
                num2 = long(str_num2[0]) * 1024
            else:
                num2 = long(str_num2[0])
            PPS = str((num1+num2) /60.0) + "Mpps"
        #BPS = info[5]+info[6]
        if info[5].isdigit() and info[6].isdigit():
            BPS = str((long(info[5])+long(info[6])) /60.0 /1024 /1024 * 8) + "Mbps"
        else:
            str_num1 = re.findall(r'\d+', info[5])
            str_unit1 = re.findall(r'[a-zA-Z]+', info[5])
            if str_unit1[0] == 'K':
                num1 = long(str_num1[0]) /1024
            elif str_unit1[0] == 'G':
                num1 = long(str_num1[0]) * 1024
            else:
                num1 = long(str_num1[0])
            str_num2 = re.findall(r'\d+', info[6])
            str_unit2 = re.findall(r'[a-zA-Z]+', info[6])
            if str_unit2[0] == 'K':
                num2 = long(str_num2[0]) /1024
            elif str_unit2[0] == 'G':
                num2 = long(str_num2[0]) * 1024
            else:
                num2 = long(str_num2[0])
            BPS = str((num1+num2)*8 /60.0) + "Mbps"
        break
    file_name = ENV_FILE_DIR + "/dpvs_statis.txt"
    FILE_CONTENT = ""
    FILE_CONTENT = "CPS: " + CPS + "\n" + FILE_CONTENT
    FILE_CONTENT = "BPS: " + PPS + "\n" + FILE_CONTENT
    FILE_CONTENT = "PPS: " + BPS + "\n" + FILE_CONTENT
    file_writen(FILE_CONTENT, file_name)
    print(CONFIG_PASS + "test analysis")
