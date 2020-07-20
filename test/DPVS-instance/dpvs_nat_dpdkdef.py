#coding=utf-8
import os
import sys
import commands
import fcntl
import netifaces
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
    if len(sys.argv) < 5:
        print "usage:"
        print "  python dpvs_nat_dpdkdef.py  (WAN/LAN ips) vip:vport"
        print " (rs ips) dpdk-n  -t/-u (default -t) rr/wrr/sh/lc... (default rr)"
    '''params parser'''
    config_ip = sys.argv[1]
    vip_info  = sys.argv[2]
    rip_info  = sys.argv[3]
    dev       = sys.argv[4]
    if len(sys.argv) >= 6:
        serv_type = sys.argv[5] + " "
    else:
        serv_type = '-t '
    if len(sys.argv) == 7:
        sch = sys.argv[6]
    else:
        sch = 'rr'

    ipvsadm_add_server = "/root/dpvs/bin/ipvsadm -a "
    ipvsadm_add_vip = "/root/dpvs/bin/ipvsadm -A "
    ipvsadm_del_vip = "/root/dpvs/bin/ipvsadm -D "
    dpip_del_addr = "/root/dpvs/bin/dpip addr del "
    dpip_add_addr = "/root/dpvs/bin/dpip addr add "
    dpip_route_add = "/root/dpvs/bin/dpip route add default via "
    dpip_route_del = "/root/dpvs/bin/dpip route del default via "
    '''config ips'''
    if not os.path.exists(ENV_FILE_DIR):
        os.mkdir(ENV_FILE_DIR)
    file_name = ENV_FILE_DIR + "/rollback_nat_onearm.sh"
    FILE_CONTENT = ""
    '''check dpvs + dpdk nic status'''
    s, r = commands.getstatusoutput("/root/dpvs/bin/dpip link show")
    if s != 0 or r.find(dev) == -1:
        file_writen(FILE_CONTENT, file_name)
        print "WRONG DPDK vitrual iface config!"
        sys.exit(-1)
    '''set dpip route and address'''
    ip_list = config_ip.split(",")
    #add WAN/LAN IP for DPVS
    for ip in ip_list:
        if os.system(dpip_add_addr + ip + "/24 dev " + dev) !=0:
            file_writen(FILE_CONTENT, file_name)
            print "dpip addr add WAN/LAN IP failed!"
            sys.exit(-1)
        cmd0 = dpip_del_addr + ip + "/24 dev " + dev + " \n"
        FILE_CONTENT = cmd0 + FILE_CONTENT

    vip      = vip_info.split(":")[0]
    vport    = vip_info.split(":")[1]
    #add service <VIP:vport> to forwarding
    if os.system(ipvsadm_add_vip + serv_type + vip_info + " -s " + sch) !=0:
        file_writen(FILE_CONTENT, file_name)
        print "dpip service <vip:vport> add failed!"
        sys.exit(-1)
    cmd0 = ipvsadm_del_vip + serv_type + vip_info + "\n"
    FILE_CONTENT = cmd0 + FILE_CONTENT
    #add RSs for service, forwarding mode NAT
    rip_list = rip_info.split(",")
    for rip in rip_list:
        if os.system(ipvsadm_add_server + serv_type + vip_info
                         + " -r " + rip + " -m") !=0:
            file_writen(FILE_CONTENT, file_name)
            print "add RS failed!"
            sys.exit(-1)
    #add VIP to WAN interface
    if os.system(dpip_add_addr + vip + "/32 dev " + dev) !=0:
        file_writen(FILE_CONTENT, file_name)
        print "dpip addr add VIP failed!"
        sys.exit(-1)
    cmd0 = dpip_del_addr + vip + "/32 dev " + dev + " \n"
    FILE_CONTENT = cmd0 + FILE_CONTENT

    file_writen(FILE_CONTENT, file_name)
    print(CONFIG_PASS + "DPVS ")
