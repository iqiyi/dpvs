#coding=utf-8
import os
import sys
import commands
import socket
import struct
import fcntl
#-------constants used-----------#
ENV_FILE_DIR     = "/root/old_env"
CONFIG_PASS      = "CONFIGED SUCCEED for "
keepalived_contents = '''\
! Configuration File for keepalived
global_defs {
}

'''
keepalived_vs_contents = '''\
virtual_server  match %(snat_name)s {
    protocol %(proto)s
    lb_algo %(lb_algo)s
    lb_kind SNAT
    src-range %(src-range)s
    oif %(dpdk_if)s
    alpha
    omega

   quorum 1
   quorum_up  %(addr_add)s
   quorum_down %(addr_del)s

    %(rss)s
}
'''
keepalived_rs_contents = '''
    real_server %(rip)s 0 {
        weight %(weight)s
        MISC_CHECK {
            misc_path "exit 0"
            misc_timeout 10 
        }
    }
'''
#-------basic configure----------#
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

if __name__ == '__main__':
    '''director keepalived conf + ip ifconfig'''
    if len(sys.argv) < 4:
        print "usage:"
        print "python keepalived_snat_onekni.py (src-range) wan_addr:wi gw"
        print "oif(default dpdk0)  TCP/UDP/ALL,rr/wrr/sh/lc(TCP/rr)"
    '''params parser'''
    print sys.argv
    src  = sys.argv[1]
    wan_info  = sys.argv[2]
    gw_info   = sys.argv[3]
    if len(sys.argv) >= 5:
        oif         = sys.argv[4]
    if len(sys.argv) >= 6:
        other_conf  = sys.argv[5]
        serv_params = other_conf.split(",")
        if len(serv_params) < 2:
            print "lack of service config info!"
            sys.exit(-1)
        else:
            serv_sch  = serv_params[1]
            serv_type = serv_params[0]
    else:
        serv_sch  = "rr"
        serv_type = "TCP"
    wan_ip    = wan_info.split(":")[0]
    wan_wi    = wan_info.split(":")[1]
    '''dpdk interfaces test'''
    s, r = commands.getstatusoutput("/root/dpvs/bin/dpip link show | grep dpdk")
    dpdk_list = r.split("\n")
    if s != 0 or len(dpdk_list) < 1 :
        print "WRONG DPDK vitrual iface config!"
        sys.exit(-1)
    elif oif == "dpdk1":
        if len(dpdk_list) < 2:
            print Exception,"WRONG DPDK vitrual iface config!"
            sys.exit(-1)
        elif r.count('UP') < 2:
            print "LACK of UP DPDK vitrual iface!"
            sys.exit(-1)

    '''rollback file edit'''
    if not os.path.exists(ENV_FILE_DIR):
        os.mkdir(ENV_FILE_DIR)
    file_name = ENV_FILE_DIR + "/rollback_alived_snat.sh"
    FILE_CONTENT = ""
    '''keepalived config file edit'''
    KEEPALIVED_CONF = keepalived_contents
    keepalived_rs_conf = keepalived_rs_contents % {'rip':wan_ip,'weight':wan_wi}
    addr_add = "/root/dpvs/bin/dpip addr add " + wan_ip + "/24 dev " + oif + " sapool;"
    addr_add = addr_add + "/root/dpvs/bin/dpip addr add " + gw_info + " dev dpdk0;"
    addr_del = "/root/dpvs/bin/dpip addr del " + wan_ip + "/24 dev " + oif + " ;"
    addr_del = addr_del + "/root/dpvs/bin/dpip addr del " + gw_info + " dev dpdk0;"
    keepalived_vs_param = {'lb_algo':serv_sch,'dpdk_if':oif,'src-range':src,
     'addr_add':"\"" + addr_add + "\"",'addr_del':"\"" + addr_del + "\"",'rss':keepalived_rs_conf}
    if serv_type == "ALL":
        keepalived_vs_param['snat_name'] = "SNAT1"
        keepalived_vs_param['proto'] = "ICMP"
        tmp_icmp_conf = keepalived_vs_contents % keepalived_vs_param
        KEEPALIVED_CONF = KEEPALIVED_CONF + tmp_icmp_conf
        keepalived_vs_param['snat_name'] = "SNAT2"
        keepalived_vs_param['proto'] = "TCP"
        tmp_tcp_conf = keepalived_vs_contents % keepalived_vs_param
        KEEPALIVED_CONF = KEEPALIVED_CONF + tmp_tcp_conf
        keepalived_vs_param['snat_name'] = "SNAT3"
        keepalived_vs_param['proto'] = "UDP"
        tmp_udp_conf = keepalived_vs_contents % keepalived_vs_param
        KEEPALIVED_CONF = KEEPALIVED_CONF + tmp_udp_conf
    elif serv_type == "TCP":
        keepalived_vs_param['snat_name'] = "SNAT1"
        keepalived_vs_param['proto'] = "ICMP"
        tmp_icmp_conf = keepalived_vs_contents % keepalived_vs_param
        KEEPALIVED_CONF = KEEPALIVED_CONF + tmp_icmp_conf
        keepalived_vs_param['snat_name'] = "SNAT2"
        keepalived_vs_param['proto'] = "TCP"
        tmp_tcp_conf = keepalived_vs_contents % keepalived_vs_param
        KEEPALIVED_CONF = KEEPALIVED_CONF + tmp_tcp_conf
    else:
        keepalived_vs_param['snat_name'] = "SNAT1"
        keepalived_vs_param['proto'] = "ICMP"
        tmp_icmp_conf = keepalived_vs_contents % keepalived_vs_param
        KEEPALIVED_CONF = KEEPALIVED_CONF + tmp_icmp_conf
        keepalived_vs_param['snat_name'] = "SNAT2"
        keepalived_vs_param['proto'] = "UDP"
        tmp_udp_conf = keepalived_vs_contents % keepalived_vs_param
        KEEPALIVED_CONF = KEEPALIVED_CONF + tmp_udp_conf

    if os.path.exists("/etc/keepalived/keepalived.conf"):
        cmd = "mv -f /etc/keepalived/keepalived.conf /etc/keepalived/keepalived.conf-bak"
        s, r = commands.getstatusoutput(cmd)
        if s != 0:
            file_writen(FILE_CONTENT, file_name)
            print "backup file failed, maybe for limits of authority!"
            sys.exit(-1)
        cmd0 = "mv -f /etc/keepalived/keepalived.conf-bak /etc/keepalived/keepalived.conf \n"
        FILE_CONTENT = cmd0 + FILE_CONTENT
    else:
        cmd0 = "rm -f /etc/keepalived/keepalived.conf \n"
        FILE_CONTENT = cmd0 + FILE_CONTENT
    file_writen(KEEPALIVED_CONF, "/etc/keepalived/keepalived.conf")
    '''start keepalived thread'''
    if os.system("/root/dpvs/bin/keepalived -f /etc/keepalived/keepalived.conf") != 0:
        file_writen(FILE_CONTENT, file_name)
        print "keepalived thread start failed!"
        sys.exit(-1)

    '''kill -TERM <pid of keepalived>'''
    s, r = commands.getstatusoutput("ps -ef | grep keepalived")
    if s != 0 or len(r.split("\n")) < 1 :
        file_writen(FILE_CONTENT, file_name)
        print "keepalived thread not FOUND!"
        sys.exit(-1)
    for line in r.split("\n"):
        tmp_line = line.split()
        if tmp_line[2] == "1":
            th = tmp_line[1]
            cmd0 = "kill -TERM " + th + "\n"
            FILE_CONTENT = cmd0 + FILE_CONTENT
            break
    file_writen(FILE_CONTENT, file_name)
    print(CONFIG_PASS + "keepalived SNAT")

