#coding=utf-8
import os
import sys
import commands
import socket
import struct
import netifaces
import fcntl
#-------constants used-----------#
ENV_FILE_DIR     = "/root/old_env"
CONFIG_PASS      = "CONFIGED SUCCEED for "
keepalived_contents = '''\
! Configuration File for keepalived
!include /etc/dpvs.conf
! test configure file
global_defs {
}

local_address_group laddr_g1 {
'''
vrrp_sync_contents = '''\
vrrp_sync_group 111 {
    group {
        VI_1
    }
}

'''
vrrp_instance_contents = '''\
vrrp_instance VI_1 {
    state %(state)s
    interface dpdk0.kni
    dpdk_interface dpdk0
    virtual_router_id 111
    priority %(priority)s
    advert_int 1
    authentication {
       auth_type PASS
       auth_pass 12345
     }

    virtual_ipaddress {
       %(vip)s
    }
}
'''
keepalived_vs_contents = '''\
virtual_server_group %(name)s {
    %(vip)s %(vport)s
}

virtual_server  group %(vs_group_name)s {
    delay_loop 3 
    lb_algo %(lb_algo)s
    lb_kind %(lb_kind)s
    protocol %(proto)s
    laddr_group_name laddr_g1

    %(rss)s
}
'''
keepalived_rs_contents = '''
    real_server %(rip)s %(rport)s {
        weight %(weight)s
        inhibit_on_failure
        %(check)s
    }
'''
keepalived_tcp_check='''TCP_CHECK {
            nb_sock_retry 2
            connect_timeout 3
            connect_port %(rport)s
        }
'''
keepalived_udp_check='''MISC_CHECK {
            misc_path "nmap %(ipv6)s -sU -n %(rip)s -p %(rport)s | grep 'udp open' && exit 0 || exit 1"
            misc_timeout 3
        }
'''
keepalived_rs_append = '''    real_server %(rip)s %(rport)s {\\n        weight %(weight)s\\n\\n        %(rs_uthreshold)s\\n        inhibit_on_failure\\n        TCP_CHECK {\\n            connect_timeout 3\\n            retry 2\\n            connect_port %(rport)s\\n       }\\n    } #end %(rip)s %(rport)s\\n\\n'''

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
        print "python keepalived_fnat_onearm.py (ifconfig ips) vip:vport"
        print "(rs ips) 1/0 TCP/UDP,rr/wrr/sh/lc,FNAT/DR(default TCP,rr,FNAT)"
    '''params parser'''
    config_ip = sys.argv[1]
    vip_info  = sys.argv[2]
    rip_info  = sys.argv[3]
    master    = sys.argv[4]
    if len(sys.argv) >= 6:
        serv_info  = sys.argv[5]
        serv_params = serv_info.split(",")
        if len(serv_params) < 3:
            print "lack of service config info!"
            sys.exit(-1)
        else:
            serv_lb   = serv_params[2]
            serv_sch  = serv_params[1]
            serv_type = serv_params[0]
    else:
        serv_lb   = "FNAT"
        serv_sch  = "rr"
        serv_type = "TCP"
    vip      = vip_info.split(":")[0]
    vport    = vip_info.split(":")[1]
    '''keepalived configuration content edit'''
    KEEPALIVED_CONF = keepalived_contents
    s, r = commands.getstatusoutput("/root/dpvs/bin/dpip link show | grep dpdk")
    if s != 0 or len(r.split("\n")) < 1 :
        print "WRONG DPDK vitrual iface config!"
        sys.exit(-1)
    '''find Active interface'''
    ip_list = config_ip.split(",")
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
    file_name = ENV_FILE_DIR + "/rollback_alived_mback.sh"
    FILE_CONTENT = ""
    if master == "1":
        state = 'MASTER'
        priority = '100'
    else:
        state = 'BACKUP'
        priority = '80'

    for item in ip_list:
        cmd = "ip addr add " + item + "/24 dev dpdk0.kni"
        s, r = commands.getstatusoutput(cmd)
        if s != 0:
            print "local ip config failed!"
            sys.exit(-1)
        cmd0 = "ip addr del " + item + "/24 dev dpdk0.kni" + "\n"
        FILE_CONTENT = cmd0 + FILE_CONTENT

        if os.system("/root/dpvs/bin/dpip route add " + item + "/32 dev dpdk0 scope kni_host") !=0:
            file_writen(FILE_CONTENT, file_name)
            print "dpip route add failed!"
            sys.exit(-1)
        cmd0 = "/root/dpvs/bin/dpip route del " + item + "/32 dev dpdk0 scope kni_host\n"
        FILE_CONTENT = cmd0 + FILE_CONTENT

    '''append LIP config + vrrp conf to KEEPALIVED_CONF'''
    conf_tmp = "    " + ip_list[0] + " dpdk0 \n"
    conf_tmp =  conf_tmp + "    " + ip_list[1] + " dpdk0 \n"

    KEEPALIVED_CONF = KEEPALIVED_CONF + conf_tmp + "}\n"
    KEEPALIVED_CONF = KEEPALIVED_CONF + vrrp_sync_contents 
    vrrp_param = {'state':state,'priority':priority,'vip':vip}
    vrrp_conf = vrrp_instance_contents % vrrp_param
    KEEPALIVED_CONF = KEEPALIVED_CONF + vrrp_conf 
    '''append virtual server conf to KEEPALIVED_CONF'''
    name = vip + "-" + vport
    vs_group_name = name
    lb_algo = serv_sch 
    lb_kind = serv_lb
    proto   = serv_type
    keepalived_rs_conf = ""
    if proto == 'TCP':
        check_temp = keepalived_tcp_check
    elif proto == 'UDP':
        check_temp = keepalived_udp_check
    else:
        check_temp = ''
    rip_list = rip_info.split(",")
    for rip_item in rip_list:
        rip      = rip_item.split(":")[0]
        rport    = rip_item.split(":")[1]
        weight   = rip_item.split(":")[2]

        check = check_temp % {'rip':rip,'rport':rport}
        tmp_rs_param = {'rip':rip,'rport':rport,'weight':weight,'check':check}
        tmp_rs_conf  = keepalived_rs_contents % tmp_rs_param
        keepalived_rs_conf = keepalived_rs_conf + tmp_rs_conf
    keepalived_vs_param = {'name':name,'vs_group_name':vs_group_name,'lb_algo':lb_algo,'vip':vip,
                         'vport':vport,'lb_kind':lb_kind,'proto':proto,'rss':keepalived_rs_conf}
    keepalived_vs_conf = keepalived_vs_contents % keepalived_vs_param
    KEEPALIVED_CONF = KEEPALIVED_CONF + keepalived_vs_conf 

    if os.path.exists("/etc/keepalived/keepalived.conf"):
        cmd = "mv /etc/keepalived/keepalived.conf /etc/keepalived/keepalived.conf-bak"
        s, r = commands.getstatusoutput(cmd)
        if s != 0:
            file_writen(FILE_CONTENT, file_name)
            print "backup file failed, maybe for limits of authority!"
            sys.exit(-1)
        cmd0 = "mv /etc/keepalived/keepalived.conf-bak /etc/keepalived/keepalived.conf \n"
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
    '''add routes to DPDK interface'''
    ip_route = ""
    for i in range(3):
        ip_route = ip_route + vip.split(".")[i] + "."
    ip_route = ip_route + "0/24"
    if os.system("/root/dpvs/bin/dpip route add " + ip_route + " dev dpdk0") !=0:
        file_writen(FILE_CONTENT, file_name)
        print "dpip route add failed!"
        sys.exit(-1)
    cmd0 = "/root/dpvs/bin/dpip route del " + ip_route + " dev dpdk0 \n"
    FILE_CONTENT = cmd0 + FILE_CONTENT
    '''mater DPVS need set VIP too'''
    if master == "1":
        if os.system("/root/dpvs/bin/dpip addr add " + vip + "/32 dev dpdk0") !=0:
            file_writen(FILE_CONTENT, file_name)
            print "dpip addr add VIP failed!"
            sys.exit(-1)
        cmd0 = "/root/dpvs/bin/dpip addr del " + vip + "/32 dev dpdk0 \n"
        FILE_CONTENT = cmd0 + FILE_CONTENT
    '''local address del cmd writen in rollback file'''
    for item in ip_list:
        cmd0 = "/root/dpvs/bin/dpip addr del " + item + "/32 dev dpdk0 \n"
        FILE_CONTENT = cmd0 + FILE_CONTENT

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
    print(CONFIG_PASS + "keepalived " + state + " on " + res)

