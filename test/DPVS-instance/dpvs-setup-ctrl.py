#!/usr/bin/python
#coding=utf-8
########script to setup env of dpvs and run########
#-- INPUT:DPVS version
#-- OUTPUT:setup info: succeed/failed
import os
import sys
import time
import commands
import fcntl
import netifaces
#-------------constant strings used----------------#
ENV_FILE_DIR     = "/root/old_env"
CONFIG_PASS      = "CONFIGED SUCCEED for "

#------------roll back script writing------------#
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
 
#-------------correlated env record---------------#
def record_old_dpdk_env(FILE_CONTENT):
    '''dpdk-devbind --status get bind status'''
    cmd = "dpdk-devbind --status | grep drv=igb_uio"
    cmd_stats, cmd_result =  commands.getstatusoutput(cmd)
    if cmd_stats == 0:
        bind_list = cmd_result.split("\n")       
        num = len(bind_list)
        for i in range(num):
            cmd0 = "dpdk-devbind -b igb_uio " + bind_list[i].split()[0] + "\n"
            FILE_CONTENT = cmd0 + FILE_CONTENT            

    return {"status":True, "content":FILE_CONTENT}         

######################################################
#####    functions run for env compiled        #######
######################################################
def dpdk_env_setup(FILE_CONTENT, ifaces):
    '''test the dpdk env and record old one'''
    bind_stats_cmd = "dpdk-devbind --status"
    cmd_status, cmd_result =  commands.getstatusoutput(bind_stats_cmd)
    if cmd_status != 0:
        dpdk_deployed = False
    else:
        dpdk_deployed = True 
        rec = record_old_dpdk_env(FILE_CONTENT)
        FILE_CONTENT = rec["content"]

    '''testify system: NUMA struct or not'''
    sys_struct = "grep -i numa /var/log/dmesg"
    _, res = commands.getstatusoutput(sys_struct)
    if res.find("No NUMA configuration found") != -1: 
        return {"status":False, "content":FILE_CONTENT, "detail":"single-node system, skip..."} 

    '''DPDK hugepages set'''
    numa_nodes = "grep -i numa /var/log/dmesg | grep node"
    _, res_numa = commands.getstatusoutput(numa_nodes)
    total = len(res_numa.split("\n"))
    cmd_str = "ls /sys/devices/system/node/node0/hugepages/ | grep hugepages-"
    _, res = commands.getstatusoutput(cmd_str)
    for i in range(total):
        huge_cmd = "echo 8192 > /sys/devices/system/node/node" + str(i) + "/hugepages/" + res + "/nr_hugepages"
        stats, _ = commands.getstatusoutput(huge_cmd)
        if stats != 0:
            return {"status":False, "content":FILE_CONTENT, "detail":"failed set huge pages"}

    '''DPDK dependencies installation'''
    cmd = "yum install -y automake libnl3 libnl-genl-3.0 openssl popt  popt-devel numactl gcc make meson ninja-build"
    os.system(cmd)
    #yum install failed but could start dpvs, just in case

    '''DPDK drivers load -- files:/root/dpdk-dependencies/kmod'''
    uio_cmd = "modprobe uio"
    s, res = commands.getstatusoutput(uio_cmd)
    if s == 0:
        cmd0 = "rmmod uio \n"
        FILE_CONTENT = cmd0 + FILE_CONTENT
    elif res.find("File exists") != -1:
        pass
    else:
        return {"status":False, "content":FILE_CONTENT, "detail":"DPDK drivers loading failed"}

    uio_cmd = "insmod /root/dpdk-dependencies/kmod/igb_uio.ko"
    s, res = commands.getstatusoutput(uio_cmd)
    if s == 0:
        cmd0 = "rmmod /root/dpdk-dependencies/kmod/igb_uio.ko \n"
        FILE_CONTENT = cmd0 + FILE_CONTENT
    elif res.find("File exists") != -1:
        pass
    else:
        return {"status":False, "content":FILE_CONTENT, "detail":"DPDK drivers loading failed"}

    uio_cmd = "insmod /root/dpdk-dependencies/kmod/rte_kni.ko"
    s, res = commands.getstatusoutput(uio_cmd)
    if s == 0:
        cmd0 = "rmmod /root/dpdk-dependencies/kmod/rte_kni.ko \n"
        FILE_CONTENT = cmd0 + FILE_CONTENT
    elif res.find("File exists") != -1:
        pass
    else:
        return {"status":False, "content":FILE_CONTENT, "detail":"DPDK drivers loading failed"}

    '''bind NIC with dpdk-dependencies/usertools/dpdk-devbind.py'''
    stats_cmd = "/root/dpdk-dependencies/usertools/dpdk-devbind.py --status | grep "
    bind_cmd = "/root/dpdk-dependencies/usertools/dpdk-devbind.py -b igb_uio "
    unbind_cmd = "/root/dpdk-dependencies/usertools/dpdk-devbind.py -b ixgbe " #bind kernel
    othbind_cmd = "/root/dpdk-dependencies/usertools/dpdk-devbind.py -b " #bind other known network
    bind_num = 0
    #bind kernel network first to have "if" key
    stats, res = commands.getstatusoutput(stats_cmd + "igb_uio")
    niclist = res.split("\n")
    for nic in niclist:
        if nic.find("drv=") == -1:  #other networks
            tmp_bind = unbind_cmd + nic.split()[0]   #bind kernel
            stats, _ = commands.getstatusoutput(tmp_bind)
            if stats != 0:
                return {"status":False, "content":FILE_CONTENT, "bind_num":0, "detail":"DPDK devbind failed"}
        elif nic.find("drv=ixgbe") == -1 and nic.find("drv=igb_uio") == -1:  #networks not other or kernel
            for elem in nic.split():
                if elem.find("drv=") != -1:
                    tmp_bind = unbind_cmd + nic.split()[0] #bind kernel
                    stats, _ = commands.getstatusoutput(tmp_bind)
                    if stats != 0:
                        return {"status":False, "content":FILE_CONTENT, "bind_num":0, "detail":"DPDK devbind failed"}
                    cmd0 = othbind_cmd + elem.split("=")[1] + " " + nic.split()[0] + "\n"
                    FILE_CONTENT = cmd0 + FILE_CONTENT
        elif nic.find("drv=igb_uio") != -1: #bind DPDK already
            bind_num = bind_num + 1

    #iface can bind:down or get from sys_argv / intern NIC
    usable_face = []
    if ifaces == "": #no given ifaces--need tcpdump to determine
        faces = netifaces.interfaces()
        commands.getstatus("yum install -y tcpdump")
        for face in faces:
            if face == 'lo' or face.find("eth") == -1:
                continue
            up_cmd = "ifup " + face
            s, _ = commands.getstatusoutput(up_cmd)
            if s != 0:
                usable_face.append(face)  
                continue
            dump_cmd = "tcpdump -c 3 -i " + face   
            _, res = commands.getstatusoutput(dump_cmd)
            if res.find("IP 172.") != -1:
                continue;
            usable_face.append(face)
    else:
        for face in ifaces.split(","):
            usable_face.append(face) 
    #trasverse interfaces:not Active or external network one can bind
    for face in usable_face:
        stats, res = commands.getstatusoutput(stats_cmd + face)
        if res.find("Active") != -1 or stats != 0:
            continue

        down_cmd = "ifconfig " + face + " down"  
        commands.getstatus(down_cmd)
        stats, _ = commands.getstatusoutput(bind_cmd + res.split()[0])
        if stats == 0:
            bind_num += 1
            cmd0 = unbind_cmd + res.split()[0] + "\n"
            FILE_CONTENT = cmd0 + FILE_CONTENT  
        if bind_num == 2:
            break

    return {"status":True, "content":FILE_CONTENT, "bind_num":bind_num, "detail":"DPDK environment settled"} 

def dpvs_ctrl(bind_num, FILE_CONTENT, DPVS_VERSION, gitpro = False, spec = ""):
    '''build DPVS with source'''
    os.chdir(r'/root/dpvs')
    cmd0 = ""
    if os.system("git --version") != 0:
        os.system("yum install git -y")
    '''checkout to branch to test, if gitpro=True'''
    if gitpro:
        #checkout to DPVS_VERSION branch to compile DPVS
        checkout_cmd = "git checkout  " + DPVS_VERSION
        s, r = commands.getstatusoutput(checkout_cmd)
        if s != 0:
            return {"status":False, "content":FILE_CONTENT, "detail":"checkout to DPVS_VERSION branch failed"}
    #environmental variable RET_SDK set
    if not os.environ["RTE_SDK"]:
        os.environ["RTE_SDK"] = "/root/dpdk-dependencies"
    elif os.environ["RTE_SDK"] != "/root/dpdk-dependencies":
        os.system("echo \"export RTE_SDK=/root/dpdk-dependencies\" >> ~/.bashrc")
        commands.getstatus("source /root/.bashrc")
        f = open("/root/.bashrc", "r")
        count = str(len(f.readlines()) - 1)
        cmd0 = "sed '%s, $d' -i /root/.bashrc \nsource /root/.bashrc \n" % count
        FILE_CONTENT = cmd0 + FILE_CONTENT #delete last environ line
    #compile DPVS
    compile_cmd = "make -j32"
    if os.system(compile_cmd) != 0:
        return {"status":False, "content":FILE_CONTENT, "detail":"DPVS compile FAILED"}
    #install DPVS
    make_cmd = "make install"
    stats, _ = commands.getstatusoutput(make_cmd)
    if stats != 0:
        return {"status":False, "content":FILE_CONTENT, "detail":"DPVS install FAILED"}
    #backup /etc/dpvs.conf
    if os.path.exists("/etc/dpvs.conf"):
        backup_cmd = "mv /etc/dpvs.conf /etc/dpvs.conf-bak"
        cmd0 = "mv /etc/dpvs.conf-bak /etc/dpvs.conf \n"
        stats, _ = commands.getstatusoutput(backup_cmd)
        if stats != 0:
            print "DPVS conf backup FAILED"   #add logging
        else:
            FILE_CONTENT = cmd0 + FILE_CONTENT
    #copy conf to /etc/dpvs.conf
    if bind_num == 1:
        cp_cmd = "cp conf/dpvs.conf.single-nic.sample /etc/dpvs.conf"
    if bind_num == 2:
        cp_cmd = "cp conf/dpvs.conf.sample /etc/dpvs.conf"
    stats = os.system(cp_cmd)  #copy conf file to /etc/dpvs.conf
    if stats != 0:
        return {"status":False, "content":FILE_CONTENT, "detail":"DPVS conf update FAILED"}
    #NAT64 IPV6-6 OR IPV4 only
    if spec == "ip6":
        '''change mode from default perfect to signature'''
        s, _ = commands.getstatusoutput("sudo sed -i \"s/perfect/signature/g\" /etc/dpvs.conf")
        if s != 0:
            return {"status":False, "content":FILE_CONTENT, "detail":"DPVS ip6-6 conf update FAILED"}

    #run DPVS
    run_cmd = "./bin/dpvs  &"
    if os.system(run_cmd) != 0:
        return {"status":False, "content":FILE_CONTENT, "detail":"DPVS start FAILED"}

    time.sleep(13)  #wait for thread up

    cmd0 = "ps -ef | grep dpvs | awk '{print $2}'| xargs kill -9 \n"
    FILE_CONTENT = cmd0 + FILE_CONTENT
    #test again
    run_cmd = "./bin/dpip link show"
    stats, res = commands.getstatusoutput(run_cmd)
    if bind_num == 1 and res.find("dpdk0") == -1:
        return {"status":False, "content":FILE_CONTENT, "detail":"DPVS run FAILED"}
    if bind_num == 2 and res.find("dpdk1") == -1:
        return {"status":False, "content":FILE_CONTENT, "detail":"DPVS run FAILED"}

    return {"status":True, "content":FILE_CONTENT, "detail":"DPVS environment settled"} 

if __name__ == '__main__':
    '''generate rollback script with time()'''
    if len(sys.argv) < 1:
        print "usage:"
        print "  python dpvs-setup-ctrl.py DPVS_GIT_VERSION(checkout branch then make) ifaces nat64/ip6/"""
    if len(sys.argv) > 1:
        DPVS_VERSION = sys.argv[1]
        git_enable = True
    else:
        DPVS_VERSION = "v1.7.8" 
        git_enable = False
    FILE_CONTENT = "#!/usr/bin/sh \n"
    file_name = ENV_FILE_DIR + "/" + "old_env.sh"
    if not os.path.exists(ENV_FILE_DIR):
        os.makedirs(ENV_FILE_DIR)
        FILE_CONTENT = "rm -rf " + ENV_FILE_DIR + "\n" + FILE_CONTENT
    else:
        FILE_CONTENT = "rm -f " + ENV_FILE_DIR + "/*\n"  + FILE_CONTENT

    if not os.path.exists("/root/dpvs"):
        if os.system("tar -xvf /root/dpvs.tar -C /root") != 0:
            file_writen(FILE_CONTENT, file_name)
            print "extract dpvs.tar failed!"
            sys.exit(-1)
    if not os.path.exists("/root/dpdk-dependencies"):
        if os.system("tar -xvf /root/dpdk-dependencies.tar -C /root") != 0:
            file_writen(FILE_CONTENT, file_name)
            print "extract dpdk-dependencies.tar failed!"
            sys.exit(-1)
    '''DPVS runing status reset'''
    stats, res = commands.getstatusoutput("ps -ef | grep dpvs")
    lines = res.split("\n")
    for line in lines:
        if line.find("grep") == -1 and line.find("python") == -1: #program thread info line
            elem_list = line.split()
            program = elem_list[(len(elem_list))-1]
            if program.find(".") == -1: #program NOT run in source dir can be restart after test done
                cmd0 = program + " & \n" 
                FILE_CONTENT = cmd0 + FILE_CONTENT
            if os.system("kill -9 " + elem_list[1]) != 0:
                print "DPVS running but exit failed!"
                file_writen(FILE_CONTENT, file_name)
                sys.exit(-1)
    '''DPDK environment setting''' 
    if len(sys.argv) > 2:
        ifaces = sys.argv[2]
    else:
        ifaces = ""
    dpdk_res = dpdk_env_setup(FILE_CONTENT,ifaces)
    FILE_CONTENT = dpdk_res["content"] 
    bind_num = dpdk_res.get("bind_num", 0)
    if bind_num == 0 or not dpdk_res["status"]:
        print("Failed config DPDK if: " + dpdk_res["detail"])
        file_writen(FILE_CONTENT, file_name)
        sys.exit(-1)
    else:
        print("DPDK ENV configured")
    '''config and start DPVS process--True/False 
       represent whether to checkout version branch ingress'''
    if len(sys.argv) > 3: #NAT64 / IPV6-6
        spec = sys.argv[3]
    else:
        spec = "" #IPV4-IPV4
    dpvs_res = dpvs_ctrl(bind_num, FILE_CONTENT, DPVS_VERSION, git_enable, spec)
    FILE_CONTENT = dpvs_res["content"] 
    if not dpvs_res["status"]:
        print(CONFIG_FAIL + "DPVS" + "---" + dpvs_res["detail"])
        file_writen(FILE_CONTENT, file_name)
        sys.exit(-1)

    file_writen(FILE_CONTENT, file_name)
    print(CONFIG_PASS + "DPVS")
