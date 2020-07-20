########script to rollback env of dpvs########
## INPUT:none
## OUTPUT:succeed/failed
#coding=utf-8
import os
import sys
import commands
#-------------reset environment----------------#
def rollback_env(file_name):
    os.chdir(r'/root')
    file_copy = "cp " + file_name + " ./clean.sh"
    stats, _ = commands.getstatusoutput(file_copy)
    if stats != 0:
        return {"status":False, "detail":"copy cleanup file failed!"}

    rollback_cmd = "sh clean.sh"
    stats, res = commands.getstatusoutput(rollback_cmd)
    if stats == 0:
        return {"status":True, "detail":"env reset done"}
    else:
        return {"status":True, "detail":res}
            
if __name__ == '__main__':
    #rollback after all cases done
    file_name = "/root/old_env/old_env.sh"
    rb_res = rollback_env(file_name)
    if rb_res["status"]:
        stats, _ = commands.getstatusoutput("rm -f /root/clean.sh")
        if stats != 0:
            print "rm clean.sh file FAILED!"
    else:
        print "reset dpvs env FAILED!"
        sys.exit(-1)
