import os
import sys
import commands

if __name__ == '__main__':
    filename = sys.argv[1]
    commands.getstatusoutput("sh " + filename)
    if len(sys.argv) > 2:
        commands.getstatusoutput("python /root/dpvs_env_rollback.py")



