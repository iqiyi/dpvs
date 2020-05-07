#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Communication Module.

    This module provides communication utilies, include but no limited to
    * Execute command/scrips on a remote host and retrieve the exit status and outputs.
    * Launch  command/script on a remote hostr and return immediately.
    * Download/Upload file from/to a remote host.

    __author__      = 'wencyu'
    __email__       = 'yuwenchao@qiyi.com'
    __date__        = '2020/05/06'
    __version__     = '0.1.0'
    __copyright__   = 'Copyright 2020, iQiYi/DPVS'

"""
import time
import paramiko
import threading
from errcode import ErrorCode


class SSHConfig():
    """
    SSH global config for paramiko module.
    """
    PORT    = 22
    USER    = 'root'
    PASSWD  = ''
    CONN_TO = 3

    @staticmethod
    def get_ssh_port():
        return SSHConfig.PORT

    @staticmethod
    def get_ssh_user():
        return SSHConfig.USER

    @staticmethod
    def get_ssh_passwd():
        return SSHConfig.PASSWD

    @staticmethod
    def get_ssh_conn_timeout():
        return SSHConfig.CONN_TO

    @staticmethod
    def set_ssh_port(port):
        if (0 < port < 65536):
            SSHConfig.PORT = port
            return 0
        return -1

    @staticmethod
    def set_ssh_user(user):
        SSHConfig.USER = user
        return 0

    @staticmethod
    def set_ssh_passwd(passwd):
        SSHConfig.PASSWD = passwd
        return 0

    @staticmethod
    def set_ssh_conn_timeout(timeout):
        if timeout > 0:
            SSHConfig.CONN_TO = timeout
            return 0
        return -1


def channel_wati_exit_status(channel, timeout):
    """ Wait for exit status ready of paramiko.Channel.

    Args:
        channel: Channel object blocked by recv_exit_status of paramiko.Channel.
        timeout: Time to wait.

    Returns:
        ErrorCode.OK if exit status was ready, or timeout was 0 or None
        ErrorCode.TIMEOUT if time out.

    Raises:
        None
    """
    tick = time.time()
    intv = 0.001
    if not timeout:
        return ErrorCode.OK
    while not channel.exit_status_ready():
        if time.time() - tick > timeout:
            return ErrorCode.TIMEOUT
        time.sleep(intv)
        intv *= 2
    return ErrorCode.OK


def exec_command(remote_host, cmd, timeout=None):
    """ Execute a command on the remote host in a block way.
        Use ssh protocol to communicate with the remote host.
        The params of ssh is from SSHConfig.

    Args:
        remote_host: Where to execute the command.
        cmd:         The command to be executed on the remote host.
        timeout:     Time to wait the exit status to be ready of the command, in seconds.
                     Wait until the command exit if timeout is 0 or None.
    Returns:
        Exit status and output of the command if succeed.
        ErrorCode.SSHERROR if ssh failed.
        ErrorCode.TIMEOUT if timeout.

    Raises:
        None
    """
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=remote_host,
                    port=SSHConfig.get_ssh_port(),
                    username=SSHConfig.get_ssh_user(),
                    password=SSHConfig.get_ssh_passwd(),
                    timeout=SSHConfig.get_ssh_conn_timeout())
        stdin, stdout, stderr = ssh.exec_command(cmd)

        ret = channel_wati_exit_status(stdout.channel, timeout)
        if ret != ErrorCode.OK:
            ## how to kill the remote process ?
            return ret,  ErrorCode.strerror(ret)

        status = stdout.channel.recv_exit_status() # block until cmd finished
        outputs = stdout.read().decode()
        return status, outputs

    except paramiko.SSHException as e:
        return ErrorCode.SSHERROR, "%s: %s" % (ErrorCode.strerror(ErrorCode.SSHERROR), e)
    except Exception as e:
        return ErrorCode.UNKOWN, "%s: %s" % (ErrorCode.strerror(ErrorCode.UNKOWN), e)
    finally:
        ssh.close()


def launch_command(remote_host, cmd):
    """ Execute a command on the remote host in a nonblock way.
        Launch the remote command in a thread and do not wait for its exit ready status.
        Use ssh protocol to communicate with the remote host.
        The params of ssh is from SSHConfig.

    Args:
        remote_host: Where to execute the command.
        cmd:         The command to be executed on the remote host.

    Returns:
        None

    Raises:
        None
    """
    t = threading.Thread(target=exec_command, args=(remote_host, cmd))
    t.start()


def exec_script(remote_host, script, timeout=None, destdir='/tmp'):
    """ Execute a script on the remote host in a block way.

    Args:
        remote_host: Where to execute the script.
        script:      The script to be executed on the remote host.
        timeout:     Time to wait the exit ready status of the script, in seconds.
                     Wait until the script exit if timeout is 0 or None.
        destdir:     Temporary directory on the remote host to execute the script.
                     An existing destdir should be given, otherwise a new destdir
                     would be created and not removed after the function exit.
    Returns:
        Exit status and output of the command if succeed.
        ErrorCode.SSHERROR if ssh failed.
        ErrorCode.TIMEOUT if timeout.
        ErrorCode.UNKOWN if unexpected fail caught.

    Raises:
        None
    """
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=remote_host,
                    port=SSHConfig.get_ssh_port(),
                    username=SSHConfig.get_ssh_user(),
                    password=SSHConfig.get_ssh_passwd(),
                    timeout=SSHConfig.get_ssh_conn_timeout())
        sftp = ssh.open_sftp()
        try:
            sftp.listdir(destdir)
        except IOError as e:
            print('%s, create dir %s' % (e, destdir))
            #sftp.mkdir(destdir)
            stdin, stdout, stderr = ssh.exec_command('mkdir -p %s' % destdir)
            status = stdout.channel.recv_exit_status()
            if status != 0:
                print('Error: fail to mkdir %s on %s' % (destdir, remote_host))
                outputs = stdout.read().decode()
                return status, outputs
        destfile = os.path.abspath(destdir) + '/' +  os.path.basename(script)
        sftp.put(script, destfile)
        sftp.chmod(destfile, 0o544)

        status,outputs = exec_command(remote_host, destfile, timeout)
        sftp.remove(destfile)
        if status == ErrorCode.TIMEOUT:
            # kill the script if timeout
            ssh.exec_command("kill $(ps -ef | grep \"%s\" | grep -v grep | awk '{print $2}')" % destfile)
        return status, outputs

    except paramiko.SSHException as e:
        return ErrorCode.SSHERROR, "%s: %s" % (ErrorCode.strerror(ErrorCode.SSHERROR), e)
    except Exception as e:
        return ErrorCode.UNKOWN, "%s: %s" % (ErrorCode.strerror(ErrorCode.UNKOWN), e)
    finally:
        ssh.close()


def launch_script(remote_host, script, destdir='/tmp'):
    """ Execute the script on the remote host in a nonblock way.
        Upload and launch the script in a thread and do not wait for its exit.

    Args:
        remote_host: Where to execute the script.
        script:      The script to be executed on the remote host.
        destdir:     Temporary directory on the remote host to execute the script.
                     An existing destdir should be given, otherwise a new destdir
                     would be created and not removed after the function exit.

    Returns:
        None

    Raises:
        None
    """
    t = threading.Thread(target=exec_script, args=(remote_host, script, destdir))
    t.start()


def upload_file(remote_host, local_file, remote_file, fmode=None):
    """ Upload a file to the remote host.
        It would block the caller until upload finished.

    Args:
        remote_host: The dest server to recieve the file.
        local_file:  The pathname of the local file to upload.
        remote_file: The pathname of the target file on the remote host.
                     An existing remote_file directory should be existing,
                     otherwise a new directory would be created.
    Returns:
        (0, "upload suceed") if succeed.
        ErrorCode.SSHERROR if ssh failed.
        ErrorCode.UNKOWN if unexpected fail caught.

    Raises:
        None
    """
    if not os.path.exists(local_file):
        return ErrorCode.NOTEXIST, ErrorCode.strerror(ErrorCode.NOTEXIST)
    destdir = os.path.dirname(remote_file)
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=remote_host,
                    port=SSHConfig.get_ssh_port(),
                    username=SSHConfig.get_ssh_user(),
                    password=SSHConfig.get_ssh_passwd(),
                    timeout=SSHConfig.get_ssh_conn_timeout())
        sftp = ssh.open_sftp()
        try:
            sftp.listdir(destdir)
        except IOError as e:
            print('%s, create dir: %s' % (e, destdir))
            #sftp.mkdir(destdir)
            stdin, stdout, stderr = ssh.exec_command('mkdir -p %s' % destdir)
            status = stdout.channel.recv_exit_status()
            if status != 0:
                print('Error: fail to mkdir %s on %s' % (destdir, remote_host))
                outputs = stdout.read().decode()
                return status, outputs
        sftp.put(local_file, remote_file)
        if fmode:
            sftp.chmod(destfile, fmode)
        return 0, "upload suceed"
    except paramiko.SSHException as e:
        return ErrorCode.SSHERROR, "%s: %s" % (ErrorCode.strerror(ErrorCode.SSHERROR), e)
    except Exception as e:
        return ErrorCode.UNKOWN, "%s: %s" % (ErrorCode.strerror(ErrorCode.UNKOWN), e)
    finally:
        ssh.close()


def download_file(remote_host, remote_file, local_file, fmode=None):
    """ Download a file from the remote host.
        It would block the caller until download finished.

    Args:
        remote_host: The remote host from which to download.
        local_file:  The local pathname of the download file.
                     An existing locale_file directory should be existing,
                     otherwise a new directory would be created.
        remote_file: The remote file pathname to download.
    Returns:
        (0, "download suceed") if succeed.
        ErrorCode.INVALID if local_file is invalid.
        ErrorCode.SSHERROR if ssh failed.
        ErrorCode.UNKOWN if unexpected fail caught.

    Raises:
        None
    """
    if os.path.isfile(local_file):
        print('Warning: delete the already existing file: %s' % local_file)
    if os.path.isdir(local_file):
        return ErrorCode.INVALID, "%s: local_file=%s" %\
                (ErrorCode.strerror(ErrorCode.INVALID), local_file)
    localdir = os.path.dirname(os.path.abspath(local_file))
    print(localdir)
    if not os.path.isdir(localdir):
        os.makedirs(localdir)
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=remote_host,
                    port=SSHConfig.get_ssh_port(),
                    username=SSHConfig.get_ssh_user(),
                    password=SSHConfig.get_ssh_passwd(),
                    timeout=SSHConfig.get_ssh_conn_timeout())
        sftp = ssh.open_sftp()
        sftp.get(remote_file, local_file)
        if fmode:
            os.chmod(local_file, fmode)
        return 0, "download suceed"
    except paramiko.SSHException as e:
        return ErrorCode.SSHERROR, "%s: %s" % (ErrorCode.strerror(ErrorCode.SSHERROR), e)
    except Exception as e:
        return ErrorCode.UNKOWN, "%s: %s" % (ErrorCode.strerror(ErrorCode.UNKOWN), e)
    finally:
        ssh.close()


def is_remote_host_avail(remote_host):
    """ Check whether the remote host is accessible.

    Args:
        None

    Returns:
        True if the remote host is accessible,
        False otherwise.

    Raises:
        None
    """
    status, outputs = exec_command(remote_host, 'hostname', 3)
    if status:
        print(outputs)
    return not status



###########################################################################

if __name__ == '__main__':
    SSHConfig.set_ssh_user('root')
    SSHConfig.set_ssh_passwd('Dpvs.Test')
    print("ssh params: %d, %s, %s, %d" % (SSHConfig.get_ssh_port(),
                              SSHConfig.get_ssh_user(),
                              SSHConfig.get_ssh_passwd(),
                              SSHConfig.get_ssh_conn_timeout()))
    print('Is 10.15.204.15 accessible? %s' % is_remote_host_avail('10.15.204.15'))
    print(exec_command('10.15.204.15', 'hostname', 3))
    launch_command('10.15.204.15', 'hostname; sleep 3; date')
    #print(exec_script('10.15.204.15', '/tmp/test.sh', 10))
    #launch_script('10.15.204.15', '/tmp/test.sh')
    #print(upload_file('10.15.204.15', '/home/wencyu/dpvs-20191218.tar.gz',  '/tmp/dpvs.tar.gz'))
    #print(download_file('10.15.204.15', '/tmp/dpvs.tar.gz', './dpvs.tar.gz'))
