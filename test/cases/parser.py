#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Configuration Parser Module.

    Parse configuration files and provide utility functions
    to retrieve the configurations.

    __author__      = 'wencyu'
    __email__       = 'yuwenchao@qiyi.com'
    __date__        = '2020/05/08'
    __version__     = '0.1.0'
    __copyright__   = 'Copyright 2020, iQiYi/DPVS'
"""
import os
import sys
import yaml
import socket


def is_valid_ip(str_ip):
    """ Check if an IP address string is valid.
        Support IPv4 only.

    Args:
        str_ip: The IPv4 address string to check.

    Returns:
        Boolean type.
        True if the str_ip is a valid IPv4 address, False otherwise.

    Raises:
        None
    """
    try:
        socket.inet_pton(socket.AF_INET, str_ip)
        return True
    except socket.error:
        return False


def get_host_ip():
    """ Get IP address of current host.
        Support IPv4 only.

    Args:
        None

    Returns:
        IPv4 string address of the current host if succeed, None otherwise.

    Raises:
        None
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('8.8.8.8', 80))
        return sock.getsockname()[0]
    except:
        return None
    finally:
        sock.close()


def load_yaml_file(filename):
    """ Load a yaml file into memory.

    Args:
        filename: The name of file to load.

    Returns:
        The corresponding python object, None otherwise.

    Raises:
        None
    """
    try:
        with open(filename) as fd:
            cfg = yaml.load(fd, Loader=yaml.FullLoader)
            if not cfg:
                raise
            return cfg
    except:
        print('Fail to load yaml file: %s' % filename)
        return None


def check_cfg_main(cfg):
    """ Check if the main configurations are valid.

    Agrs:
        cfg: The python dictionary object loaded from main yaml config file.

    Returns:
        A new main config dictionary if validation passes, None otherwise.
        The original input config dictionary is not modified.

    Raises:
        None
    """
    cfgmain = { 'host':                     None,
                'workdir':                  '.',
                'default_script_delay':     0,
                'default_script_timeout':   60,
                'default_script_nonblock':  False,
                'report_file':              './report.md',
                'run_parallel':             True,
                'cases':                    {}
              }
    if not cfg or type(cfg) != type({}):
        return None

    if 'cases' not in cfg.keys() or not cfg['cases'] or not len(cfg['cases']):
        print('Error: no cases configured!')
        return None

    for key in cfg.keys():
        if key == 'host':
            if not is_valid_ip(cfg[key]) or cfg[key] ==  '127.0.0.1':
                cfgmain[key] = get_host_ip()
                if not cfgmain[key]:
                    print('Error: invalid config -- %s: %s' % (key, cfg[key]))
                    return None
                continue
            cfgmain[key] = cfg[key]
        elif key == 'workdir':
            if not os.path.exists(cfg[key]):
                print('Error: invalid config -- %s: %s' % (key, cfg[key]))
                return None
            cfgmain[key] = os.path.abspath(cfg[key])
        elif key in ('default_script_delay', 'default_script_timeout', 'default_script_priority'):
            if type(cfg[key]) != type(1):
                print('Error: invalid config -- %s: %s' % (key, cfg[key]))
                return None
            cfgmain[key] = int(cfg[key])
        elif key == 'report_file':
            if not os.path.exists(os.path.dirname(os.path.abspath(cfg[key]))):
                os.makedirs(os.path.dirname(cfg[key]))
            cfgmain[key] = os.path.abspath(cfg[key])
        elif key in ('run_parallel', 'default_script_nonblock'):
            if type(cfg[key]) != type(True):
                print('Error: invalid config -- %s: %s' % (key, cfg[key]))
                return None
            cfgmain[key] = cfg[key]
        elif key == 'cases':
            continue
        else:
            print("Warning: ignore not supported config -- %s: %s" % (key, cfg[key]))

    return cfgmain


def check_cfg_case(cfg):
    """ Check if the case configurations are valid.

    Agrs:
        cfg: The python dictionary object loaded from case yaml config file.

    Returns:
        A new case config dictionary if validation passes, None otherwise.
        The original input config dictionary is not modified.

    Raises:
        None
    """
    if not cfg or type(cfg) != type({}) or not len(cfg):
        return None
    cfgcases = cfg.copy()

    try:
        for name in cfgcases.keys():
            case = cfgcases[name]
            if not case or type(case) != type({}) or not len(case):
                print('Error: invalid case config -- %s: %s' % (name, case))
                return None
            for case_key in case.keys():
                if case_key == 'desc':
                    continue
                svr_group = case[case_key]
                if not svr_group or type(svr_group) != type({}) or not len(svr_group):
                    print('Error: invalid server_group config -- %s: %s' % (case_key, svr_group))
                    return None
                for sg_key in svr_group.keys():
                    if sg_key == 'stages':
                        stage = svr_group[sg_key]
                        if not stage or type(stage) != type({}) or not len(stage):
                            print('Error: invalid stage config -- %s: %s' % (sg_key, stage))
                            return None
                        for stage_key in stage.keys():
                            action = stage[stage_key]
                            if not action or type(action) != type({}) or not len(action):
                                print('Error: invalid stage action config -- %s: %s' % (stage_key, action))
                                return None
                            for key in action.keys():
                                if key == 'script':
                                    if not os.path.exists(action[key]):
                                        print('Error: script file not found -- %s: %s' % (key, action[key]))
                                        return None
                                    action[key] = os.path.abspath(action[key])
                                elif key == 'nonblock':
                                    if type(action[key]) != type(True):
                                        print('Error: invalid config -- %s: %s' % (key, action[key]))
                                        return None
                                elif key in ('priority', 'delay', 'timeout'):
                                    if type(action[key]) != type(0):
                                        print('Error: invalid config -- %s: %s' % (key, action[key]))
                                        return None
                                else:
                                    print('Warning: unsupported config -- %s: %s' % (key, action[key]))
                    elif sg_key == 'hosts':
                        hosts = svr_group[sg_key]
                        if not hosts or type(hosts) != type({}) or not len(hosts):
                            print('Error: invalid hosts config -- %s: %s' % (sg_key, hosts))
                            return None
                        for host in hosts.keys():
                            if not is_valid_ip(host):
                                print('Error: invalid hosts ip -- %' % host)
                                return None
                            params = hosts[host]
                            if params is None:
                                continue
                            for key in params.keys():
                                if key not in ('setup_params', 'run_params', 'clean_params'):
                                    print('Warning: not supported config -- %s: %s' % (key, params[key]))
                    elif sg_key == 'files':
                        files = svr_group[sg_key]
                        if not files:
                            continue
                        if type(files) != type([]) or not len(files):
                            print('Error: invalid files cofnig -- %s: %s' % (sg_key, files))
                            return None
                        newfiles = []
                        for f in files:
                            if not os.path.exists(f):
                                print('Error: file not exist -- %s' % f)
                                return None
                            newfiles.append(os.path.abspath(f))
                        if len(newfiles):
                            svr_group[sg_key] = newfiles

                    elif sg_key == 'packages':
                        packages = svr_group[sg_key]
                        if not packages:
                            continue
                        if type(packages) != type([]) or not len(packages):
                            print('Error: invalid packages config -- %s: %s' % (sg_key, packages))
                            return None
                    else:
                        print('Warning: not supported config -- %s: %s' % (sg_key, svr_group[sg_key]))
        return cfgcases
    except:
        print('Error: invalid config(unexpected error) -- %s' % cfg)
        return None


def parse_cfgfile(filename):
    """ Parse config file into python dictionary object,
        and check if the configurations are valid.

    Args:
        filename: The config file name.

    Returns:
        A python dictionary object containing the configurations if succeed. None otherwise.

    Raises:
        None
    """
    loadcfg = load_yaml_file(filename)
    cfg = check_cfg_main(loadcfg)
    if not cfg:
        return None
    #print(loadcfg)
    for case in loadcfg['cases']:
        loadcfg_case = load_yaml_file(case)
        cfg_cases = check_cfg_case(loadcfg_case)
        #print(loadcfg_case)
        if not cfg_cases:
            return None
        else:
            for key in cfg_cases.keys():
                cfg['cases'][key] = cfg_cases[key]

    #print(yaml.dump(cfg, sort_keys=True))
    return cfg


class CfgFile(object):
    """ Config file object.
        Load global and cases configurtions from yaml files into the object.
        Some uitlity functions are provided for the convinient access of some
        config entries.
    """
    def __init__(self, filename):
        ''' Init a CfgFile object.
        Raise:
            ValueError if error occurs.
        '''
        self.filename = filename

        self.configs = parse_cfgfile(filename)
        if not self.configs:
            print('Error: invalid config file -- %s' % filename)
            raise ValueError

        self.hostip = self.configs['host']
        self.workdir = self.configs['workdir']
        self.default_script_delay = self.configs['default_script_delay']
        self.default_script_priority =  self.configs['default_script_priority']
        self.report_file = self.configs['report_file']
        self.run_parallel = self.configs['run_parallel']
        self.cases = self.configs['cases']

    def dump_configs(self, fd=sys.stdout):
        ''' Dump current configurations from CfgFile into yaml stream.
            If no steam is specified, standard output stream is used.
        '''
        print(yaml.dump(self.configs, sort_keys=True), file=fd)

    def get_case_entry(self, keylist):
        ''' Get the config entry in self.cases specified by a key list.
            It's the most common way to get a config entry in a case.
        Args:
             keylist: a valid key list/tuple in the yaml config file,
                      starting with the case name.
        Returns:
            A corresponding python object if the key list is valid.
            Note the python object returned is not deep copied.
        '''
        try:
            entry = self.cases
            for key in keylist:
                entry = entry[key]
            return entry
        except KeyError as e:
            print('Invalid key list -- %s, %s' % (keylist, e))
            return None

    def get_case_names(self):
        ''' Return a tuple of all case names.
        '''
        return tuple(self.cases.keys())

    def get_case(self, case_name):

        ''' Return the python config object of a case specified by case name.
            Note the python object returned is not deep copied.
        '''
        try:
            return self.cases[case_name]
        except KeyError as e:
            print('%s: case %s not found.' % (e, case_name))
            return None

    def get_case_server_group_names(self, case_name):
        ''' Return a tuple of server group names for specified case.
        '''
        try:
            sg_name = []
            for key in self.cases[case_name].keys():
                if key in ['desc']:
                    continue
                sg_name.append(key)
            return tuple(sg_name)
        except:
            print('Fail to get server group names for case %s' % case_name)
            return None

    def get_case_server_group(self, case_name, sg_name):
        ''' Return the python server group config object of a case.
            Note the python object returned is not deep copied.
        '''
        try:
            return self.cases[case_name][sg_name]
        except KeyError as e:
            print('%s: server group %s for case %s not foud.' % (e, sg_name, case_name))
            return None

    def get_case_hosts(self, case_name):
        ''' Return a tuple of host IP of specified case.
            The return hosts are a collection of host IP in all server group
            and stages of the case.
        '''
        try:
            hosts = set()
            svgs = self.get_case_server_group_names(case_name)
            for sg in svgs:
                for host in self.cases[case_name][sg]['hosts'].keys():
                    hosts.add(host)
            return tuple(hosts)
        except:
            print('Fail to get all host IPs for case %s.' % case_name)
            return None


if __name__ == '__main__':
    #print(load_yaml_file('conf/example/example.yaml'))
    #print(yaml.dump(load_yaml_file('conf/example/example-case2.yaml')))
    #print(parse_cfgfile('conf/example/example.yaml'))

    cfgfile = CfgFile('conf/example/example.yaml')
    print(cfgfile.get_case_entry(('example-case1', 'client', 'hosts', '10.123.16.46', 'run_params')));
    #cfgfile.get_case_entry(('example-case1', 'client', 'stages'))['run'] = 'This will change the CfgFile object.'
    print(cfgfile.get_case_names())
    print('cfgfile.get_case:\n%s' % cfgfile.get_case('example-case3'))
    print(cfgfile.get_case_server_group_names('example-case1'))
    print(cfgfile.get_case_server_group('example-case1', 'realserver'))
    print(cfgfile.get_case_hosts('example-case1'))
    cfgfile.dump_configs()

