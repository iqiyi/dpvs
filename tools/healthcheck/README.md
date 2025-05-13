DPVS Healthcheck Program
------

# Introduction

The program implements a 3-tier health check framework for DPVS. It works in cooperation with dpvs-agent, polling loadbalancer services periodically and performing actions according to check results.
From top to botoom, there are 3 check layers tracking health states of `VA`, `VS`, and `Checker` respectively.

* **VA**(Virtual Address): Loadbalancer virtual service address denoted by IP.
* **VS** Virtual Server): Loadbalancer virtual service denoted by triplet <IP,Protocol,Port>.
* **Checker**: Checker runner for a specific backend server, invoking its health check method regularly.

A `VA` comprises of mutiple `VS`s, and a `VS` consists of multiple `Checkers`. The `Checker` checks backend server's health state periodically, and reports the result to its `VS`. The `VS` tracks health states for all its backends, performs UP/DOWN actions on each backend, sums a health state of itself from backends states and reports the result to `VA`. The `VA` collects all its `VS` health states, calculates a health state of itself with respect to `DownPolicy` configured by user, and executes corresponding action when its health state is changed.

The diagram below shows an example of the health check deployment layout.

```
VA:                                                                       192.168.88.1
                                                                                |
                                --------------------------------------------------------------------------------------
                                |                                               |                                    |
VS:                     192.168.88.1-TCP-80                            192.168.88.1-TCP-443                 192.168.88.1-UDP-80
                                |                                               |                                    |
                       ----------------------                        -----------------------                         |
                       |                    |                        |                     |                         |
Checker:      192.168.88.30-TCP-8080  192.168.88.68-TCP-8080  192.168.88.30-TCP-443  192.168.88.68-TCP-443  192.168.88.68-UDP-6000
```

Check methods supported are:

* **none**: Do nothing, used as a placeholder.
* **tcp**: Check via TCP probe, including a SYN probe procedure and possible data exchange.
* **udp**: Check via UDP probe relying on ICMP error message such as `Destination Unreachable` and possible data exchange.
* **ping**: Check via ICMP/ICMPv6 echo request/reply.
* **udpping**: Firstly, perform a ping check, and if succeed, then do a udp check.
* **http**: Check via HTTP/HTTPS probe, supporting versatile user configurations.

Action methods supported by `VS` are:
* **BackendUpdate**: Update backend's weight and `inhibited` flag in DPVS according to given health state. Also return new service lists if the ojects to update expired.

Action methods supported by`VA` are:
* **Blank**: Do nothing, used as a placeholder.
* **KernelRouteAddDel**: Add/Remove IP address from a specified linux network interface.
* **DpvsAddrAddDel**: Add/Remove IP address from a specified DPVS interface.
* **DpvsAddrKernelRouteAddDel**: Do both `KernelRouteAddDel` and `DpvsAddrAddDel`.
* **Script**: Run a script provided by user.

Check/Action methods can extend easily under the framework of the healthcheck program.

# Configurations

### 1. Application Configurations

Application configurations are provided with commandline parameters. Run `./healthcheck -h` to see the supported configuration items.

```sh
# ./healthcheck -h
Usage of ./healthcheck:
  -alsologtostderr
        log to standard error as well as files
  -checker-notify-channel-size uint
        Channel size for checker state change notice and resync. (default 100)
  -conf-check-uri string
        Http URI for checking if config file valid. (default "/conf/check")
  -conf-uri string
        Http URI for showing current effective configs. (default "/conf")
  -config-file string
        File path of healthcheck config file. (default "/etc/healthcheck.conf")
  -config-reload-interval duration
        Time interval to reload healthcheck config file. (default 7s)
  -debug
        Enable gops for debug.
  -dpvs-agent-addr string
        Server address of dpvs-agent. (default ":8082")
  -dpvs-service-list-interval duration
        Time interval to refetch dpvs services. (default 15s)
  -log_backtrace_at value
        when logging hits line file:N, emit a stack trace
  -log_dir string
        If non-empty, write log files in this directory
  -log_link string
        If non-empty, add symbolic links in this directory to the log files
  -logbuflevel int
        Buffer log messages logged at this level or lower (-1 means don't buffer; 0 means buffer INFO only; ...). Has limited applicability on non-prod platforms.
  -logtostderr
        log to standard error instead of files
  -metic-notify-channel-size uint
        Channel size for metric data sent from checkers to metric server. (default 1000)
  -metric-delay duration
        Max delayed time to send changed metric to metric server. (default 2s)
  -metric-server-addr string
        Server address for exporting healthcheck state and statistics. (default ":6601")
  -metric-server-uri string
        Http URI for exporting healthcheck state and statistics. (default "/metrics")
  -stderrthreshold value
        logs at or above this threshold go to stderr (default 2)
  -v value
        log level for V logs
  -vmodule value
        comma-separated list of pattern=N settings for file-filtered logging
  -vs-notify-channel-size uint
        Channel size for virtual service state change notice and resync. (default 100)
```

> Notes: The commandline parameters above may evolve with the project iteration. Please refer to the helper information from your program for the supported parameters.

### 2. Checker Configurations

The healthcheck program supports a yaml format file for checker configurations. The file layout and all supported configurations are maintained in [healthcheck.conf.template](./conf/healthcheck.conf.template).

A `global` config block for `VS` and `VA` can be included in the file, and if not, the default configurations in codes are used. Besides, you can set different config value from the global for a specific `VA` and `VS` in `virtual-addresses` and `virtual-servers` config blocks respectively. If set, it overwirtes the global configuations. We provide two config files as examples.

* [healthcheck.conf.simple](./conf/healthcheck.conf.simple): A simplest config file with all items are their default value.
* [healthcheck.conf.sample](./conf/healthcheck.conf.sample): A config file specifies global config block and some specific object related blocks.

An empty configuration file is allowed, in which case the default configurations in codes are used. Note that the healthcheck program must start with an existing config file specified by `-config-file` commandline parameter.

We can validate the config file with an HTTP API specified with `-conf-check-uri` commandline parameter, whose default value is `/conf/check`. Take [healthcheck.conf.sample](./conf/healthcheck.conf.sample) for example.

```
# curl http://10.61.240.28:6601/conf/check
Config File /etc/healthcheck.conf: VALID
......
```

Besides, we can retrieve the effective configurations via HTTP API specified by `-conf-uri` commandline parameter, whose default value is `/conf`. Still take [healthcheck.conf.sample](./conf/healthcheck.conf.sample) for example.

```
# curl http://10.61.240.28:6601/conf  
# Check Method Annotations: 1-none, 2-tcp, 3-udp, 4-ping, 5-udpping, 6-http, 10000-auto, 65535-passive
# VA DownPolicy Annotations: 1-oneOf, 2-allOf

global:
  virtual-address:
    disable: false
    down-policy: 2
    actioner: KernelRouteAddDel
    action-timeout: 2s
    action-sync-time: 1m0s
    action-params:
      ifname: dpdk0.102.kni
  virtual-server:
    method: 10000
    interval: 3s
    down-retry: 1
    up-retry: 1
    timeout: 2s
    method-params: {}
    actioner: BackendUpdate
    action-timeout: 2s
    action-sync-time: 15s
    action-params: {}
virtual-addresses:
  192.168.88.1:
    disable: false
    down-policy: 1
    actioner: DpvsAddrKernelRouteAddDel
    action-timeout: 2s
    action-sync-time: 30s
    action-params:
      dpvs-ifname: dpdk0.102
      ifname: dpdk0.102.kni
  2001::1:
    disable: true
    down-policy: 2
    actioner: KernelRouteAddDel
    action-timeout: 2s
    action-sync-time: 1m0s
    action-params:
      ifname: dpdk0.102.kni
virtual-servers:
  192.168.88.1-TCP-8080:
    method: 4
    interval: 5s
    down-retry: 0
    up-retry: 0
    timeout: 1s
    method-params: {}
    actioner: BackendUpdate
    action-timeout: 1s
    action-sync-time: 10s
    action-params: {}
```

# Metric Observation

A metric collection mechanism in built in the program. We can get the metric data from the metric server specified by `-metric-server-addr` and `-metric-server-uri` commandline parameters. The metric data divides into two categories.

* Thread Statistics: The current running, stopping and finished Go Routines for `VA`, `VS`, `Checker` and healthcheck methods.
* Object Statistics: Organized as a three layer structure, each line shows current health state and statistic data for a specific item in the layer.

The object statistics is shown in 6-tuple format. Its meanings varies for different layer, as shown in table below.

|                    | up, down           | up_notices, down_notices         | fail1, fail2               |
| ------------------ | ------------------ | -------------------------------- | ---------------------------|
| Checker            | probe state counts | state change notices             | check timeout, check error |   
| VirtualService(VS) | success actions    | received va state change notices | failed up/down actions     |   
| VirtualAddress(VA) | success actions    | received vs state change notices | failed up/down actions     |

This is the metric report from my test environments, which shows the health states and statistics of my DPVS server at 2025-05-09 14:31:02.

```
#curl http://10.61.240.28:6601/metrics
2025-05-09 14:31:02.802071741 +0800 CST m=+1026.188881757

Thread Statistics:
                    running         stopping        finished        
VirtualAddress      1               0               0               
VirtualService      3               0               0               
Checker             4               0               0               
HealthCheck         1               0               1227            

object                              state                               statistics                          extra(optional)
---------------------------------------------------------------------------------------------------------------------------
192.168.88.1                        Healthy 17m0s                       1,0,3,0,0,0                     
    TCP 192.168.88.1:80                 Healthy 16m58s                      1,0,1,0,0,0                     
    -> 192.168.88.30:80                    Healthy 17m1s                       341,0,1,0,0,0                   
    TCP 192.168.88.1:8080               Healthy 16m59s                      1,0,1,0,0,0                     
    -> 192.168.88.130:80                   Healthy 16m59s                      204,0,1,0,0,0                   
    UDP 192.168.88.1:80                 Healthy 17m0s                       1,0,2,0,0,0                     
    -> 192.168.88.130:7000                 Healthy 16m58s                      340,0,1,0,0,0                   
    -> 192.168.88.30:6000                  Healthy 17m3s                       342,0,1,0,0,0                   
Notes:
  statistics denotation: up,down,up_notices,down_notices,fail(up,timeout),fail(down,error)
```
