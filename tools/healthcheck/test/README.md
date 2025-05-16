DPVS 健康检查程序压力测试
---

# 测试方法

首先，使用 [stress-test.sh](./stress-test.sh) 脚本生成测试业务。

* 测试业务列表只需要有 VS 和 RS 配置，不需要配置 VIP、local IP 等。
* 通过调整脚本 `Step 2` 中的 i(ngroups), j 两个循环控制变量的范围控制产生的健康检查配置数量的多少。
* 通过调整脚本 `Step 2` 中循环控制变量 j 的范围控制每个 VS 下配置的 RS 数量的多少，默认每个 VS 配置 5 个 RS。

测试业务生成后 RS 初始状态都是 UP（权重为100）：

```
## 未启动健康检查服务时测试业务状态
IP Virtual Server version 1.10.1 (size=0)
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port           Forward Weight ActiveConn InActConn
TCP  192.168.1.1:80 wrr 
  -> 192.168.19.155:80            FullNat 100    0          0    
  -> 192.168.19.156:80            FullNat 100    0          0    
  -> 192.168.19.157:80            FullNat 100    0          0    
  -> 192.168.19.158:80            FullNat 100    0          0    
  -> 192.168.19.159:80            FullNat 100    0          0    
TCP  192.168.1.2:80 wrr 
  -> 192.168.19.160:80            FullNat 100    0          0    
  -> 192.168.19.161:80            FullNat 100    0          0    
  -> 192.168.19.162:80            FullNat 100    0          0    
  -> 192.168.19.163:80            FullNat 100    0          0    
  -> 192.168.19.164:80            FullNat 100    0          0    
TCP  192.168.1.3:80 wrr 
  -> 192.168.19.165:80            FullNat 100    0          0    
  -> 192.168.19.166:80            FullNat 100    0          0   
...
```

但实际上这些 RS 是不通的，后续健康检查程序会把所有的 RS 设置为 DOWN，即权重设为 0 同时添加 `inhibited` 标记。

```
## 健康检查完成测试业务状态
IP Virtual Server version 1.10.1 (size=0)
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port           Forward Weight ActiveConn InActConn
TCP  192.168.1.1:80 wrr
  -> 192.168.19.155:80            FullNat 0      0          0          inhibited
  -> 192.168.19.156:80            FullNat 0      0          0          inhibited
  -> 192.168.19.157:80            FullNat 0      0          0          inhibited
  -> 192.168.19.158:80            FullNat 0      0          0          inhibited
  -> 192.168.19.159:80            FullNat 0      0          0          inhibited
TCP  192.168.1.2:80 wrr
  -> 192.168.19.160:80            FullNat 0      0          0          inhibited
  -> 192.168.19.161:80            FullNat 0      0          0          inhibited
  -> 192.168.19.162:80            FullNat 0      0          0          inhibited
  -> 192.168.19.163:80            FullNat 0      0          0          inhibited
  -> 192.168.19.164:80            FullNat 0      0          0          inhibited
TCP  192.168.1.3:80 wrr
  -> 192.168.19.165:80            FullNat 0      0          0          inhibited
  -> 192.168.19.166:80            FullNat 0      0          0          inhibited
...
```

测试业务创建后，`stress-test.sh` 脚本会用如下命令在启动健康检查服务并将其置于后台运行，并把日志输出到脚本所在目录中的 `healthcheck.log` 文件中。

```sh
../healthcheck --alsologtostderr -dpvs-agent-addr=$dpvs_agent_server 2>&1 > healthcheck.log &
```

> 注意：测试环境默认 dpvs-agent 运行在 54321 端口上，其它端口请修改脚本中对应的变量值。

健康检查程序启动后，`stress-test.sh` 脚本会循环检测当前的 RS 总数和被置为 DOWN 状态的 RS 数量。 测试业务的 RS 会陆续由初始的 UP 状态而转为 DOWN 状态，我们根据 RS 被置为 DOWN 的数量的增长速度即可评估健康检查程序的并发性能。

# 配置文件

压测配置 RS 探测失败不重试、探测失败超时时间为 1 秒，其它都采用默认配置参数。具体配置文件如下。

```yaml
# Check Method Annotations: 1-none, 2-tcp, 3-udp, 4-ping, 5-udpping, 6-http, 10000-auto, 65535-passive
# VA DownPolicy Annotations: 1-oneOf, 2-allOf
---
global:
  virtual-address:
    actioner: KernelRouteAddDel
    action-params:
      ifname: dpdk0.102.kni
  virtual-server:
    method: 10000
    down-retry: 999999 ## no retry
    timeout: 1s
```

# 测试数据

* RS 数量：测试脚本自动创建的 RS 总量。
* 初始探测耗时：健康检查程序从启动到看到第一个 RS 被置为 DOWN 的时间，包含配置下发、实例创建和一次探测超时的时间。
* 耗时(5分位)：从第一个 RS 被置为 DOWN 到 50% 的 RS 被置为 DOWN 的时间。
* 耗时(9分位)：从第一个 RS 被置为 DOWN 到 90% 的 RS 被置为 DOWN 的时间。
* 总耗时：从第一个 RS 被置为 DOWN 到所有的 RS 被置为 DOWN 的时间。
* CPU 占用：健康检查程序的 CPU 使用量（压测期间 `pidstat -ur -p $(pidof healthcheck) 10` 命令输出的CPU%指标）。
* 内存占用：健康检查程序的内存使用量（压测期间 `pidstat -ur -p $(pidof healthcheck) 10` 命令输出的RSS指标）。

| RS数量 | 初始探测耗时 | 耗时(5分位) | 耗时(9分位) | 总耗时 | CPU占用 | 内存占用 | 备注       |
| ------ | ------------ | ----------- | ----------- | ------ | ------- | -------- | ---------- |
| 0      | 0            | 0           | 0           | 0      | 0.0%    | 8MB      |            |
| 1275   | 4s           | 2s          | 3s          | 3s     | 8.9%    | 56MB     |            |
| 2550   | 4s           | 2s          | 3s          | 15s    | 16.1%   | 88MB     |            |
| 5100   | 5s           | 2s          | 3s          | 14s    | 30.6%   | 157MB    |            |
| 10200  | 5s           | 1s          | 10s         | 13s    | 55.5%   | 307MB    |            |
| 20400  | 4s           | 2s          | 11s         | 28s    | 107.5%  | 599MB    |            |
| 40800  | 4s           | 15s         | 30s         | 58s    | 215.1%  | 1162MB   |            |
| 51000  | 4s           | 14s         | 29s         | 59s    | 264.5%  | 1385MB   |            |
| 60280  | 7s           | 10s         | 16s         | 72s    | 317.8%  | 1899MB   | 控制面过载 |

> 说明：
> 1. 初始探测耗时包含 1s 的探测超时时间。
> 2. 测试机 CPU型号为 Intel(R) Xeon(R) CPU E5-2650 v4 @ 2.20GHz。


# 测试日志

**1275 个 RS**

```
[2025-05-12.16:05:35] Starting healthcheck program ...
[2025-05-12.16:05:35] Do Checking ...
[2025-05-12.16:05:35] total: 1275, inhibited: 0
[2025-05-12.16:05:36] total: 1275, inhibited: 0
[2025-05-12.16:05:37] total: 1275, inhibited: 0
[2025-05-12.16:05:38] total: 1275, inhibited: 0
[2025-05-12.16:05:39] total: 1275, inhibited: 37
[2025-05-12.16:05:40] total: 1275, inhibited: 451
[2025-05-12.16:05:41] total: 1275, inhibited: 892
[2025-05-12.16:05:42] total: 1275, inhibited: 1265 
[2025-05-12.16:05:43] total: 1275, inhibited: 1265 
[2025-05-12.16:05:44] total: 1275, inhibited: 1265 
[2025-05-12.16:05:45] total: 1275, inhibited: 1265 
[2025-05-12.16:05:46] total: 1275, inhibited: 1265 
[2025-05-12.16:05:47] total: 1275, inhibited: 1265 
[2025-05-12.16:05:48] total: 1275, inhibited: 1265 
[2025-05-12.16:05:49] total: 1275, inhibited: 1265 
[2025-05-12.16:05:50] total: 1275, inhibited: 1270 
[2025-05-12.16:05:51] total: 1275, inhibited: 1274 
[2025-05-12.16:05:52] total: 1275, inhibited: 1275 
[2025-05-12.16:05:53] total: 1275, inhibited: 1275 
[2025-05-12.16:05:54] total: 1275, inhibited: 1275 
[2025-05-12.16:05:55] total: 1275, inhibited: 1275 
[2025-05-12.16:05:56] total: 1275, inhibited: 1275 
```

**2550 个 RS**

```
[2025-05-12.16:25:36] Starting healthcheck program ...
[2025-05-12.16:25:36] Do Checking ...
[2025-05-12.16:25:36] total: 2550, inhibited: 0
[2025-05-12.16:25:37] total: 2550, inhibited: 0
[2025-05-12.16:25:38] total: 2550, inhibited: 0
[2025-05-12.16:25:39] total: 2550, inhibited: 0
[2025-05-12.16:25:40] total: 2550, inhibited: 140
[2025-05-12.16:25:41] total: 2550, inhibited: 996
[2025-05-12.16:25:42] total: 2550, inhibited: 1875 
[2025-05-12.16:25:43] total: 2550, inhibited: 2473 
[2025-05-12.16:25:44] total: 2550, inhibited: 2473 
[2025-05-12.16:25:45] total: 2550, inhibited: 2473 
[2025-05-12.16:25:46] total: 2550, inhibited: 2473 
[2025-05-12.16:25:47] total: 2550, inhibited: 2473 
[2025-05-12.16:25:48] total: 2550, inhibited: 2473
[2025-05-12.16:25:49] total: 2550, inhibited: 2473
[2025-05-12.16:25:51] total: 2550, inhibited: 2473
[2025-05-12.16:25:52] total: 2550, inhibited: 2513
[2025-05-12.16:25:53] total: 2550, inhibited: 2534
[2025-05-12.16:25:54] total: 2550, inhibited: 2549
[2025-05-12.16:25:55] total: 2550, inhibited: 2550
[2025-05-12.16:25:56] total: 2550, inhibited: 2550
[2025-05-12.16:25:57] total: 2550, inhibited: 2550
[2025-05-12.16:25:58] total: 2550, inhibited: 2550
[2025-05-12.16:25:59] total: 2550, inhibited: 2550
```

**5100 个 RS**

```
[2025-05-12.16:31:50] Starting healthcheck program ...
[2025-05-12.16:31:50] Do Checking ...
[2025-05-12.16:31:50] total: 5100, inhibited: 0
[2025-05-12.16:31:52] total: 5100, inhibited: 0
[2025-05-12.16:31:53] total: 5100, inhibited: 0
[2025-05-12.16:31:54] total: 5100, inhibited: 0
[2025-05-12.16:31:55] total: 5100, inhibited: 546
[2025-05-12.16:31:56] total: 5100, inhibited: 2278 
[2025-05-12.16:31:57] total: 5100, inhibited: 4064 
[2025-05-12.16:31:58] total: 5100, inhibited: 4820 
[2025-05-12.16:31:59] total: 5100, inhibited: 4820 
[2025-05-12.16:32:00] total: 5100, inhibited: 4820 
[2025-05-12.16:32:01] total: 5100, inhibited: 4820 
[2025-05-12.16:32:03] total: 5100, inhibited: 4820 
[2025-05-12.16:32:04] total: 5100, inhibited: 4820
[2025-05-12.16:32:05] total: 5100, inhibited: 4820
[2025-05-12.16:32:06] total: 5100, inhibited: 4991
[2025-05-12.16:32:07] total: 5100, inhibited: 5082
[2025-05-12.16:32:08] total: 5100, inhibited: 5095
[2025-05-12.16:32:09] total: 5100, inhibited: 5100
[2025-05-12.16:32:10] total: 5100, inhibited: 5100
[2025-05-12.16:32:11] total: 5100, inhibited: 5100
[2025-05-12.16:32:12] total: 5100, inhibited: 5100
[2025-05-12.16:32:14] total: 5100, inhibited: 5100
```

**10200 个 RS**

```
[2025-05-12.16:37:42] Starting healthcheck program ...
[2025-05-12.16:37:42] Do Checking ...
[2025-05-12.16:37:42] total: 10200, inhibited: 0
[2025-05-12.16:37:44] total: 10200, inhibited: 0
[2025-05-12.16:37:45] total: 10200, inhibited: 0
[2025-05-12.16:37:46] total: 10200, inhibited: 0
[2025-05-12.16:37:47] total: 10200, inhibited: 1951
[2025-05-12.16:37:48] total: 10200, inhibited: 5856
[2025-05-12.16:37:50] total: 10200, inhibited: 8802
[2025-05-12.16:37:51] total: 10200, inhibited: 8802
[2025-05-12.16:37:52] total: 10200, inhibited: 8802
[2025-05-12.16:37:53] total: 10200, inhibited: 8802
[2025-05-12.16:37:54] total: 10200, inhibited: 8802
[2025-05-12.16:37:56] total: 10200, inhibited: 8802
[2025-05-12.16:37:57] total: 10200, inhibited: 8802
[2025-05-12.16:37:58] total: 10200, inhibited: 9299
[2025-05-12.16:37:59] total: 10200, inhibited: 9919
[2025-05-12.16:38:00] total: 10200, inhibited: 10170
[2025-05-12.16:38:02] total: 10200, inhibited: 10196
[2025-05-12.16:38:03] total: 10200, inhibited: 10196
[2025-05-12.16:38:04] total: 10200, inhibited: 10196
[2025-05-12.16:38:05] total: 10200, inhibited: 10196
[2025-05-12.16:38:06] total: 10200, inhibited: 10196
[2025-05-12.16:38:08] total: 10200, inhibited: 10196
[2025-05-12.16:38:09] total: 10200, inhibited: 10196
[2025-05-12.16:38:10] total: 10200, inhibited: 10196
[2025-05-12.16:38:11] total: 10200, inhibited: 10196
[2025-05-12.16:38:12] total: 10200, inhibited: 10196
[2025-05-12.16:38:14] total: 10200, inhibited: 10199
[2025-05-12.16:38:15] total: 10200, inhibited: 10200
[2025-05-12.16:38:16] total: 10200, inhibited: 10200
[2025-05-12.16:38:17] total: 10200, inhibited: 10200
[2025-05-12.16:38:18] total: 10200, inhibited: 10200
[2025-05-12.16:38:19] total: 10200, inhibited: 10200
```

**20400 个 RS**

```
[2025-05-12.17:27:28] Starting healthcheck program ...
[2025-05-12.17:27:28] Do Checking ...
[2025-05-12.17:27:28] total: 20400, inhibited: 0
[2025-05-12.17:27:29] total: 20400, inhibited: 0
[2025-05-12.17:27:30] total: 20400, inhibited: 0
[2025-05-12.17:27:32] total: 20400, inhibited: 1418
[2025-05-12.17:27:34] total: 20400, inhibited: 12007 
[2025-05-12.17:27:35] total: 20400, inhibited: 15979 
[2025-05-12.17:27:37] total: 20400, inhibited: 15979 
[2025-05-12.17:27:38] total: 20400, inhibited: 15979 
[2025-05-12.17:27:39] total: 20400, inhibited: 15979 
[2025-05-12.17:27:41] total: 20400, inhibited: 15979 
[2025-05-12.17:27:42] total: 20400, inhibited: 15979 
[2025-05-12.17:27:43] total: 20400, inhibited: 18208 
[2025-05-12.17:27:45] total: 20400, inhibited: 19958
[2025-05-12.17:27:46] total: 20400, inhibited: 20349
[2025-05-12.17:27:48] total: 20400, inhibited: 20350
[2025-05-12.17:27:49] total: 20400, inhibited: 20350
[2025-05-12.17:27:50] total: 20400, inhibited: 20350
[2025-05-12.17:27:52] total: 20400, inhibited: 20350
[2025-05-12.17:27:53] total: 20400, inhibited: 20350
[2025-05-12.17:27:55] total: 20400, inhibited: 20350
[2025-05-12.17:27:56] total: 20400, inhibited: 20350
[2025-05-12.17:27:57] total: 20400, inhibited: 20350
[2025-05-12.17:27:59] total: 20400, inhibited: 20384
[2025-05-12.17:28:00] total: 20400, inhibited: 20400
[2025-05-12.17:28:01] total: 20400, inhibited: 20400
[2025-05-12.17:28:03] total: 20400, inhibited: 20400
[2025-05-12.17:28:04] total: 20400, inhibited: 20400
[2025-05-12.17:28:06] total: 20400, inhibited: 20400
```

**40800 个 RS**

```
[2025-05-12.17:44:33] Starting healthcheck program ...
[2025-05-12.17:44:33] Do Checking ...
[2025-05-12.17:44:33] total: 40800, inhibited: 0
[2025-05-12.17:44:34] total: 40800, inhibited: 0
[2025-05-12.17:44:36] total: 40800, inhibited: 0
[sockopt_msg_recv] errcode set in socket msg#21 header: msg callback failed(-23)
Success
[2025-05-12.17:44:38] total: 40800, inhibited: 2363
[2025-05-12.17:44:41] total: 40800, inhibited: 5784
[2025-05-12.17:44:43] total: 40800, inhibited: 5784
[2025-05-12.17:44:44] total: 40800, inhibited: 5784
[2025-05-12.17:44:46] total: 40800, inhibited: 5784
[2025-05-12.17:44:48] total: 40800, inhibited: 7271
[2025-05-12.17:44:50] total: 40800, inhibited: 17583 
[2025-05-12.17:44:52] total: 40800, inhibited: 28485
[2025-05-12.17:44:54] total: 40800, inhibited: 29354
[2025-05-12.17:44:56] total: 40800, inhibited: 29354
[2025-05-12.17:44:57] total: 40800, inhibited: 29354
[2025-05-12.17:44:59] total: 40800, inhibited: 29354
[2025-05-12.17:45:01] total: 40800, inhibited: 29354
[2025-05-12.17:45:03] total: 40800, inhibited: 29379
[2025-05-12.17:45:04] total: 40800, inhibited: 30648
[2025-05-12.17:45:07] total: 40800, inhibited: 37525
[2025-05-12.17:45:08] total: 40800, inhibited: 37591
[2025-05-12.17:45:10] total: 40800, inhibited: 37591
[2025-05-12.17:45:12] total: 40800, inhibited: 37591
[2025-05-12.17:45:14] total: 40800, inhibited: 37591
[2025-05-12.17:45:15] total: 40800, inhibited: 37591
[2025-05-12.17:45:17] total: 40800, inhibited: 37591
[sockopt_msg_recv] errcode set in socket msg#21 header: msg callback failed(-23)
Success
[2025-05-12.17:45:19] total: 32505, inhibited: 39290
[2025-05-12.17:45:21] total: 40800, inhibited: 40731
[2025-05-12.17:45:23] total: 40800, inhibited: 40750
[2025-05-12.17:45:24] total: 40800, inhibited: 40750
[2025-05-12.17:45:26] total: 40800, inhibited: 40750
[2025-05-12.17:45:28] total: 40800, inhibited: 40750
[2025-05-12.17:45:30] total: 40800, inhibited: 40750
[2025-05-12.17:45:31] total: 40800, inhibited: 40750
[2025-05-12.17:45:33] total: 40800, inhibited: 40750
[2025-05-12.17:45:35] total: 40800, inhibited: 40800
[2025-05-12.17:45:37] total: 40800, inhibited: 40800
[2025-05-12.17:45:39] total: 40800, inhibited: 40800
[2025-05-12.17:45:40] total: 40800, inhibited: 40800
[2025-05-12.17:45:42] total: 40800, inhibited: 40800
```

**51000 个 RS**

```
[2025-05-12.18:07:15] Starting healthcheck program ...
[2025-05-12.18:07:15] Do Checking ...
[2025-05-12.18:07:15] total: 51000, inhibited: 0
[2025-05-12.18:07:17] total: 51000, inhibited: 0
[2025-05-12.18:07:19] total: 51000, inhibited: 628
[2025-05-12.18:07:21] total: 51000, inhibited: 3511
[2025-05-12.18:07:25] total: 51000, inhibited: 8556
[2025-05-12.18:07:27] total: 51000, inhibited: 8556
[2025-05-12.18:07:29] total: 51000, inhibited: 8556
[2025-05-12.18:07:31] total: 51000, inhibited: 17916 
[2025-05-12.18:07:33] total: 51000, inhibited: 29641 
[2025-05-12.18:07:36] total: 51000, inhibited: 41320 
[2025-05-12.18:07:38] total: 51000, inhibited: 41382 
[2025-05-12.18:07:40] total: 51000, inhibited: 41382
[2025-05-12.18:07:42] total: 51000, inhibited: 41382
[2025-05-12.18:07:44] total: 51000, inhibited: 41382
[2025-05-12.18:07:46] total: 51000, inhibited: 41652
[2025-05-12.18:07:48] total: 51000, inhibited: 45486
[2025-05-12.18:07:50] total: 51000, inhibited: 48332
[2025-05-12.18:07:52] total: 51000, inhibited: 48332
[2025-05-12.18:07:54] total: 51000, inhibited: 48332
[2025-05-12.18:07:56] total: 51000, inhibited: 48332
[2025-05-12.18:07:58] total: 51000, inhibited: 48332
[2025-05-12.18:08:00] total: 51000, inhibited: 48332
[2025-05-12.18:08:02] total: 51000, inhibited: 50480
[2025-05-12.18:08:04] total: 51000, inhibited: 50989
[2025-05-12.18:08:06] total: 51000, inhibited: 50989
[2025-05-12.18:08:08] total: 51000, inhibited: 50989
[2025-05-12.18:08:10] total: 51000, inhibited: 50989
[2025-05-12.18:08:12] total: 51000, inhibited: 50989
[2025-05-12.18:08:14] total: 51000, inhibited: 50989
[2025-05-12.18:08:16] total: 51000, inhibited: 50989
[2025-05-12.18:08:18] total: 51000, inhibited: 51000
[2025-05-12.18:08:20] total: 51000, inhibited: 51000
[2025-05-12.18:08:22] total: 51000, inhibited: 51000
[2025-05-12.18:08:24] total: 51000, inhibited: 51000
[2025-05-12.18:08:26] total: 51000, inhibited: 51000
```

**60280 个 RS**

```
[2025-05-12.17:12:57] Starting healthcheck program ...
[2025-05-12.17:12:57] Do Checking ...
[2025-05-12.17:12:57] total: 60280, inhibited: 0
[2025-05-12.17:12:59] total: 60280, inhibited: 0
[sockopt_msg_recv] errcode set in socket msg#21 header: msg callback failed(-23)
Success
[sockopt_msg_recv] errcode set in socket msg#21 header: msg callback failed(-23)
Success
[2025-05-12.17:13:02] total: 20535, inhibited: 80
[sockopt_msg_recv] errcode set in socket msg#21 header: msg callback failed(-23)
Success
[sockopt_msg_recv] errcode set in socket msg#21 header: msg callback failed(-23)
Success
[2025-05-12.17:13:04] total: 12370, inhibited: 217
[2025-05-12.17:13:06] total: 60280, inhibited: 7778
[2025-05-12.17:13:09] total: 60280, inhibited: 7778
[2025-05-12.17:13:12] total: 60280, inhibited: 10078 
[sockopt_msg_recv] errcode set in socket msg#21 header: msg callback failed(-23)
Success
[2025-05-12.17:13:14] total: 21745, inhibited: 36798 
[sockopt_msg_recv] errcode set in socket msg#21 header: msg callback failed(-23)
Success
[2025-05-12.17:13:18] total: 40140, inhibited: 47912 
[2025-05-12.17:13:21] total: 60280, inhibited: 48056 
[2025-05-12.17:13:23] total: 60280, inhibited: 48056
[2025-05-12.17:13:25] total: 60280, inhibited: 48056
[sockopt_msg_recv] errcode set in socket msg#21 header: msg callback failed(-23)
[2025-05-12.17:13:28] total: 60280, inhibited: 39482
[2025-05-12.17:13:30] total: 60280, inhibited: 55065
[2025-05-12.17:13:33] total: 60280, inhibited: 56066
[2025-05-12.17:13:36] total: 60280, inhibited: 56066
[2025-05-12.17:13:38] total: 60280, inhibited: 56066
[2025-05-12.17:13:41] total: 60280, inhibited: 56066
[sockopt_msg_recv] errcode set in socket msg#21 header: msg callback failed(-23)
Success
[2025-05-12.17:13:43] total: 60280, inhibited: 38237
[2025-05-12.17:13:45] total: 60280, inhibited: 58302
[2025-05-12.17:13:48] total: 60280, inhibited: 58393
[2025-05-12.17:13:50] total: 60280, inhibited: 58393
[2025-05-12.17:13:53] total: 60280, inhibited: 58393
[2025-05-12.17:13:55] total: 60280, inhibited: 58393
[2025-05-12.17:13:58] total: 60280, inhibited: 58393
[2025-05-12.17:14:00] total: 60280, inhibited: 60243
[2025-05-12.17:14:03] total: 60280, inhibited: 60245
[2025-05-12.17:14:06] total: 60280, inhibited: 60245
[2025-05-12.17:14:08] total: 60280, inhibited: 60245
[2025-05-12.17:14:11] total: 60280, inhibited: 60245
[2025-05-12.17:14:13] total: 60280, inhibited: 60245
[2025-05-12.17:14:16] total: 60280, inhibited: 60280
[2025-05-12.17:14:18] total: 60280, inhibited: 60280
[2025-05-12.17:14:21] total: 60280, inhibited: 60280
[2025-05-12.17:14:23] total: 60280, inhibited: 60280
[2025-05-12.17:14:26] total: 60280, inhibited: 60280
```

# 结论

1. 健康检查程序最大处理能力约为 5000 RS/s；
2. RS 状态变化不超过 5000 RS/s 时，健康检查程序能够快速摘除或恢复故障的 RS；
3. RS 状态变化 10000 RS/s 时，健康检查程序大约可以 10s 摘除或恢复故障的 RS；
4. 可以支持 40000+ RS/s 的 RS 状态变化，但约 50% 的 RS 故障可能得不到及时发现；
5. 每 10000 RS 的约占用 0.5核 CPU 和 300MB 内存，且 CPU、内存用量与 RS 数量成良好的线性关系。

此外，在 50000+ 个 RS 配置处于健康状态稳定的场景下，单个 RS 故障的摘除和恢复时间约为 5s，与只有此 1 个 RS 配置时的处理时间区别不大。

> 说明: 
> 1. 测试过程中 DPVS 服务无数据面流量。
> 2. dpvs-agent 的API接口性能是测试数据出现长尾效应的主要原因，对测试结果有一定的影响，尤其是 RS 超过 40000+ 时。
