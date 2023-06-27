DPVS 健康检查程序压力测试
---

# 测试方法

首先，使用 [stress-test.sh](./stress-test.sh) 脚本生成测试业务。

* 测试业务列表只需要有 VS 和 RS 配置，不需要配置 VIP、local IP 等。
* 通过调整脚本 `Step 2` 中的 i, j 两个循环控制变量的范围控制产生的健康检查配置数量的多少。
* 通过调整脚本 `Step 2` 中循环控制变量 j 的范围控制每个 VS 下配置的 RS 数量的多少，默认每个 VS 配置 5 个 RS。

测试业务生成后 RS 初始状态都是 UP（权重为1）：

```
## 未启动健康检查服务时测试业务状态
IP Virtual Server version 1.9.4 (size=0)
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port           Forward Weight ActiveConn InActConn
TCP  192.168.0.1:80 wlc
  -> 192.168.19.155:8080          FullNat 1      0          0          
  -> 192.168.19.156:8080          FullNat 1      0          0          
  -> 192.168.19.157:8080          FullNat 1      0          0          
  -> 192.168.19.158:8080          FullNat 1      0          0          
  -> 192.168.19.159:8080          FullNat 1      0          0          
TCP  192.168.0.2:80 wlc
  -> 192.168.19.160:8080          FullNat 1      0          0          
  -> 192.168.19.161:8080          FullNat 1      0          0          
  -> 192.168.19.162:8080          FullNat 1      0          0          
  -> 192.168.19.163:8080          FullNat 1      0          0          
  -> 192.168.19.164:8080          FullNat 1      0          0          
TCP  192.168.0.3:80 wlc
  -> 192.168.19.165:8080          FullNat 1      0          0          
  -> 192.168.19.166:8080          FullNat 1      0          0          
...
```

但实际上这些 RS 是不通的，后续健康检查程序会把所有的 RS 设置为 DOWN（权重为 0，并添加  标志）。

```
## 健康检查完成测试业务状态
IP Virtual Server version 1.9.4 (size=0)
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port           Forward Weight ActiveConn InActConn
TCP  192.168.0.1:80 wlc
  -> 192.168.19.155:8080          FullNat 0      0          0          inhibited
  -> 192.168.19.156:8080          FullNat 0      0          0          inhibited
  -> 192.168.19.157:8080          FullNat 0      0          0          inhibited
  -> 192.168.19.158:8080          FullNat 0      0          0          inhibited
  -> 192.168.19.159:8080          FullNat 0      0          0          inhibited
TCP  192.168.0.2:80 wlc
  -> 192.168.19.160:8080          FullNat 0      0          0          inhibited
  -> 192.168.19.161:8080          FullNat 0      0          0          inhibited
  -> 192.168.19.162:8080          FullNat 0      0          0          inhibited
  -> 192.168.19.163:8080          FullNat 0      0          0          inhibited
  -> 192.168.19.164:8080          FullNat 0      0          0          inhibited
TCP  192.168.0.3:80 wlc
  -> 192.168.19.165:8080          FullNat 0      0          0          inhibited
  -> 192.168.19.166:8080          FullNat 0      0          0          inhibited
...
```

测试业务创建后，`stress-test.sh` 脚本会循环检测当前的 RS 总数和被置为 DOWN 状态的 RS 数量。当我们启动健康检查程序后，

```sh
./healthcheck -log_dir=./log
```

测试业务的 RS 会陆续由初始的 UP 状态而转为 DOWN 状态，我们根据 RS 被置为 DOWN 的数量的增长速度即可评估健康检查程序的并发性能。

# 测试数据

* RS 数量：测试脚本自动创建的 RS 总量
* 初始探测耗时：健康检查程序启动到看到第一个 RS 被置为 DOWN 的时间。
* 耗时(5分位)：从第一个 RS 被置为 DOWN 到 50% 的 RS 被置为 DOWN 的时间。
* 耗时(9分位)：从第一个 RS 被置为 DOWN 到 90% 的 RS 被置为 DOWN 的时间。
* 总耗时：从第一个 RS 被置为 DOWN 到所有的 RS 被置为 DOWN 的时间。
* CPU 占用：健康检查程序的 CPU 使用量（用 iftop 命令观测得到）。
* 内存占用：健康检查程序的内存使用量（用 iftop 命令观测得到）。

| RS数量 | 初始探测耗时 | 耗时(5分位） | 耗时(9分位) | 总耗时 | CPU占用 | 内存占用 |
| ------ | ------------ | ------------ | ----------- | ------ | ------- | -------- |
| 0      | 0            | 0            | 0           | 0      | 0.1核   | 100MB    |
| 1040   | 6s           | 1s           | 2s          | 2s     | 0.1核   | 110MB    |
| 5080   | 6s           | 1s           | 2s          | 3s     | 0.4核   | 160MB    |
| 10160  | 5s           | 4s           | 6s          | 8s     | 0.8核   | 200MB    |
| 26670  | 5s           | 9s           | 16s         | 34s    | 1.8核   | 560MB    |
| 52070  | 7s           | 7s           | 33s         | 90s    | 4.4核   | 1120MB   |

> 说明： 健康检查程序默认配置的 retry 为 1 次、timeout 为 1s、周期为 3s，因此初始探测时间理论上为 1s(timeout) + 3s (delay loop) + 1s (timeout) = 5s。该数据和我们测试数据基本一致，不计入性能延迟。


# 测试日志

**1040 个 RS**

```
[2023-06-02.17:08:51] total: 1040, inhibited: 0
[2023-06-02.17:08:55] total: 1040, inhibited: 0
[2023-06-02.17:08:56] total: 1040, inhibited: 0
[2023-06-02.17:08:57] total: 1040, inhibited: 0
[2023-06-02.17:08:58] total: 1040, inhibited: 321 
[2023-06-02.17:08:59] total: 1040, inhibited: 709 
[2023-06-02.17:09:00] total: 1040, inhibited: 1040
[2023-06-02.17:09:01] total: 1040, inhibited: 1040
[2023-06-02.17:09:02] total: 1040, inhibited: 1040
[2023-06-02.17:09:03] total: 1040, inhibited: 1040
```

**5080 个 RS**

```
[2023-06-02.17:02:17] total: 5080, inhibited: 0
[2023-06-02.17:02:18] total: 5080, inhibited: 0
[2023-06-02.17:02:19] total: 5080, inhibited: 0
[2023-06-02.17:02:20] total: 5080, inhibited: 0
[2023-06-02.17:02:21] total: 5080, inhibited: 1474
[2023-06-02.17:02:22] total: 5080, inhibited: 3340
[2023-06-02.17:02:23] total: 5080, inhibited: 5078
[2023-06-02.17:02:25] total: 5080, inhibited: 5080
[2023-06-02.17:02:26] total: 5080, inhibited: 5080
[2023-06-02.17:02:27] total: 5080, inhibited: 5080
[2023-06-02.17:02:28] total: 5080, inhibited: 5080
```

**10160 个 RS**

```
[2023-06-02.16:51:21] total: 10160, inhibited: 0
[2023-06-02.16:51:23] total: 10160, inhibited: 0
[2023-06-02.16:51:24] total: 10160, inhibited: 0
[2023-06-02.16:51:25] total: 10160, inhibited: 0
[2023-06-02.16:51:27] total: 10160, inhibited: 0
[2023-06-02.16:51:28] total: 10160, inhibited: 52
[2023-06-02.16:51:29] total: 10160, inhibited: 2050
[2023-06-02.16:51:30] total: 10160, inhibited: 4021
[2023-06-02.16:51:32] total: 10160, inhibited: 6027
[2023-06-02.16:51:33] total: 10160, inhibited: 8094
[2023-06-02.16:51:34] total: 10160, inhibited: 10116
[2023-06-02.16:51:36] total: 10160, inhibited: 10160
[2023-06-02.16:51:37] total: 10160, inhibited: 10160
[2023-06-02.16:51:38] total: 10160, inhibited: 10160
[2023-06-02.16:51:39] total: 10160, inhibited: 10160
```

**26670 个 RS**

```
[2023-06-02.16:44:45] total: 26670, inhibited: 0
[2023-06-02.16:44:46] total: 26670, inhibited: 0
[2023-06-02.16:44:48] total: 26670, inhibited: 0
[2023-06-02.16:44:50] total: 26670, inhibited: 0
[2023-06-02.16:44:51] total: 26670, inhibited: 0
[2023-06-02.16:44:53] total: 26670, inhibited: 1857
[2023-06-02.16:44:55] total: 26670, inhibited: 4389
[2023-06-02.16:44:56] total: 26670, inhibited: 6887
[2023-06-02.16:44:58] total: 26670, inhibited: 9388
[2023-06-02.16:45:00] total: 26670, inhibited: 12166
[2023-06-02.16:45:02] total: 26670, inhibited: 15079
[2023-06-02.16:45:03] total: 26670, inhibited: 17741
[2023-06-02.16:45:05] total: 26670, inhibited: 20307
[2023-06-02.16:45:07] total: 26670, inhibited: 23046
[2023-06-02.16:45:09] total: 26670, inhibited: 25967
[2023-06-02.16:45:10] total: 26670, inhibited: 26665
[2023-06-02.16:45:12] total: 26670, inhibited: 26665
[2023-06-02.16:45:14] total: 26670, inhibited: 26666
[2023-06-02.16:45:16] total: 26670, inhibited: 26667
[2023-06-02.16:45:18] total: 26670, inhibited: 26667
[2023-06-02.16:45:19] total: 26670, inhibited: 26667
[2023-06-02.16:45:21] total: 26670, inhibited: 26668
[2023-06-02.16:45:23] total: 26670, inhibited: 26669
[2023-06-02.16:45:25] total: 26670, inhibited: 26669
[2023-06-02.16:45:26] total: 26670, inhibited: 26670
[2023-06-02.16:45:28] total: 26670, inhibited: 26670
[2023-06-02.16:45:30] total: 26670, inhibited: 26670
[2023-06-02.16:45:32] total: 26670, inhibited: 26670
[2023-06-02.16:45:34] total: 26670, inhibited: 26670
```

**52070 个 RS**

```
[2023-06-02.16:37:39] total: 52070, inhibited: 0
[2023-06-02.16:37:42] total: 52070, inhibited: 0
[2023-06-02.16:37:44] total: 52070, inhibited: 0
[2023-06-02.16:37:46] total: 52070, inhibited: 0
[2023-06-02.16:37:48] total: 52070, inhibited: 1
[2023-06-02.16:37:51] total: 52070, inhibited: 3032
[2023-06-02.16:37:53] total: 52070, inhibited: 6743
[2023-06-02.16:37:55] total: 52070, inhibited: 10129
[2023-06-02.16:37:58] total: 52070, inhibited: 13849
[2023-06-02.16:38:00] total: 52070, inhibited: 17478
[2023-06-02.16:38:03] total: 52070, inhibited: 21177
[2023-06-02.16:38:05] total: 52070, inhibited: 25168
[2023-06-02.16:38:08] total: 52070, inhibited: 28867
[2023-06-02.16:38:10] total: 52070, inhibited: 32909
[2023-06-02.16:38:13] total: 52070, inhibited: 37034
[2023-06-02.16:38:16] total: 52070, inhibited: 40798
[2023-06-02.16:38:18] total: 52070, inhibited: 44471
[2023-06-02.16:38:21] total: 52070, inhibited: 48355
[2023-06-02.16:38:23] total: 52070, inhibited: 51830
[2023-06-02.16:38:26] total: 52070, inhibited: 52025
[2023-06-02.16:38:29] total: 52070, inhibited: 52030
[2023-06-02.16:38:31] total: 52070, inhibited: 52034
[2023-06-02.16:38:34] total: 52070, inhibited: 52035
[2023-06-02.16:38:36] total: 52070, inhibited: 52035
[2023-06-02.16:38:39] total: 52070, inhibited: 52035
[2023-06-02.16:38:41] total: 52070, inhibited: 52035
[2023-06-02.16:38:44] total: 52070, inhibited: 52035
[2023-06-02.16:38:46] total: 52070, inhibited: 52035
[2023-06-02.16:38:49] total: 52070, inhibited: 52035
[2023-06-02.16:38:51] total: 52070, inhibited: 52037
[2023-06-02.16:38:53] total: 52070, inhibited: 52042
[2023-06-02.16:38:56] total: 52070, inhibited: 52042
[2023-06-02.16:38:58] total: 52070, inhibited: 52047
[2023-06-02.16:39:01] total: 52070, inhibited: 52049
[2023-06-02.16:39:03] total: 52070, inhibited: 52052
[2023-06-02.16:39:06] total: 52070, inhibited: 52053
[2023-06-02.16:39:08] total: 52070, inhibited: 52057
[2023-06-02.16:39:11] total: 52070, inhibited: 52060
[2023-06-02.16:39:13] total: 52070, inhibited: 52060
[2023-06-02.16:39:16] total: 52070, inhibited: 52065
[2023-06-02.16:39:18] total: 52070, inhibited: 52070
[2023-06-02.16:39:21] total: 52070, inhibited: 52070
[2023-06-02.16:39:23] total: 52070, inhibited: 52070
[2023-06-02.16:39:25] total: 52070, inhibited: 52070
[2023-06-02.16:39:28] total: 52070, inhibited: 52070
```

# 结论

1. 健康检查程序处理能力约为 3000 RS/s；
2. RS 状态变化不超过 5000 RS/s 时，健康检查程序能够快速摘除或恢复故障的 RS；
3. RS 状态变化 10000 RS/s 时，健康检查程序可以在 8s 内摘除或恢复故障的 RS；
3. 可以支持 50000+ RS/s 的 RS 状态变化，但约 50% 的 RS 故障可能得不到及时发现。

此外，在 50000+ 个 RS 配置处于健康状态稳定的场景下，单个 RS 故障的摘除和恢复时间约为 5s，与只有此 1 个 RS 配置时的处理时间区别不大。

> 说明: 以上结论采用健康检查程序默认配置时测试得到，测试过程中 DPVS 服务无数据面流量。
