DPVS v1.7.2 功能测试结果
------------------------
- IPv4 协议栈测试
  * [Y] DPVS IPv4 地址添加、查询、删除
  * [Y] DPVS IPv4 路由添加、查询、删除
  * [Y] DPVS IPv4 ARP 缓存表正常
  * [Y] DPVS IPv4 地址能 ping 通

- IPv6 协议栈测试
  * [Y] DPVS IPv6 地址添加、查询、删除
  * [Y] DPVS IPv6 路由添加、查询、删除
  * [Y] DPVS IPv6 ARP 缓存表正常
  * [Y] DPVS IPv6 地址能 ping 通

- DPVS FullNAT 转发测试
  * [Y] ipvsadm 业务添加、查询、修改、删除
  * [Y] keepalive 业务添加、查询、修改、删除
  - TCP 协议数据转发
    * [Y] 4to4 转发
    * [Y] 6to6 转发
    * [Y] 6to4 转发
  - TCP synproxy 功能
    * [Y] 4to4 转发
    * [Y] 6to6 转发
    * [Y] 6to4 转发
  - TOA Centos 7
    * [Y] 源 IP、端口获取功能(4to4, 6to6, 6to4) -- 6to4 apache可以直接获取源IP，nginx需要patch
    * [Y] toa.ko 加载测试
    * [Y] toa.ko 卸载测试（有流量时）
    * [Y] toa.ko 版本前向兼容测试 -- nginx兼容，apache关闭IPv6后不兼容
  - TOA Centos 6
    * [Y] 源 IP、端口 获取功能(4to4, 6to6, 6to4) -- 6to6无环境未测试，6to4 nginx需要patch
    * [Y] toa.ko 加载测试
    * [Y] toa.ko 卸载测试（有流量时）
    * [Y] toa.ko 版本前向兼容测试
  - UDP 协议数据转发（无 UOA 数据）
    * [Y] 4to4 转发
    * [Y] 6to6 转发
    * [Y] 6to4 转发
  - UOA Centos 7
    * [Y] 源 IP、端口获取功能(4to4, 6to6, 6to4)
    * [Y] uoa.ko 加载测试
    * [Y] uoa.ko 卸载测试（有流量时）
    * [N] uoa.ko 版本前向兼容测试 -- 不兼容 v1.6 版本 uoa.ko，无法获取源 IP、带 UOA 的 UDP 包被丢弃（4to4 未丢）
  - UOA Centos 6
    * [Y] 源 IP、端口获取功能(4to4, 6to4)
    * [Y] uoa.ko 加载测试
    * [Y] uoa.ko 卸载测试（有流量时）
    * [N] uoa.ko 版本前向兼容测试 -- 不兼容 v1.6 版本 uoa.ko，无法获取源 IP、带 UOA 的 UDP 包被丢弃（4to4 未丢）
  - Flow Director 测试
    * [Y] Perfect 模式、一个或多个 Local IP (4to4, 6to4)
    * [N] Perfect 模式、一个或多个 Local IP (6to6) -- 网卡不支持
    * [Y] Signature 模式、一个 Local IP (4to4, 6to6, 6to4)
    * [N] Signature 模式、多个 Local IP (4to4, 6to6, 6to4) -- 网卡不支持
    * [Y] Signature 模式、多个 Local IP、打开 packet redirect (4to4, 6to6, 6to4)


- DPVS SNAT 转发测试
  * [Y] ipvsadm 业务添加、查询、修改、删除
  * [Y] keepalived 业务添加、查询、修改、删除
  * [Y] ICMP 转发
  * [Y] TCP 转发
  * [Y] UDP 转发
  * [Y] ICMP 隧道上网
  * [Y] TCP 隧道上网
  * [Y] UDP 隧道上网

- DPVS DR 转发测试
  - TCP 协议数据转发
    * [Y] 4to4 转发
    * [Y] 6to6 转发
    * [N] 6to4 转发 -- 原理上不支持
  - UDP 协议数据转发
    * [Y] 4to4 转发
    * [Y] 6to6 转发
    * [N] 6to4 转发 -- 原理上不支持

- DPVS Tunnel 转发测试
  - TCP 协议数据转发
    * [Y] 4to4 转发
    * [Y] 6to6 转发
    * [N] 6to4 转发 -- 原理上不支持
  - UDP 协议数据转发
    * [Y] 4to4 转发
    * [Y] 6to6 转发
    * [N] 6to4 转发 -- 原理上不支持

- DPVS NAT 转发测试(单核，或多核打开redirect)
  - TCP 协议数据转发
    * [Y] 4to4 转发
    * [Y] 6to6 转发
    * [N] 6to4 转发 -- 原理上不支持
  - UDP 协议数据转发
    * [Y] 4to4 转发
    * [Y] 6to6 转发
    * [N] 6to4 转发 -- 原理上不支持

-------------------
Note:
   * [Y]: Test Passed
   * [N]: Test Failed or Not Supported
