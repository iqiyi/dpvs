## 级别界定

* P1: 线上广泛使用的核心功能，或影响服务可用性的稳定性指标、或核心性能指标
* P2: 线上小范围使用的重要功能，或重要的性能指标
* P3: 一般功能或性能指标
* P4: 不重要的功能或性能指标

## 测试案例

- 设备和接口
  - [ ] P1: bonding mode 0
  - [ ] P1: bonding mode 4
  - [ ] P4: bonding mode 1,2,3,5,6
  - [ ] P1: vlan
  - [ ] P1: bonding + vlan
  - [ ] P1: gre tunnel
  - [ ] P3: ipip tunnel
  - [ ] P1: bonding + gre tunnel
  - [ ] P1: bonding + vlan + gre tunnel
  - [ ] P1: kni
  - [ ] P1: bonding + kni
  - [ ] P1: vlan + kni
  - [ ] P1: bonding + vlan + kni
  - [ ] P2: kni ipv4 mac 多播地址同步
  - [ ] P2: kni ipv6 mac 多播地址同步

- IPv4 协议栈
  - [ ] P1: DPVS IPv4 地址添加、查询、删除
  - [ ] P1: DPVS IPv4 路由添加、查询、删除
  - [ ] P1: DPVS IPv4 ARP 缓存表添加、查询、删除
  - [ ] P1: DPVS IPv4 地址能 ping 通
  - [ ] P1: DPVS IPv4 LIP/SAPOOL 添加、查询、删除
  - [ ] P3: DPVS IPv4 ping 延时及稳定性
  - [ ] P4: DPVS IPv4 forward 功能
  - [ ] P4: DPVS IPv4 分片收集功能
  - [ ] P4: DPVS IPv4 traceroute 支持

- IPv6 协议栈
  - [ ] P1: DPVS IPv6 地址添加、查询、删除
  - [ ] P1: DPVS IPv6 路由添加、查询、删除
  - [ ] P1: DPVS IPv6 ARP 缓存表添加、查询、删除
  - [ ] P1: DPVS IPv6 地址能 ping 通
  - [ ] P2: DPVS IPv6 LIP/SAPOOL 添加、查询、删除
  - [ ] P3: DPVS IPv6 ping 延时及稳定性
  - [ ] P4: DPVS IPv6 forward 功能
  - [ ] P3: DPVS IPv6 协议栈开关
  - [ ] P4: DPVS IPv6 traceroute 支持

- IPVS 转发功能
  - [ ] P1: FullNAT TCP 4to4 转发
  - [ ] P1: FullNAT TCP 6to4 转发
  - [ ] P2: FullNAT TCP 6to6 转发
  - [ ] P1: TCP synproxy 转发
  - [ ] P1: TCP establish_timeout 超时时间设置
  - [ ] P1: FullNAT UDP 4to4 转发
  - [ ] P2: FullNAT UDP 6to4 转发
  - [ ] P3: FullNAT UDP 6to6 转发
  - [ ] P1: 连接保持 persistent 功能
  - [ ] P3: 连接保持 persistent + expire_quiescent_template 功能
  - [ ] P2: 黑名单功能
  - [ ] P3: defence_udp_drop 功能
  - [ ] P3: defence_tcp_drop 功能
  - [ ] P1: SNAT TCP/UDP ipv4 转发
  - [ ] P1: SNAT ICMP ipv4 转发（打开redirect）
  - [ ] P1: Tunnel 4to4 转发
  - [ ] P3: Tunnel 6to6 转发
  - [ ] P2: DR 4to4 转发
  - [ ] P3: DR 6to6 转发
  - [ ] P2: NAT 4to4 转发（单核或者打开redirect）
  - [ ] P3: NAT 6to6 转发（单核或者打开redirect）
  - [ ] P4：DPVS 转发关联的 ICMP 错误报文（ICMP_DEST_UNREACH,ICMP_SOURCE_QUENCH,ICMP_TIME_EXCEEDED）转发
  - [ ] P2: 高并发测试时 local IP/Port 使用均匀性
  - [ ] P2: 大流量时数据包在各个 Worker CPU 上分布的均匀性
  - [ ] P3: FullNat/DR/Tunnel/SNAT 四种转发业务配置在一个 DPVS 测试
  - [ ] P3: 200个转发业务配置测试
  - [ ] P4: 1000个转发业务配置测试

- IPVS 调度算法
  - [ ] P1: rr
  - [ ] P1: wrr
  - [ ] P1: wlc
  - [ ] P2: conhash

- TOA/UOA 内核模块
  - [ ] P1: TOA 在不同版本内核上加载、卸载稳定性（使用中测试）
  - [ ] P1: TOA 4to4 功能验证
  - [ ] P1: TOA 6to4 功能验证
  - [ ] P3: TOA 6to6 功能验证
  - [ ] P2: TOA 版本前向兼容性测试
  - [ ] P1: UOA 在不同版本内核上加载、卸载稳定性（使用中测试）
  - [ ] P1: UOA 4to4 功能验证
  - [ ] P2: UOA 6to4 功能验证
  - [ ] P3: UOA 6to6 功能验证
  - [ ] P2: UOA 版本前向兼容性测试

- dpip 工具
  - [ ] P1: 网卡基本信息、统计信息、详细信息查看
  - [ ] P1: Cpu worker 基本信息、统计信息、详细信息查看
  - [ ] P4: 网卡、Cpu worker 统计信息清零
  - [ ] P2: 网卡混杂模式设置
  - [ ] P3: forward2kni 设置
  - [ ] P2: 网卡 link up/down 设置
  - [ ] P1: ipv4 地址配置、查询、删除（包含local IP）
  - [ ] P1: ipv6 地址配置、查询、删除（包含local IP)
  - [ ] P3: 清除网卡上所有 IP 地址
  - [ ] P1: ipv4 主机路由、网关路由、kni 路由、默认路由配置、查询、删除
  - [ ] P1: ipv6 主机路由、网关路由、kni 路由、默认路由配置、查询、删除
  - [ ] P2: ipv4/ipv6 路由表清空功能
  - [ ] P3: table outwall 路由功能
  - [ ] P1: arp 缓存表查找
  - [ ] P2: arp 静态表项添加、删除
  - [ ] P1: vlan 接口添加、查询、删除
  - [ ] P1: tunnel 接口添加、查询、删除
  - [ ] P3: ipv6 包统计信息查询
  - [ ] P4: 限流功能配置、查询、删除

- ipvsadm 工具
  - [ ] P1: 添加、修改、查询、删除 FullNat/DR/Tunnel 转发业务
  - [ ] P1: 添加、修改、查询、删除 SNAT MATCH 转发业务
  - [ ] P1: 查询、重置统计数据
  - [ ] P2: 查询、修改、删除指定业务配置
  - [ ] P2: 查询、修改、删除指定业务 Local IP
  - [ ] P2: synproxy 配置功能
  - [ ] P2: persistent连接配置功能
  - [ ] P2: 所有 IPVS 调度算法配置、修改功能
  - [ ] P2: IPVS 全量会话查询功能
  - [ ] P3: IPVS 指定会话查询功能
  - [ ] P3: 黑名单配置增删和查询功能
  - [ ] P3: 清除所有service配置

- keepalived 工具
  - [ ] P1: keepalived start/stop
  - [ ] P1: keepalived reload 配置修改生效
  - [ ] P1: keepalived restart（有配置流量时测试)
  - [ ] P1: virtual_server 配置增删
  - [ ] P1: virtual_server + vip:vport 功能
  - [ ] P1: virtual_server + virtual_server_group 功能
  - [ ] P1: virtual_server match 功能（src-range/dst-range/iif/oif等，SNAT配置）
  - [ ] P1: virtual_server quorum 功能
  - [ ] P1: virtual_server quorum_up/quorum_down 功能
  - [ ] P1: virtual_server alpha 功能
  - [ ] P1: virtual_server omega 功能
  - [ ] P1: virtual_server hysteresis 功能
  - [ ] P1: virtual_server lb_algo 配置修改
  - [ ] P1: virtual_server lb_kind 配置修改
  - [ ] P1: virtual_server protocol 配置修改
  - [ ] P2: virtual_server syn_proxy 配置修改
  - [ ] P2: virtual_server pesistent timeout 配置修改
  - [ ] P2: virtual_server establish_timeout 配置修改
  - [ ] P1: real_server 配置增删
  - [ ] P1: real_server TCP_CHECK 功能
  - [ ] P1: real_server MISC_CHECK 功能
  - [ ] P1: real_server weight 配置修改
  - [ ] P1: real_server inhibit_on_failure 功能
  - [ ] P1: local_address_group 功能
  - [ ] P1: deny_address_group 功能
  - [ ] P1: local IP 配置增删
  - [ ] P2: 黑名单增删
  - [ ] P1: vrrp_instance 主备切换功能
  - [ ] P1: vrrp_instance virtual_ipaddress 配置修改
  - [ ] P2: vrrp_instance virtual_ipaddress_excluded 配置修改
  - [ ] P2: vrrp_sync_group 功能
  - [ ] P2: virtual_server vip:vport/group/match 三种类型同时配置功能
  - [ ] P3: 相同 vip 的 virtual_server 配置两个以上不同端口的功能
  - [ ] P3: 相同 vip:vport，不同协议 TCP/UDP 的功能配置
  - [ ] P3: 200 个业务配置时keepalived start/stop/reload/restart 和健康检查功能
  - [ ] P3: 200 个 vip 配置时主备切换功能
  - [ ] P3: 1000 个业务配置时 keepalived start/stop/reload/restart 和健康检查功能
