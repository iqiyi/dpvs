基础支持
============

1. 网卡相关
  - [ ] IPv6 RSS: IP 方式
  - [ ] IPv6 RSS: TCP 方式
  - [ ] IPv6 FDIR: Perfect 方式
  - [ ] IPv6 FDIR: Signature 方式
  - [ ] IPv6 Checksum: TCP header
  - [ ] IPv6 Checksum: UDP header
2. mbuf 相关
  - [ ] IPv6 mbuf: 没有 exthdrs
  - [ ] IPv6 mbuf: 包含 exthdrs
  - [ ] IPv6 mbuf: 包含 sack/wscale/tstamp 选项
  - [ ] IPv6 mbuf: 包含 toa 选项
  - [ ] IPv6 mbuf: 包含 uoa 私有协议
  - [ ] IPv6 mbuf: TCP soft checksum
  - [ ] IPv6 mbuf: UDP soft checksum
  - [ ] IPv6 mbuf: ICMPv6 soft checksum
  - [ ] toa.ko for Centos 6.x
  - [ ] toa.ko for Centos 7.x
  - [ ] uoa.ko for Centos 6.x
  - [ ] uoa.ko for Centos 7.x
3. 协议相关
  - [ ] fastxmit on for all forwarding mode
  - [ ] fastxmit off for all forwarding mode
  - [ ] synproxy on
  - [ ] synproxy fail (syn flood 攻击)
  - [ ] ICMPv6 info message local in
  - [ ] ICMPv6 error message local in
  - [ ] ICMPv6 error message forwarding
4. 设备相关
  - [ ] bonding 设备
  - [ ] vlan 设备
  - [ ] bonding + vlan 设备
  - [ ] ipip tunnel 设备
  - [ ] gre tunnel 设备
  - [ ] bonding + tunnel 设备


DPVS业务场景测试
================

DPVS 应用场景灵活多样，可以从以下6个维度描述一个DPVS应用的业务场景。

* 维度1. 集群模式
  - 单台DPVS
  - 主备模式
  - OSPF模式
* 维度2. 网络环境
  - 内网 （对应one-arm DPVS）
  - 外网 （对应two-arm DPVS）
* 维度3. 配置方式
  - ipvsadm 手动配置
  - keepalived 配置文件
* 维度4. DPVS 转发类型（不同类型可以组合使用）
  - Fullnat 转发
  - DR 转发
  - Tunnel 转发
  - NAT 转发
  - SNAT 转发 (不能与前四种转发混合使用）
* 维度5. 网络协议 （不同网络协议类型可以组合使用）
  - IPv4 协议
  - IPv6 协议
* 维度6. 业务协议（不同业务协议类型可以组合使用）
  - TCP 协议
  - UDP 协议
  - ICMP 协议 （仅支持SNAT转发）

从上面看，DPVS的需要测试的业务场景的组合数量为：
  3 种集群模式 * 2 种网络环境 * 2 种配置方式 * 16 种转发类型 * 2 种网络协议 * 12 种业务协议 = 4608
因为时间和精力有限，我们只能选择如下几个典型的业务应用场景进行测试。

1. IPv6 协议转发测试
  - [ ] 单台DPVS + 内网 + ipvsadm 手动配置 + Fullnat 转发 + ipv6 协议 + TCP 协议
  - [ ] 单台DPVS + 内网 + ipvsadm 手动配置 + Fullnat 转发 + ipv6 协议 + UDP 协议
  - [ ] 单台DPVS + 内网 + ipvsadm 手动配置 + Fullnat 转发 + ipv6 协议 + TCP/UDP 协议（同 VIP）
  - [ ] 单台DPVS + 内网 + ipvsadm 手动配置 + DR 转发 + ipv6 协议 + TCP 协议
  - [ ] 单台DPVS + 内网 + ipvsadm 手动配置 + DR 转发 + ipv6 协议 + UDP 协议
  - [ ] 单台DPVS + 内网 + ipvsadm 手动配置 + DR 转发 + ipv6 协议 + TCP/UDP 协议（同 VIP）
  - [ ] 单台DPVS + 内网 + ipvsadm 手动配置 + Tunnel 转发 + ipv6 协议 + TCP 协议
  - [ ] 单台DPVS + 内网 + ipvsadm 手动配置 + Tunnel 转发 + ipv6 协议 + UDP 协议
  - [ ] 单台DPVS + 内网 + ipvsadm 手动配置 + Tunnel 转发 + ipv6 协议 + TCP/UDP 协议（同 VIP）
  - [ ] 单台DPVS + 内网 + ipvsadm 手动配置 + 单核 NAT 转发 + ipv6 协议 + TCP 协议
  - [ ] 单台DPVS + 内网 + ipvsadm 手动配置 + 单核 NAT 转发 + ipv6 协议 + UDP 协议
  - [ ] 单台DPVS + 内网 + ipvsadm 手动配置 + 单核 NAT 转发 + ipv6 协议 + TCP/UDP 协议（同 VIP）
  - [ ] 单台DPVS + 内网 + ipvsadm 手动配置 + Fullnat/DR/Tunnel/单核NAT 转发 + ipv6 协议 + TCP/UDP 协议（同 VIP）

2. IPv6/IPv4 协议混合部署转发测试
  - [ ] 单台DPVS + 内网 + ipvsadm 手动配置 + Fullnat 转发 + ipv4/ipv6 协议 + TCP 协议
  - [ ] 单台DPVS + 内网 + ipvsadm 手动配置 + Fullnat 转发 + ipv4/ipv6 协议 + UDP 协议
  - [ ] 单台DPVS + 内网 + ipvsadm 手动配置 + Fullnat 转发 + ipv4/ipv6 协议 + TCP/UDP 协议（同 VIP）
  - [ ] 单台DPVS + 内网 + ipvsadm 手动配置 + DR 转发 + ipv4/ipv6 协议 + TCP 协议
  - [ ] 单台DPVS + 内网 + ipvsadm 手动配置 + DR 转发 + ipv4/ipv6 协议 + UDP 协议
  - [ ] 单台DPVS + 内网 + ipvsadm 手动配置 + Tunnel 转发 + ipv4/ipv6 协议 + TCP 协议
  - [ ] 单台DPVS + 内网 + ipvsadm 手动配置 + Tunnel 转发 + ipv4/ipv6 协议 + UDP 协议
  - [ ] 单台DPVS + 内网 + ipvsadm 手动配置 + 单核 NAT 转发 + ipv4/ipv6 协议 + TCP 协议
  - [ ] 单台DPVS + 内网 + ipvsadm 手动配置 + 单核 NAT 转发 + ipv4/ipv6 协议 + UDP 协议
  - [ ] 单台DPVS + 内网 + ipvsadm 手动配置 + Fullnat/DR/Tunnel/单核NAT 转发 + ipv4/ipv6 协议 + TCP/UDP 协议（同 VIP）

3. 内网 one-arm 转发测试
  - [ ] 单台DPVS + 内网 + keepalived 配置文件 + Fullnat 转发 + ipv4/ipv6 协议 + TCP/UDP 协议（同 VIP）
  - [ ] 主备模式 + 内网 + keepalived 配置文件 + Fullnat 转发 + ipv4/ipv6 协议 + TCP/UDP 协议（同 VIP）
  - [ ] 主备模式 + 内网 + keepalived 配置文件 + Fullnat 转发 + ipv4/ipv6 协议 + TCP/UDP 协议（VIP 数量 >= 300）

4. 外网 two-arm 转发测试
  - [ ] 单台DPVS + 外网 + keepalived 配置文件 + Fullnat 转发 + ipv4/ipv6 协议 + TCP/UDP 协议（同 VIP）
  - [ ] 主备模式 + 外网 + keepalived 配置文件 + Fullnat 转发 + ipv4/ipv6 协议 + TCP/UDP 协议（同 VIP）
  - [ ] 主备模式 + 外网 + keepalived 配置文件 + Fullnat 转发 + ipv4/ipv6 协议 + TCP/UDP 协议（VIP 数量 >= 300）

5. 内网 ospf 转发测试
  - [ ] OSPF模式 + 内网 + keepalived 配置文件 + Fullnat 转发 + ipv4/ipv6 协议 + TCP/UDP 协议（同 VIP）
  - [ ] OSPF模式 + 内网 + keepalived 配置文件 + Fullnat 转发 + ipv4/ipv6 协议 + TCP/UDP 协议（VIP 数量 >= 300）

6. 外网 ospf 转发测试
  - [ ] OSPF模式 + 外网 + keepalived 配置文件 + Fullnat 转发 + ipv4/ipv6 协议 + TCP/UDP 协议（同 VIP）
  - [ ] OSPF模式 + 外网 + keepalived 配置文件 + Fullnat 转发 + ipv4/ipv6 协议 + TCP/UDP 协议（VIP 数量 >= 300）

7. SNAT 转发测试
  - [ ] 单台DPVS + 外网 + ipvsadm 手动配置 + SNAT 转发 + IPv6 协议 + TCP 协议
  - [ ] 单台DPVS + 外网 + ipvsadm 手动配置 + SNAT 转发 + IPv6 协议 + UDP 协议
  - [ ] 单台DPVS + 外网 + ipvsadm 手动配置 + SNAT 转发 + IPv6 协议 + ICMP 协议
  - [ ] 单台DPVS + 外网 + keepalived 配置文件 + SNAT 转发 + IPv4/IPv6 协议 + TCP/UDP/ICMP 协议
  - [ ] 单台DPVS + 外网 + keepalived 配置文件 + SNAT 转发 + IPv4/IPv6 协议 + TCP/UDP/ICMP 协议（隧道方式）
  - [ ] 单台DPVS + 外网 + keepalived 配置文件 + SNAT 转发 + IPv4/IPv6 协议 + TCP/UDP/ICMP 协议（RSS/FDIR 测试）
  - [ ] 单台DPVS + 外网 + keepalived 配置文件 + SNAT 转发 + IPv4/IPv6 协议 + TCP/UDP/ICMP 协议（隧道方式 + RSS/FDIR 测试）
  - [ ] 主备模式 + 外网 + keepalived 配置文件 + SNAT 转发 + IPv4/IPv6 协议 + TCP/UDP/ICMP 协议
  - [ ] OSPF模式 + 外网 + keepalived 配置文件 + SNAT 转发 + IPv4/IPv6 协议 + TCP/UDP/ICMP 协议
  - [ ] OSPF模式 + 外网 + keepalived 配置文件 + SNAT 转发 + IPv4/IPv6 协议 + TCP/UDP/ICMP 协议（隧道方式）

