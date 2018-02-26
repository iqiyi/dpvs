UDP Option of Address (UOA)
==========================

## what means `UOA` ?

`UOA` is **UDP Option of Address**, the idea comes from `TOA` of `LVS`. `UOA` is used to retrieve real source IP of UDP packets, for the case source IP are modified by middle boxes (like load balancer or `LB`).

There's no option field for UDP header ! Yes, actually we use private IP option instead, while only UDP codes check that option. Why use IP option but for UDP only ? Because IP is point-to-point model, there's no idea of "IP session" (5-tuples).

> In this doc, always assuming the UOA sender is LB and receiver is RS.

## Design Consideration

Just write down some considerations when design.

* User transparent

    The program running on Real Server (RS) need no code change. the only step for user is to install `uoa.ko` on RS. While the `uoa.ko` must be uninstalled without any side-effect.

* Performance should not be affect

    Support `UOA` on both side of LB (`DPVS`/`LVS`) and RS should not hurt the performance. To achieve this,
    1. not all UDP/IP packets of an "session" should contain `UOA` option.
    2. less packet bytes copy by choosing head-end or tail-end moving.

* Reliability (partial)

    UDP/IP is not reliable, `UOA` should try "best effert" to fillful the reliability to get real source IP.

    1. LB send `UOA` option when forwarding packet to RS and only for new UDP connection,
    2. LB send `UOA` option utill **ACK** from RS is seen for that connection or max trails reached (default is 3).
    3. LB send `UOA` option by inserting option to original packet if possilble, and use 'empty-payload' packet if original has no room for `UOA`.
    4. RS echo `UOA` as **ACK**. (needn't waiting RS send packet to LB to bring the ACK).
    5. "ACK" packet is also an 'empty-payload' with echoed `UOA` option, and must not forward.

    Let's keep it simple, no sequence number, no timer, no "retrans".

* Avoid Race Condition (not 100%)

    UDP/IP has no guarantee of the order of packets. There's a "race condition" that the program on RS receive the UDP packet with out `uoa` option ahead to the packet with `UOA`. In that case user calling 'getpeername' or 'accept' may get modified source IP. The implement just try to avoid that but still no guarantee, we don't want to queue the packets and reorder them, it make things too complicated.

* No room to insert `UOA` option

    Some packet are not qualified to insert private `UOA` option because out of space,

    1. IP option field is "full".
    2. The length of packet will exceed PMTU if `UOA` inserted

    To address these issues, we introduce 'empty payload' UDP packet for UOA option only. And this 'empty-payload' packet with `UOA` is always be sent ahead any packets, just trying to avoid race condition mentioned above. 

* Sufficient Statistics

    The Statistics must be sufficient and easy to fetch and not affect the performance. So that we can debug/diagnostic the issues easier, even on production environment.

* Compatible with TCP ?

    Since IP option is used, actually it's possilble to compatible with TCP. So we can use only one kernel module, however `TOA` is widelly used, let't hold to support TCP for now.

* Leverage IP codes to parse option

    It was Considered to use `ip_rcv/ip_rcv_options/ip_options_compile` to parse `UOA` and UDP codes just read it from `IPCB(skb).opt`. But if we replace `ip_rcv` in `ptype_base[]`, it's dangerous and takes too long call-path get get options being handled.

    So let's peek and parse IP options again to get possible `UOA` in UDP codes, it waste little CPU time, but IP header checking should not take too much resource.

* Why IP option ?

    Can we use private protocol, not IP option ?

    We can use a private `IPPROTO_XXX` protocol to encaplate UDP ? Looks like `IP + UOA + UDP`, simmilar with tunnel. But it may lead to firewall issues, note UDP/TCP are most popular, and frendly to firewall or other middle box, but new protocol may not. Another way is `IP + UDP + UOA + payload`, but it's difficult to identify the UOA and application payload.
