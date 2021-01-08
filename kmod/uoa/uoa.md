UDP Option of Address (UOA)
==========================

## what means `UOA` ?

`UOA` is *UDP Option of Address*, the idea comes from `TOA` of `LVS`. `UOA` is used to retrieve real source IP/port of UDP packets, for the scenario source IP/port are modified by middle boxes (like load balancer or `LB`).

There's no option field for UDP header, why *UDP Option* ? Yes, actually we use private IP option instead, while only UDP codes check that option.

> In this doc, always assuming the UOA sender is `LB` (configured with FullNAT) and receiver is Real Server (`RS`).  
> The original client IP/port is "real IP/port", and the IP/port after translation, is translated IP/port. Translated IP/port is the source IP/port for the packets seen by RS.

## Design Consideration

Just write down some considerations when design. Pls read the codes for any details.

#### **User transparent** (partial)

The program running on RS need no or little code change. User need to install `uoa.ko` on RS, while the `uoa.ko` must be uninstalled without any side-effect.

The target WAS *no code change* for user program, and only need `uoa.ko`. But for the the factors,

1.  UDP is connectless

    One UDP *socket* can be used to communicated with different peers (without `connect`). Thus, `sock{}` is not combined with '5-tuples', means it cannot be leveraged to save real IP/port as what's done in `TOA`.

2. No way to get packet back to LB

    Further more, if we pass real client IP/port to user, e.g., by recvfrom(2), then the user program have no idea to send packet back to translated IP/port (aka `LIP/lport` for `FullNAT`). It breaks the LB function.

So we introduced an new socket option for user to get real Client IP/port.

#### **Performance**

Support `UOA` on both side of LB (`DPVS`/`LVS`) and RS should not hurt the performance. To achieve this,

1. Not all UDP/IP packets of an "session" should contain `UOA` option.
2. Less packet bytes are copied by choosing *head-end* or *tail-end* moving.

#### **Reliability** (partial)

UDP/IP is not reliable, `UOA` should try *best effert* for the reliability to get real source IP/port.

1. LB send `UOA` option when forwarding packet to RS and only for new UDP connection,
2. LB send `UOA` option until *ACK* from RS is seen for that connection or *max trails* reached.
3. LB send `UOA` option by inserting option to original packet if possilble.
3. LB send `UOA` by using 'empty-payload' packet if original has no room for `UOA`.
4. RS echo `UOA` as *ACK*. (Needn't waiting user packets to client to "bring" the ACK).
5. "ACK" packet is also an 'empty-payload' with echoed `UOA` option, and must NOT be forwarded to client.

Let's keep it simple, no sequence number reordering, no timer, no TCP like "retrans".
Note "ACK" is not supported for this version, so "max-trails" is used for new UDP "session".

#### **Avoid Race Condition** (partial)

UDP/IP has no guarantee of the order of packets. There's a "race condition" that RS receive the UDP packet without `uoa` option ahead to the packet with `UOA`. In that case, before first `UOA` received, there's a small window, user calling `getsockopt` may fail to get the real client IP/port. The implement just try to avoid that "race", but no guarantee, we don't want to queue the packets and reorder them, it make things too complicated.

The "race" is really a small probability, in IDC internal network.

#### **No room**

Some packets are not "qualified" to insert private `UOA` option because no room available,

1. There's no room in IP option field.
2. The length of packet will exceed MTU if `UOA` inserted.

To address these issues, we introduce *empty payload UDP* packet for UOA option only. And this *empty-payload* packet with `UOA` is always be sent *ahead* to the original packet with no room for UOA, in order to "trying avoid" race condition mentioned above. Here we must use UDP instead of "empty" IP packets, for the session matching reason.

#### **Sufficient Statistics**

The Statistics must be sufficient, easy to fetch and not affect the performance. So that we are able to debug, diagnostic the possible issues easier, especially on production environment.

#### **Compatible with TCP ?**

Since IP option is used, actually it's possilble to compatible with TCP. Then we can use only one kernel module. However `TOA` is widelly used, and `sock{}` is OK to save `TOA`, that make `TOA` codes more simple. So let't hold this idea.

#### **Why IP option ?**

Can we use private protocol, instead of IP option ?

We may use a private `IPPROTO_XXX` protocol to encaplate UDP ? Looks like `IP+UOA+UDP`, simmilar with the idea of tunnel. But it may lead to firewall issues, note UDP/TCP are most popular, friendly to firewall or other middle box, but new protocol may not. And the new encaplation may have MTU issues for all packets. Another way is `IP+UDP+UOA+payload`, but it's difficult to identify the UOA and application payload.

#### **Why support private protocol then ?**

Currently, we have supported private protocol. The reason is that we found not all l3-switches support IPv4 options, or there exists a strict speed limitation such as 300pps. The reason from provider is the switch cannot handle IP options with hardware(chips), and the switch in this case just has to drop the whole packet, or pass the packets with IP options to CPU for process with a very limited speed. On the other hand, the switch can "support" unkown IP protocol, thus we can wrap UDP source address into a private protocol and forward it to backends. The packets carrying UOA private protocol typically have the structure of "ETHER|IP/IPv6|UOA|UDP/...".

Uoa private protocol (`opp` mode) supports IPv4/IPv6/Nat64, while the IP option (`ipo` mode) supports IPv4 only.
 
--------------------------------

Lei Chen `<raychen@qiyi.com>`, Mar 2018.
