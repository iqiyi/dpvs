Client IP can not get by original system call when you are using NAT64 mode(VIP is IPv6 while RS is IPv4).
We use 'getsockopt' to get a real client IPv6 IP by register a new system call. It should be noticed that
toa module must be installed when you are using this function.

```
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

'getsockopt(connfd, IPPROTO_IP, TOA_SO_GET_LOOKUP, &uaddr, &len)':

connfd: connection fd which is build by 'accept';
IPPROTO_IP:  included in <netinet/in.h>;
TOA_SO_GET_LOOKUP: registered hook, included in toa.h;
uaddr: struct 'toa_nat64_peer' included in toa.h;
&len: sizeof(struct toa_nat64_peer);
```
