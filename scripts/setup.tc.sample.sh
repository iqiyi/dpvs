#!/bin/sh -
# raychen, Jan 2018

VIP="192.168.204.252"
DIP="192.168.204.50"
RSs="192.168.204.51 192.168.204.52 192.168.204.53 192.168.204.54"
LIPs="192.168.204.200 192.168.204.201 192.168.204.202 192.168.204.203 192.168.204.204 192.168.204.205"
LANIF=dpdk0

#              0:  root
#     oif=lan  /
#            1:0  (10m)
#            / \
# (2000p) 1:1   1:2 (4g)

# 10m rate limit with tbf
./dpip qsch add dev ${LANIF} handle 1:0 parent 0: tbf rate 10m burst 1500000 latency 20
# 2000 pfifo limit
./dpip qsch add dev ${LANIF} handle 1:1 parent 1: pfifo limit 2000
# 4g rate limit with tbf
./dpip qsch add dev ${LANIF} handle 1:2 parent 1: tbf rate 4g burst 150000000 latency 20

# check at 0:, goto 1: if packet sent by lan interface
./dpip cls add dev ${LANIF} qsch 0: match pattern "tcp,oif=${LANIF}" target 1:
# check at 1:, goto 1:1 if packet is tcp,to=0.0.0.0:80
./dpip cls add dev ${LANIF} qsch 1: match pattern 'tcp,to=0.0.0.0:80' target 1:1
# check at 1:, goto 1:2 if packet is tcp,from=0.0.0.0:80
./dpip cls add dev ${LANIF} qsch 1: match pattern 'tcp,from=0.0.0.0:80' target 1:2

./dpip addr add $DIP/24 dev ${LANIF}
./dpip addr add $VIP/24 dev ${LANIF}
./ipvsadm -A -t $VIP:80 -s rr

for rs in $RSs; do
	./ipvsadm -a -t $VIP:80 -r $rs -b
done

for lip in $LIPs; do
	./ipvsadm --add-laddr -z $lip -t $VIP:80 -F ${LANIF}
done
