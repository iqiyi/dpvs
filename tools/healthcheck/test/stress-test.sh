#!/bin/sh
# Copyright 2023 IQiYi Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


## Step 1.
echo -e "Cleaning existing services ..."
ipvsadm -C
sleep 5

now=$(date +%F.%T)
echo -e "[$now] Start"

## Step 2.
echo -e "Adding test services ..."
rsid=5000
for i in $(seq 0 32)
do
    for j in $(seq 1 255)
    do
        vip="192.168.${i}.${j}"
        flag="-t"
        #udp=$((j%2))
        #[ "$udp" -eq 1 ] && flag="-u"
        #echo $vip $flag
        ipvsadm -A $flag $vip:80
        for k in $(seq 5)
        do
            seg3=$((rsid/255))
            seg4=$((rsid%255))
            rsid=$((rsid+1))
            rip="192.168.${seg3}.${seg4}"
            #echo "-> $rip"
            ipvsadm -a $flag $vip:80 -r $rip:8080 -b -w 100
        done
        #dpip addr add $vip/32 dev dpdk0
    done
done

## Step 3.
echo ""
echo "****************************************"
echo -e "Start healthcheck program on your own."
echo "****************************************"
echo ""

## Step 4.
echo -e "Do Checking ..."
while true
do
    now=$(date +%F.%T)
    total=$(ipvsadm -ln| grep FullNat -c)
    down=$(ipvsadm -ln| grep inhibited -c)
    echo "[$now] total: $total, inhibited: $down"
    sleep 1
done
