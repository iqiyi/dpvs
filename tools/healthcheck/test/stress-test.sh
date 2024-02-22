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

#dpvs_agent_server=localhost:53225

## Step 1.
echo -e "Cleaning existing services ..."
ipvsadm -C
sleep 5

now=$(date +%F.%T)
echo -e "[$now] Start"

## Step 2.
now=$(date +%F.%T)
echo -e "[$now] Adding test services ..."
rsid=5000
for i in $(seq 0 32)
do
    for j in $(seq 1 255)
    do
        vip="192.168.${i}.${j}"
        #echo $vip:80
        ipvsadm -At $vip:80
        #curl -sS -X PUT "http://${dpvs_agent_server}/v2/vs/${vip}-80-tcp" -H "Content-type:application/json" -d "{\"SchedName\":\"wrr\"}" >/dev/null
        ipvsadm -Pt $vip:80 -z 192.168.88.241 -F dpdk0 >/dev/null 2>&1
        #curl -X PUT "http://${dpvs_agent_server}/v2/vs/${vip}-80-tcp/laddr" -H "Content-type:application/json" -d "{\"device\":\"dpdk0\", \"addr\":\"192.168.88.241\"}"
        for k in $(seq 5)
        do
            seg3=$((rsid/255))
            seg4=$((rsid%255))
            rsid=$((rsid+1))
            rip="192.168.${seg3}.${seg4}"
            #echo "-> $rip:8080"
            ipvsadm -at $vip:80 -r $rip:8080 -b -w 100
            #curl -sS -X PUT "http://${dpvs_agent_server}/v2/vs/${vip}-80-tcp/rs" -H "Content-type:application/json" -d "{\"Items\":[{\"ip\":\"${rip}\", \"port\":80, \"weight\":100}]}" > /dev/null
        done
        #dpip addr add $vip/32 dev dpdk0
    done
done

## Step 3.
now=$(date +%F.%T)
echo ""
echo "****************************************"
echo -e "[$now] Start healthcheck program on your own."
echo "****************************************"
echo ""

## Step 4.
now=$(date +%F.%T)
echo -e "[$now] Do Checking ..."
while true
do
    now=$(date +%F.%T)
    total=$(ipvsadm -ln| grep FullNat -c)
    down=$(ipvsadm -ln| grep inhibited -c)
    echo "[$now] total: $total, inhibited: $down"
    sleep 1
done
