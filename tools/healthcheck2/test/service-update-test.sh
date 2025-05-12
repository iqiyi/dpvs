#!/bin/env sh
# /*
# Copyright 2025 IQiYi Inc. All Rights Reserved.
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
# */

#
# This test simulates the case where service backends updates immdediately and totally
# in one time.  The service denoted by $vip:$vport should stay available except a few
# disturbances during the test, other the test fails.
#
# Why is it essential?
# The healthcheck program pulls Services/RSs voluntarily every 15 second by default.
# Changes in Service/RSs may not reflect to the healthcheck program in time. The program
# uses a passive update solution to solve this problem: The backend health update API of
# dpvs-agent returns the latest Service/RSs if failed due to expired parameters indicated
# by deploy revision, and the healthcheck program updates its check objects with the new
# Service/RSs. Its a very different path from normal case and we should test independently.
#
# Test Results:
# Healthcheck programs cause about 1s disturbance each time all backends servers are repalced.
#
# Notes:
#   1. Run this script on RS.
#   2. RS should have additional LAN IP in 192.168.88.0/24 besides $rs1 and $rs2.
#

dpvs_agent_server=192.168.88.28:53225

vip=192.168.88.2
vport=80
rs1=192.168.88.30
rs2=192.168.88.130
lanif=dpdk0.102
rsif=bond0.102

curl -sS -X PUT "http://${dpvs_agent_server}/v2/vs/${vip}-${vport}-tcp" -H "Content-type:application/json" -d "{\"SchedName\":\"wrr\"}" >/dev/null
curl -sS -X PUT "http://${dpvs_agent_server}/v2/device/${lanif}/addr" -H "Content-type:application/json" -d "{\"addr\":\"${vip}/32\"}" >/dev/null
curl -sS -X PUT "http://${dpvs_agent_server}/v2/vs/${vip}-${vport}-tcp/laddr" -H "Content-type:application/json" -d "{\"device\":\"${lanif}\", \"addr\":\"192.168.88.241\"}" >/dev/null
curl -sS -X DELETE "http://${dpvs_agent_server}/v2/vs/${vip}-${vport}-tcp/rs" -H "Content-type:application/json" -d "{\"Items\":[{\"ip\":\"${rs1}\", \"port\":80, \"weight\":100}]}" >/dev/null 2>&1
ip addr del $rs1/24 dev $rsif 2>/dev/null
curl -sS -X DELETE "http://${dpvs_agent_server}/v2/vs/${vip}-${vport}-tcp/rs" -H "Content-type:application/json" -d "{\"Items\":[{\"ip\":\"${rs2}\", \"port\":80, \"weight\":100}]}" >/dev/null 2>&1
ip addr del $rs2/24 dev $rsif 2>/dev/null
curl -sS -X PUT "http://${dpvs_agent_server}/v2/vs/${vip}-${vport}-tcp/rs" -H "Content-type:application/json" -d "{\"Items\":[{\"ip\":\"${rs1}\", \"port\":80, \"weight\":100}]}" >/dev/null
ip addr add $rs1/24 dev $rsif
#ipvsadm -ln -t $vip:$vport
while true
do
    echo -e "[$(date +%F.%T)] RS changed: $rs1 -> $rs2"
  curl -sS -X DELETE "http://${dpvs_agent_server}/v2/vs/${vip}-${vport}-tcp/rs" -H "Content-type:application/json" -d "{\"Items\":[{\"ip\":\"${rs1}\", \"port\":80, \"weight\":100}]}" >/dev/null
  ip addr del $rs1/24 dev $rsif 2>/dev/null
  curl -sS -X PUT "http://${dpvs_agent_server}/v2/vs/${vip}-${vport}-tcp/rs" -H "Content-type:application/json" -d "{\"Items\":[{\"ip\":\"${rs2}\", \"port\":80, \"weight\":100}]}" > /dev/null
  ip addr add $rs2/24 dev $rsif 2>/dev/null
  sleep 20
  echo -e "[$(date +%F.%T)] RS changed: $rs2 -> $rs1"
  curl -sS -X DELETE "http://${dpvs_agent_server}/v2/vs/${vip}-${vport}-tcp/rs" -H "Content-type:application/json" -d "{\"Items\":[{\"ip\":\"${rs2}\", \"port\":80, \"weight\":100}]}" >/dev/null
  ip addr del $rs2/24 dev $rsif 2>/dev/null
  curl -sS -X PUT "http://${dpvs_agent_server}/v2/vs/${vip}-${vport}-tcp/rs" -H "Content-type:application/json" -d "{\"Items\":[{\"ip\":\"${rs1}\", \"port\":80, \"weight\":100}]}" > /dev/null
  ip addr add $rs1/24 dev $rsif 2>/dev/null
  sleep 20
done

