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
# The script adds/removes IP address to/from linux "lo" interface and the
# specified dpdk port <dpvs.ifname> according to the given UP/DOWN signal,
# which can be used as a test script for ScriptAction.
#
# Usage: $0 <dpvs.ifname> UP|DOWN <IP>
#

[ $# -lt 3 ] && echo "Usage: $0 <dpvs.ifname> UP|DOWN <IP>" && exit 1

ifname=$1
action=$2
ip=$3

ipcalc -s -c $ip
[ $? -ne 0 ] && echo "invalid IP address $ip" && exit 1

if [ "_$action" != "_UP" -a "_$action" != "_DOWN" ]; then
    echo "invalid action $action, only support UP|DOWN"
    exit 1
fi

dpip link show $ifname > /dev/null 2>&1
[ $? -ne 0 ] && echo "invalid DPVS ifname $ifname" && exit 1


pfxlen=32
ipcalc -6 $ip >/dev/null 2>&1
[ $? -eq 0 ] && pfxlen=128

if [ "_$action" == "_UP" ]; then
    ip addr add $ip/$pfxlen dev lo
    dpip addr add $ip/$pfxlen dev $ifname
else ### action DOWN
    ip addr del $ip/$pfxlen dev lo
    dpip addr del $ip/$pfxlen dev $ifname
fi

exit 0
