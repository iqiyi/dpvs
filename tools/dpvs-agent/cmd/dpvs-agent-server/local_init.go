// Copyright 2023 IQiYi Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"strings"

	"github.com/dpvs-agent/cmd/device"
	"github.com/dpvs-agent/pkg/ipc/pool"
	"github.com/dpvs-agent/pkg/ipc/types"
	"github.com/dpvs-agent/pkg/settings"

	"github.com/hashicorp/go-hclog"
)

func (agent *DpvsAgentServer) LocalLoad(cp *pool.ConnPool, parentLogger hclog.Logger) error {
	var errs []error
	logger := hclog.Default().Named("LoadConfigFile")
	if parentLogger != nil {
		logger = parentLogger.Named("LoadConfigFile")
	}

	nodeSnap := settings.ShareSnapshot()
	if err := nodeSnap.LoadFrom(settings.LocalConfigFile(), logger); err != nil {
		return err
	}

	announcePort := nodeSnap.NodeSpec.AnnouncePort
	laddrs := nodeSnap.NodeSpec.Laddrs

	for _, snap := range nodeSnap.Snapshot {
		service := snap.Service
		// 1> ipvsadm -A vip:port -s wrr
		vs := types.NewVirtualServerSpec()
		vs.SetAddr(service.Addr)
		vs.SetPort(service.Port)
		vs.SetProto(service.Proto)
		vs.SetFwmark(service.Fwmark)
		vs.SetConnTimeout(service.ConnTimeout)
		vs.SetBps(service.Bps)
		vs.SetLimitProportion(service.LimitProportion)
		vs.SetTimeout(service.Timeout)
		vs.SetSchedName(service.SchedName)
		flags := strings.ToLower(service.Flags)
		if strings.Index(flags, "expirequiescent") != -1 {
			vs.SetFlagsExpireQuiescent()
		}
		if strings.Index(flags, "synproxy") != -1 {
			vs.SetFlagsSynProxy()
		}
		if strings.Index(flags, "conhashbysrcip") != -1 {
			vs.SetFlagsHashSrcIP()
		}
		if strings.Index(flags, "conhashbyquicid") != -1 {
			vs.SetFlagsHashQuicID()
		}
		vs.Add(cp, logger)
		// 2> dpip addr add ${vip} dev ${device}
		svcAddr := types.NewInetAddrDetail()
		svcAddr.SetAddr(service.Addr)
		svcAddr.SetIfName(announcePort.Dpvs)
		svcAddr.Add(cp, logger)

		// 3> ipvsadm -at ${VIPPORT} -r ${RS:PORT} -w ${WEIGHT} -b
		rsFront := types.NewRealServerFront()
		if err := rsFront.ParseVipPortProto(vs.ID()); err != nil {
			errs = append(errs, err)
		}
		rss := make([]*types.RealServerSpec, len(service.RSs.Items))
		for i, rs := range service.RSs.Items {
			var fwdmode types.DpvsFwdMode
			fwdmode.FromString(rs.Spec.Mode)
			rss[i] = types.NewRealServerSpec()
			rss[i].SetPort(rs.Spec.Port)
			rss[i].SetWeight(uint32(rs.Spec.Weight))
			rss[i].SetProto(uint16(service.Proto))
			rss[i].SetAddr(rs.Spec.IP)
			rss[i].SetFwdMode(fwdmode)
		}

		rsFront.Update(rss, cp, logger)
		// 4> bind laddr with vs (ipvsadm --add-laddr -z ${LADDR}  -t ${VIPPORT} -F ${device})
		laddr := types.NewLocalAddrFront()
		if err := laddr.ParseVipPortProto(vs.ID()); err != nil {
		}
		lds := make([]*types.LocalAddrDetail, len(laddrs.Items))
		for i, lip := range laddrs.Items {
			lds[i] = types.NewLocalAddrDetail()
			lds[i].SetAddr(lip.Addr)
			lds[i].SetIfName(lip.Device)
		}
		laddr.Add(lds, cp, logger)
		// 5> ip addr add ${VIP} dev ${KNIDEVICE(lo?)}
		if err := device.NetlinkAddrAdd(service.Addr, announcePort.Switch, logger); err != nil {
			logger.Error("add addr", service.Addr, "onto device failed")
			errs = append(errs, err)
		}
	}
	// 6> dpip addr add ${LADDR} dev ${device}
	for _, lip := range laddrs.Items {
		lipAddr := types.NewInetAddrDetail()
		lipAddr.SetAddr(lip.Addr)
		lipAddr.SetIfName(lip.Device)
		lipAddr.SetFlags("sapool")
		resultCode := lipAddr.Add(cp, logger)
		logger.Info("Add addr to device done.", "Device", lip.Device, "Addr", lip.Addr, "result", resultCode.String())
	}

	return settings.MergedError(errs)
}
