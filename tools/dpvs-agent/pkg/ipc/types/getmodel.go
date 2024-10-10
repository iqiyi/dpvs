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

package types

import (
	"github.com/dpvs-agent/models"
)

func (vs *VirtualServerSpec) GetModel() *models.VirtualServerSpecExpand {
	modelVs := &models.VirtualServerSpecExpand{
		Addr:            vs.GetAddr(),
		Af:              vs.GetAf(),
		Bps:             vs.GetBps(),
		ConnTimeout:     vs.GetConnTimeout(),
		LimitProportion: vs.GetLimitProportion(),
		Netmask:         vs.GetNetMask(),
		Port:            vs.GetPort(),
		Proto:           vs.GetProto(),
		Fwmark:          vs.GetFwmark(),
		SynProxy:        "false",
		ExpireQuiescent: "false",
		Quic:            "false",
		SchedName:       vs.GetSchedName(),
		Timeout:         vs.GetTimeout(),
		Match:           vs.match.GetModel(),
		Stats:           vs.stats.GetModel(),
		DestCheck:       vs.GetDestCheck(),
	}

	flags := ""
	if (vs.GetFlags() & DPVS_SVC_F_SYNPROXY) != 0 {
		modelVs.SynProxy = "true"
		flags += "SynProxy|"
	}

	if (vs.GetFlags() & DPVS_SVC_F_EXPIRE_QUIESCENT) != 0 {
		modelVs.ExpireQuiescent = "true"
		flags += "ExpireQuiescent|"
	}

	if (vs.GetFlags() & DPVS_SVC_F_QUIC) != 0 {
		modelVs.Quic = "true"
		flags += "Quic|"
	}

	if (vs.GetFlags() & DPVS_SVC_F_QID_HASH) != 0 {
		flags += "ConHashByQuicID|"
	}
	if (vs.GetFlags() & DPVS_SVC_F_SIP_HASH) != 0 {
		flags += "ConHashBySrcIP|"
	}

	modelVs.Flags = flags

	return modelVs
}

func (ir *ipRange) GetModel() *models.AddrRange {
	return &models.AddrRange{
		Start: ir.GetMinAddr(),
		End:   ir.GetMaxAddr(),
	}
}

func (dm *dpvsMatch) GetModel() *models.MatchSpec {
	return &models.MatchSpec{
		Dest:      dm.drange.GetModel(),
		Src:       dm.srange.GetModel(),
		InIfName:  dm.GetIifName(),
		OutIfName: dm.GetOifName(),
	}
}

func (rs *RealServerSpec) GetModel() *models.RealServerSpecExpand {
	overloaded := rs.GetOverloaded()
	inhibited := rs.GetInhibited()
	return &models.RealServerSpecExpand{
		Spec: &models.RealServerSpecTiny{
			IP:         rs.GetAddr(),
			Mode:       rs.GetFwdModeString(),
			Port:       rs.GetPort(),
			Weight:     (uint16)(rs.GetWeight()),
			Overloaded: &overloaded,
			Inhibited:  &inhibited,
		},
		Stats: rs.stats.GetModel(),
	}
}

type ServerStats models.ServerStats

func (dst *ServerStats) Increase(src *ServerStats) {
	dst.Conns += src.Conns
	dst.InPkts += src.InPkts
	dst.InBytes += src.InBytes
	dst.OutPkts += src.OutPkts
	dst.OutBytes += src.OutBytes

	dst.Cps += src.Cps
	dst.InBps += src.InBps
	dst.InPps += src.InPps
	dst.OutBps += src.OutBps
	dst.OutPps += src.OutPps
}

func (stats *dpvsStats) GetModel() *models.ServerStats {
	return &models.ServerStats{
		Conns:    stats.GetConns(),
		InPkts:   stats.GetInPkts(),
		InBytes:  stats.GetInBytes(),
		OutPkts:  stats.GetOutPkts(),
		OutBytes: stats.GetOutBytes(),

		Cps:    stats.GetCps(),
		InBps:  stats.GetInBps(),
		InPps:  stats.GetInPps(),
		OutBps: stats.GetOutBps(),
		OutPps: stats.GetOutPps(),
	}
}

func (nic *NetifNicQueue) GetModel() []models.NicDeviceQueueData {
	nicDataQueue := make([]models.NicDeviceQueueData, len(nic.queue))
	for i, data := range nic.queue {
		nicDataQueue[i] = (models.NicDeviceQueueData)(data)
	}
	return nicDataQueue
}

func (stats *NetifNicStats) GetModel() *models.NicDeviceStats {
	nicStats := &models.NicDeviceStats{
		BufAvail:    stats.GetMBufAvail(),
		BufInuse:    stats.GetMBufInuse(),
		ID:          stats.GetID(),
		InBytes:     stats.GetInBytes(),
		InErrors:    stats.GetInErrors(),
		InMissed:    stats.GetInMissed(),
		InPkts:      stats.GetInPkts(),
		OutBytes:    stats.GetOutBytes(),
		OutPkts:     stats.GetOutPkts(),
		OutErrors:   stats.GetOutErrors(),
		RxNoMbuf:    stats.GetRxNoMbuf(),
		InBytesQ:    stats.inBytesQ.GetModel(),
		InPktsQ:     stats.inPktsQ.GetModel(),
		OutBytesQ:   stats.outBytesQ.GetModel(),
		OutPktsQ:    stats.outPktsQ.GetModel(),
		ErrorBytesQ: stats.errorQ.GetModel(),
	}
	return nicStats
}

func (detail *NetifNicDetail) GetModel() *models.NicDeviceDetail {
	return &models.NicDeviceDetail{
		Flags:    detail.GetFlags(),
		ID:       detail.GetID(),
		MTU:      detail.GetMTU(),
		Addr:     detail.GetAddr(),
		Autoneg:  detail.GetLinkAutoNeg(),
		Duplex:   detail.GetLinkDuplex(),
		NRxQ:     detail.GetRxQueueCount(),
		NTxQ:     detail.GetTxQueueCount(),
		Name:     detail.GetName(),
		SocketID: detail.GetSocketID(),
		Speed:    detail.GetSpeed(),
		Status:   detail.GetStatus(),
	}
}

func (laddr *LocalAddrDetail) GetModel() *models.LocalAddressSpecExpand {
	return &models.LocalAddressSpecExpand{
		Af:           laddr.GetAf(),
		Addr:         laddr.GetAddr(),
		Conns:        laddr.GetConns(),
		Device:       laddr.GetIfName(),
		PortConflict: laddr.GetPortConflict(),
	}
}
