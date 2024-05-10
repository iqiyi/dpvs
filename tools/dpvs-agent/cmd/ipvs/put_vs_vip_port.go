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

package ipvs

import (
	"strings"

	"github.com/dpvs-agent/models"
	"github.com/dpvs-agent/pkg/ipc/pool"
	"github.com/dpvs-agent/pkg/ipc/types"
	"github.com/dpvs-agent/pkg/settings"
	"golang.org/x/sys/unix"

	apiVs "github.com/dpvs-agent/restapi/operations/virtualserver"

	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

type putVsItem struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewPutVsItem(cp *pool.ConnPool, parentLogger hclog.Logger) *putVsItem {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("PutVsVipPort")
	}
	return &putVsItem{connPool: cp, logger: logger}
}

// ipvsadm -A vip:port -s wrr
func (h *putVsItem) Handle(params apiVs.PutVsVipPortParams) middleware.Responder {
	vs := types.NewVirtualServerSpec()
	err := vs.ParseVipPortProto(params.VipPort)
	if err != nil {
		h.logger.Error("Convert to virtual server failed", "VipPort", params.VipPort, "Error", err.Error())
		return apiVs.NewPutVsVipPortInvalidFrontend()
	}

	schedName := ""

	if params.Spec != nil {
		schedName = params.Spec.SchedName

		vs.SetFwmark(params.Spec.Fwmark)
		vs.SetConnTimeout(params.Spec.ConnTimeout) // establish time out
		vs.SetBps(params.Spec.Bps)
		vs.SetLimitProportion(params.Spec.LimitProportion)

		if params.Spec.Timeout != 0 {
			vs.SetTimeout(params.Spec.Timeout) // persistence time out
			vs.SetFlagsPersistent()
		}

		if params.Spec.ExpireQuiescent != nil && *params.Spec.ExpireQuiescent {
			vs.SetFlagsExpireQuiescent()
		}

		if params.Spec.Quic != nil && *params.Spec.Quic {
			vs.SetFlagsQuic()
		}

		if params.Spec.SynProxy != nil && *params.Spec.SynProxy {
			vs.SetFlagsSynProxy()
		}

		vs.SetProxyProto(params.Spec.ProxyProtocol)
	}

	vs.SetSchedName(schedName)
	if strings.EqualFold(vs.GetSchedName(), "conhash") {
		vs.SetFlagsHashSrcIP()

		if vs.GetProto() == unix.IPPROTO_UDP {
			// if strings.EqualFold(strings.ToLower(params.Spec.HashTaget), "qid") {vs.SetFlagsHashQuicID()}
		}
	}

	shareSnapshot := settings.ShareSnapshot()
	result := vs.Add(h.connPool, h.logger)
	h.logger.Info("Add virtual server done.", "vs", vs, "result", result.String())
	switch result {
	case types.EDPVS_OK:
		// return 201
		shareSnapshot.ServiceAdd(vs)
		h.logger.Info("Created new virtual server success.", "VipPort", params.VipPort)
		return apiVs.NewPutVsVipPortCreated()
	case types.EDPVS_EXIST:
		h.logger.Info("The virtual server already exist! Try to update.", "VipPort", params.VipPort)

		if shareSnapshot.ServiceLock(vs.ID()) {
			defer shareSnapshot.ServiceUnlock(vs.ID())
		}

		reason := vs.Update(h.connPool, h.logger)
		if reason != types.EDPVS_OK {
			// return 461
			h.logger.Error("Update virtual server failed.", "VipPort", params.VipPort, "reason", reason.String())
			return apiVs.NewPutVsVipPortInvalidBackend()
		}

		newVsModel := vs.GetModel()
		vsModel := shareSnapshot.ServiceGet(vs.ID())
		if vsModel == nil {
			newVsModel.RSs = &models.RealServerExpandList{
				Items: make([]*models.RealServerSpecExpand, 0),
			}
			shareSnapshot.ServiceUpsert(newVsModel)
			return apiVs.NewPutVsVipPortOK()
		}

		vsModel.Bps = newVsModel.Bps
		vsModel.ConnTimeout = newVsModel.ConnTimeout
		vsModel.LimitProportion = newVsModel.LimitProportion
		vsModel.ExpireQuiescent = newVsModel.ExpireQuiescent
		vsModel.Quic = newVsModel.Quic
		vsModel.Fwmark = newVsModel.Fwmark
		vsModel.SynProxy = newVsModel.SynProxy
		vsModel.Match = newVsModel.Match
		vsModel.SchedName = newVsModel.SchedName
		vsModel.Timeout = newVsModel.Timeout
		vsModel.Flags = newVsModel.Flags
		if vsModel.RSs == nil {
			vsModel.RSs = &models.RealServerExpandList{}
		}

		if vsModel.RSs.Items == nil {
			vsModel.RSs.Items = make([]*models.RealServerSpecExpand, 0)
		}

		h.logger.Info("Update virtual server success.", "VipPort", params.VipPort)

		// return 200
		return apiVs.NewPutVsVipPortOK()
	default:
		h.logger.Error("Add virtual server failed.", "result", result.String())
		return apiVs.NewPutVsVipPortInvalidBackend()
	}

	return apiVs.NewPutVsVipPortOK()
}
