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
	"fmt"
	"strings"

	"github.com/dpvs-agent/pkg/ipc/pool"
	"github.com/dpvs-agent/pkg/ipc/types"
	"github.com/dpvs-agent/pkg/settings"

	apiVs "github.com/dpvs-agent/restapi/operations/virtualserver"

	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

type putVsRs struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewPutVsRs(cp *pool.ConnPool, parentLogger hclog.Logger) *putVsRs {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("PutVsVipPortRs")
	}
	return &putVsRs{connPool: cp, logger: logger}
}

func (h *putVsRs) Handle(params apiVs.PutVsVipPortRsParams) middleware.Responder {
	front := types.NewRealServerFront()
	if err := front.ParseVipPortProto(params.VipPort); err != nil {
		h.logger.Error("Convert to virtual server failed", "VipPort", params.VipPort, "Error", err.Error())
		return apiVs.NewPutVsVipPortRsInvalidFrontend()
	}

	var rss []*types.RealServerSpec
	if params.Rss != nil && params.Rss.Items != nil {
		rss = make([]*types.RealServerSpec, len(params.Rss.Items))
		for i, rs := range params.Rss.Items {
			var fwdmode types.DpvsFwdMode
			fwdmode.FromString(rs.Mode)
			rss[i] = types.NewRealServerSpec()
			rss[i].SetAf(front.GetAf())
			rss[i].SetAddr(rs.IP)
			rss[i].SetPort(rs.Port)
			rss[i].SetProto(front.GetProto())
			rss[i].SetWeight(uint32(rs.Weight))
			rss[i].SetFwdMode(fwdmode)
			rss[i].SetOverloaded(rs.Overloaded)
			// NOTE: inhibited set by healthcheck module with API /vs/${ID}/rs/health only
			// we clear it default
			inhibited := false
			if rs.Inhibited != nil {
				inhibited = *rs.Inhibited
			}
			rss[i].SetInhibited(&inhibited)
		}
		h.logger.Info("Apply real server update.", "VipPort", params.VipPort, "rss", rss)
	}

	shareSnapshot := settings.ShareSnapshot()
	if shareSnapshot.ServiceLock(params.VipPort) {
		defer shareSnapshot.ServiceUnlock(params.VipPort)
	}

	existOnly := false
	result := front.Edit(existOnly, rss, h.connPool, h.logger)

	// h.logger.Info("Set real server sets done.", "VipPort", params.VipPort, "rss", rss, "result", result.String())
	switch result {
	case types.EDPVS_EXIST, types.EDPVS_OK:
		h.logger.Info("Set real server sets success.", "VipPort", params.VipPort, "rss", rss, "result", result.String())
		// Update Snapshot
		vsModel := shareSnapshot.ServiceGet(params.VipPort)
		newRSs := make([]*types.RealServerSpec, 0)
		for _, newRs := range rss {
			exist := false
			for _, cacheRs := range vsModel.RSs.Items {
				rsID := fmt.Sprintf("%s:%d", cacheRs.Spec.IP, cacheRs.Spec.Port)
				if strings.EqualFold(newRs.ID(), rsID) {
					// update weight only
					inhibited := newRs.GetInhibited()
					cacheRs.Spec.Weight = uint16(newRs.GetWeight())
					cacheRs.Spec.Inhibited = &inhibited
					exist = true
					break
				}
			}

			if !exist {
				newRSs = append(newRSs, newRs)
			}
		}

		for _, rs := range newRSs {
			vsModel.RSs.Items = append(vsModel.RSs.Items, rs.GetModel())
		}

		shareSnapshot.ServiceVersionUpdate(params.VipPort, h.logger)
		return apiVs.NewPutVsVipPortRsOK()
	case types.EDPVS_NOTEXIST:
		h.logger.Error("Unreachable branch")
	default:
		h.logger.Error("Set real server sets failed.", "VipPort", params.VipPort, "rss", rss, "result", result.String())
		return apiVs.NewPutVsVipPortRsInvalidBackend()
	}
	return apiVs.NewPutVsVipPortRsFailure()
}
