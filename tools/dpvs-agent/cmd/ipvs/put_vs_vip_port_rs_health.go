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
	"github.com/dpvs-agent/pkg/ipc/pool"
	"github.com/dpvs-agent/pkg/ipc/types"

	"github.com/dpvs-agent/models"
	apiVs "github.com/dpvs-agent/restapi/operations/virtualserver"

	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

type putVsRsHealth struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewPutVsRsHealth(cp *pool.ConnPool, parentLogger hclog.Logger) *putVsRsHealth {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("PutVsVipPortRsHealth")
	}
	return &putVsRsHealth{connPool: cp, logger: logger}
}

func (h *putVsRsHealth) Handle(params apiVs.PutVsVipPortRsHealthParams) middleware.Responder {
	front := types.NewRealServerFront()
	if err := front.ParseVipPortProto(params.VipPort); err != nil {
		h.logger.Error("Convert to virtual server failed", "VipPort", params.VipPort, "Error", err.Error())
		return apiVs.NewPutVsVipPortRsHealthInvalidFrontend()
	}

	// get active backends
	active, err := front.Get(h.connPool, h.logger)
	if err != nil {
		return apiVs.NewPutVsVipPortRsHealthInvalidBackend()
	}

	activeRSs := make(map[string]*types.RealServerSpec)
	for _, rs := range active {
		activeRSs[rs.ID()] = rs
	}

	rssModels := new(models.RealServerExpandList)
	rssModels.Items = make([]*models.RealServerSpecExpand, len(active))
	validRSs := make([]*types.RealServerSpec, 0)
	expiredRSs := make([]*types.RealServerSpec, 0)
	if params.Rss != nil {
		for _, rs := range params.Rss.Items {
			var fwdmode types.DpvsFwdMode
			fwdmode.FromString(rs.Mode)
			newRs := types.NewRealServerSpec()
			newRs.SetAf(front.GetAf())
			newRs.SetAddr(rs.IP)
			newRs.SetPort(rs.Port)
			newRs.SetProto(front.GetProto())
			newRs.SetWeight(uint32(rs.Weight))
			newRs.SetFwdMode(fwdmode)
			newRs.SetInhibited(rs.Inhibited)
			newRs.SetOverloaded(rs.Inhibited)

			if active, existed := activeRSs[newRs.ID()]; existed {
				rssModels.Items = append(rssModels.Items, active.GetModel())

				if active.GetWeight() == uint32(rs.ConsistentWeight) {
					validRSs = append(validRSs, newRs)
					continue
				}
				expiredRSs = append(expiredRSs, newRs)
			}
		}
	}

	existOnly := true
	result := front.Edit(existOnly, validRSs, h.connPool, h.logger)
	switch result {
	case types.EDPVS_EXIST, types.EDPVS_OK:
		if len(expiredRSs) != 0 {
			h.logger.Info("There are some rs weight versoin has already expired", "expiredRSs", expiredRSs)
			return apiVs.NewPutVsVipPortRsHealthUnexpected().WithPayload(rssModels)
		}
		h.logger.Info("Set real server sets success.", "VipPort", params.VipPort, "validRSs", validRSs, "result", result.String())
		return apiVs.NewPutVsVipPortRsHealthOK().WithPayload(rssModels)
	case types.EDPVS_NOTEXIST:
		if existOnly {
			h.logger.Error("Edit not exist real server.", "VipPort", params.VipPort, "validRSs", validRSs, "result", result.String())
			return apiVs.NewPutVsVipPortRsHealthInvalidFrontend()
		}
		h.logger.Error("Unreachable branch")
	default:
		h.logger.Error("Set real server sets failed.", "VipPort", params.VipPort, "validRSs", validRSs, "result", result.String())
		return apiVs.NewPutVsVipPortRsHealthInvalidBackend()
	}
	return apiVs.NewPutVsVipPortRsHealthFailure()
}
