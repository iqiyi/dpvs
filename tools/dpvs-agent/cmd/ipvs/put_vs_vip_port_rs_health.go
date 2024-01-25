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

	shareSnapshot := settings.ShareSnapshot()

	shareSnapshot.ServiceRLock(params.VipPort) // RLock
	version := shareSnapshot.ServiceVersion(params.VipPort)
	// get active backends
	active, err := front.Get(h.connPool, h.logger)
	if err != nil {
		shareSnapshot.ServiceRUnlock(params.VipPort) // RUnlock
		return apiVs.NewPutVsVipPortRsHealthInvalidBackend()
	}
	shareSnapshot.ServiceRUnlock(params.VipPort) // RUnlock

	activeRSs := make(map[string]*types.RealServerSpec)
	for _, rs := range active {
		activeRSs[rs.ID()] = rs
	}

	validRSs := make([]*types.RealServerSpec, 0)
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
			newRs.SetOverloaded(rs.Overloaded)

			if _, existed := activeRSs[newRs.ID()]; existed {
				validRSs = append(validRSs, newRs)
				from := activeRSs[newRs.ID()]
				to := newRs
				h.logger.Info("real server update.", "ID", newRs.ID(), "client Version", params.Version, "from", from, "to", to)
			}
		}
	}

	if !strings.EqualFold(params.Version, version) {
		h.logger.Info("The service", "VipPort", params.VipPort, "version expired. The latest version", version)
		if shareSnapshot.ServiceRLock(params.VipPort) {
			defer shareSnapshot.ServiceRUnlock(params.VipPort)
		}
		vsModel := shareSnapshot.ServiceGet(params.VipPort)
		if vsModel == nil {
			spec := types.NewVirtualServerSpec()
			spec.ParseVipPortProto(params.VipPort)

			vss, err := spec.Get(h.connPool, h.logger)
			if err != nil {
				return apiVs.NewPutVsVipPortRsHealthInvalidBackend()
			}
			for _, vs := range vss {
				front := types.NewRealServerFront()
				front.ParseVipPortProto(vs.ID())

				front.SetNumDests(vs.GetNumDests())

				rss, err := front.Get(h.connPool, h.logger)
				if err != nil {
					h.logger.Error("Get real server list of virtual server failed.", "ID", vs.ID(), "Error", err.Error())
					return apiVs.NewPutVsVipPortRsHealthInvalidBackend()
				}
				vsModel = vs.GetModel()
				vsModel.RSs = new(models.RealServerExpandList)
				vsModel.RSs.Items = make([]*models.RealServerSpecExpand, len(rss))
				for i, rs := range rss {
					rsModel := rs.GetModel()
					// rsStats := (*types.ServerStats)(rsModel.Stats)
					vsModel.RSs.Items[i] = rsModel
					// vsStats.Increase(rsStats)
				}
				shareSnapshot.ServiceUpsert(vsModel)
			}
		}
		h.logger.Error("Virtual service version miss match.", "VipPort", params.VipPort, "correct version", version, "url query param version", params.Version)
		return apiVs.NewPutVsVipPortRsHealthUnexpected().WithPayload(vsModel)
	}

	if shareSnapshot.ServiceLock(params.VipPort) {
		defer shareSnapshot.ServiceUnlock(params.VipPort)
	}

	existOnly := true
	result := front.Edit(existOnly, validRSs, h.connPool, h.logger)
	switch result {
	case types.EDPVS_EXIST, types.EDPVS_OK:
		// update Snapshot
		if newRSs, err := front.Get(h.connPool, h.logger); err == nil {
			rsModels := new(models.RealServerExpandList)
			rsModels.Items = make([]*models.RealServerSpecExpand, len(newRSs))
			for i, rs := range newRSs {
				rsModels.Items[i] = rs.GetModel()
			}

			vsModel := shareSnapshot.ServiceGet(params.VipPort)
			if vsModel == nil {
				spec := types.NewVirtualServerSpec()
				spec.ParseVipPortProto(params.VipPort)

				vss, err := spec.Get(h.connPool, h.logger)
				if err != nil {
					return apiVs.NewPutVsVipPortRsHealthInvalidBackend()
				}
				for _, vs := range vss {
					front := types.NewRealServerFront()
					front.ParseVipPortProto(vs.ID())

					front.SetNumDests(vs.GetNumDests())

					rss, err := front.Get(h.connPool, h.logger)
					if err != nil {
						h.logger.Error("Get real server list of virtual server failed.", "ID", vs.ID(), "Error", err.Error())
						return apiVs.NewPutVsVipPortRsHealthInvalidBackend()
					}
					vsModel = vs.GetModel()
					vsModel.RSs = new(models.RealServerExpandList)
					vsModel.RSs.Items = make([]*models.RealServerSpecExpand, len(rss))
					for i, rs := range rss {
						rsModel := rs.GetModel()
						vsModel.RSs.Items[i] = rsModel
						// rsStats := (*types.ServerStats)(rsModel.Stats)
						// vsStats.Increase(rsStats)
					}
				}
			}
			vsModel.RSs = rsModels
			shareSnapshot.ServiceUpsert(vsModel)
		}

		h.logger.Info("Set real server sets success.", "VipPort", params.VipPort, "validRSs", validRSs, "result", result.String())
		return apiVs.NewPutVsVipPortRsHealthOK()
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
