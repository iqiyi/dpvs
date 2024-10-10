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

type postVsRs struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewPostVsRs(cp *pool.ConnPool, parentLogger hclog.Logger) *postVsRs {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("PostVsVipPortRs")
	}
	return &postVsRs{connPool: cp, logger: logger}
}

func (h *postVsRs) Handle(params apiVs.PostVsVipPortRsParams) middleware.Responder {
	front := types.NewRealServerFront()
	if err := front.ParseVipPortProto(params.VipPort); err != nil {
		h.logger.Error("Convert to virtual server failed.", "VipPort", params.VipPort, "Error", err.Error())
		return apiVs.NewPostVsVipPortRsInvalidFrontend()
	}

	if params.Rss == nil || params.Rss.Items == nil {
		return apiVs.NewPostVsVipPortRsInvalidFrontend()
	}

	rss := make([]*types.RealServerSpec, len(params.Rss.Items))
	for i, rs := range params.Rss.Items {
		var fwdmode types.DpvsFwdMode
		fwdmode.FromString(rs.Mode)
		rss[i] = types.NewRealServerSpec()
		rss[i].SetAf(front.GetAf())
		rss[i].SetPort(rs.Port)
		rss[i].SetWeight(uint32(rs.Weight))
		rss[i].SetProto(front.GetProto())
		rss[i].SetAddr(rs.IP)
		rss[i].SetOverloaded(rs.Overloaded)
		rss[i].SetFwdMode(fwdmode)
		// NOTE: inhibited set by healthcheck module with API /vs/${ID}/rs/health only
		// we clear it default
		inhibited := false
		if rs.Inhibited != nil {
			inhibited = *rs.Inhibited
		}
		rss[i].SetInhibited(&inhibited)
	}

	shareSnapshot := settings.ShareSnapshot()
	if shareSnapshot.ServiceLock(params.VipPort) {
		defer shareSnapshot.ServiceUnlock(params.VipPort)
	}

	result := front.Update(rss, h.connPool, h.logger)
	switch result {
	case types.EDPVS_EXIST, types.EDPVS_OK:
		// Update Snapshot
		vsModel := shareSnapshot.ServiceGet(params.VipPort)
		if vsModel == nil {
			spec := types.NewVirtualServerSpec()
			err := spec.ParseVipPortProto(params.VipPort)
			if err != nil {
				h.logger.Warn("Convert to virtual server failed.", "VipPort", params.VipPort, "Error", err.Error())
				// FIXME return
			}
			vss, err := spec.Get(h.connPool, h.logger)
			if err != nil {
				h.logger.Error("Get virtual server failed.", "svc VipPort", params.VipPort, "Error", err.Error())
				// FIXME return
			}

			for _, vs := range vss {
				if strings.EqualFold(vs.ID(), spec.ID()) {
					shareSnapshot.ServiceAdd(vs)
					break
				}
			}
		} else {
			vsModel.RSs = &models.RealServerExpandList{
				Items: make([]*models.RealServerSpecExpand, len(rss)),
			}

			for i, rs := range rss {
				vsModel.RSs.Items[i] = rs.GetModel()
			}
		}

		shareSnapshot.ServiceVersionUpdate(params.VipPort, h.logger)

		h.logger.Info("Set real server to virtual server success.", "VipPort", params.VipPort, "rss", rss, "result", result.String())
		return apiVs.NewPostVsVipPortRsOK()
	default:
		h.logger.Error("Set real server to virtual server failed.", "VipPort", params.VipPort, "rss", rss, "result", result.String())
		return apiVs.NewPostVsVipPortRsFailure()
	}
	return apiVs.NewPostVsVipPortRsInvalidBackend()
}
