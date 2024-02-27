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

type getVsVipPort struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewGetVsVipPort(cp *pool.ConnPool, parentLogger hclog.Logger) *getVsVipPort {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("GetVsVipPort")
	}
	return &getVsVipPort{connPool: cp, logger: logger}
}

func (h *getVsVipPort) Handle(params apiVs.GetVsVipPortParams) middleware.Responder {
	shareSnapshot := settings.ShareSnapshot()
	if params.Healthcheck != nil && !*params.Healthcheck {
		vsModel := shareSnapshot.ServiceGet(params.VipPort)
		if vsModel != nil {
			vsModels := new(models.VirtualServerList)
			vsModels.Items = make([]*models.VirtualServerSpecExpand, 1)
			vsModels.Items[0] = vsModel
			return apiVs.NewGetVsVipPortOK().WithPayload(vsModels)
		}
	}

	vaild := true
	var vss []*types.VirtualServerSpec
	spec := types.NewVirtualServerSpec()
	err := spec.ParseVipPortProto(params.VipPort)
	if err != nil {
		vaild = false
		if params.Healthcheck != nil && !*params.Healthcheck {
			// invalid VipPort string
			// respond full cache info
			vsModels := shareSnapshot.GetModels(h.logger)
			if len(vsModels.Items) != 0 {
				return apiVs.NewGetVsVipPortOK().WithPayload(vsModels)
			}
			// read from dpvs memory
		}

		h.logger.Warn("Convert to virtual server failed. Get All virtual server.", "VipPort", params.VipPort, "Error", err.Error())
		front := types.NewVirtualServerFront()
		vss, err = front.Get(h.connPool, h.logger)
	} else {
		vss, err = spec.Get(h.connPool, h.logger)
	}

	if err != nil {
		h.logger.Error("Get virtual server list failed.", "Error", err.Error())
		return apiVs.NewGetVsVipPortNotFound()
	}

	vsModels := &models.VirtualServerList{
		Items: make([]*models.VirtualServerSpecExpand, len(vss)),
	}

	for i, vs := range vss {
		front := types.NewRealServerFront()

		err := front.ParseVipPortProto(vs.ID())
		if err != nil {
			h.logger.Error("Convert to virtual server failed. virtual server", "ID", vs.ID(), "Error", err.Error())
			continue
		}
		front.SetNumDests(vs.GetNumDests())

		rss, err := front.Get(h.connPool, h.logger)
		if err != nil {
			h.logger.Error("Get real server list of virtual server failed.", "ID", vs.ID(), "Error", err.Error())
			continue
		}

		h.logger.Info("Get real server list of virtual server success.", "ID", vs.ID(), "rss", rss)

		vsModel := vs.GetModel()
		vsModels.Items[i] = vsModel
		vsStats := (*types.ServerStats)(vsModel.Stats)
		vsModel.RSs = new(models.RealServerExpandList)
		vsModel.RSs.Items = make([]*models.RealServerSpecExpand, len(rss))

		for j, rs := range rss {
			rsModel := rs.GetModel()
			rsStats := (*types.ServerStats)(rsModel.Stats)
			vsModel.RSs.Items[j] = rsModel
			vsStats.Increase(rsStats)
		}
	}

	if vaild {
		targetModels := &models.VirtualServerList{
			Items: make([]*models.VirtualServerSpecExpand, 1),
		}

		for _, vsModel := range vsModels.Items {
			typesVsModel := (*types.VirtualServerSpecExpandModel)(vsModel)
			if strings.EqualFold(spec.ID(), typesVsModel.ID()) {
				targetModels.Items[0] = vsModel
				return apiVs.NewGetVsVipPortOK().WithPayload(targetModels)
			}
		}
	}

	return apiVs.NewGetVsVipPortOK().WithPayload(vsModels)
}
