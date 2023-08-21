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
	"github.com/dpvs-agent/models"
	"github.com/dpvs-agent/pkg/ipc/pool"
	"github.com/dpvs-agent/pkg/ipc/types"

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
	var vss []*types.VirtualServerSpec
	spec := types.NewVirtualServerSpec()
	err := spec.ParseVipPortProto(params.VipPort)
	if err != nil {
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

	vsModels := new(models.VirtualServerList)
	vsModels.Items = make([]*models.VirtualServerSpecExpand, len(vss))

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

		vsModels.Items[i] = vs.GetModel()
		vsStats := (*types.ServerStats)(vsModels.Items[i].Stats)
		vsModels.Items[i].RSs = new(models.RealServerExpandList)
		vsModels.Items[i].RSs.Items = make([]*models.RealServerSpecExpand, len(rss))

		for j, rs := range rss {
			rsModel := rs.GetModel()
			rsStats := (*types.ServerStats)(rsModel.Stats)
			vsModels.Items[i].RSs.Items[j] = rsModel
			vsStats.Increase(rsStats)
		}
	}

	return apiVs.NewGetVsVipPortOK().WithPayload(vsModels)
}
