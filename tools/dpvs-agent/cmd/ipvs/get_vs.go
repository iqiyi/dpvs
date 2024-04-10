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
	"github.com/dpvs-agent/pkg/settings"

	apiVs "github.com/dpvs-agent/restapi/operations/virtualserver"

	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

type getVs struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewGetVs(cp *pool.ConnPool, parentLogger hclog.Logger) *getVs {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("GetVs")
	}
	return &getVs{connPool: cp, logger: logger}
}

func (h *getVs) Handle(params apiVs.GetVsParams) middleware.Responder {
	shareSnapshot := settings.ShareSnapshot()
	if params.Healthcheck != nil && !*params.Healthcheck {
		return apiVs.NewGetVsOK().WithPayload(shareSnapshot.GetModels(h.logger))
	}

	// if params.Snapshot != nil && *params.Snapshot {
	//	shareSnapshot.DumpTo(settings.LocalConfigFile(), h.logger)
	// }

	front := types.NewVirtualServerFront()
	vss, err := front.Get(h.connPool, h.logger)
	if err != nil {
		h.logger.Error("Get virtual server list failed.", "Error", err.Error())
		return apiVs.NewGetVsNoContent()
	}

	vsModels := models.VirtualServerList{
		Items: make([]*models.VirtualServerSpecExpand, len(vss)),
	}

	h.logger.Info("Get all virtual server done.", "vss", vss)
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

	return apiVs.NewGetVsOK().WithPayload(&vsModels)
}
