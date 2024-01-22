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
	front := types.NewVirtualServerFront()
	vss, err := front.Get(h.connPool, h.logger)
	if err != nil {
		h.logger.Error("Get virtual server list failed.", "Error", err.Error())
		// FIXME: Invalid
		return apiVs.NewGetVsOK()
	}

	shareSnapshot := settings.ShareSnapshot()

	h.logger.Info("Get all virtual server done.", "vss", vss)
	for _, vs := range vss {
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
		vsStats := (*types.ServerStats)(vsModel.Stats)
		vsModel.RSs = new(models.RealServerExpandList)
		vsModel.RSs.Items = make([]*models.RealServerSpecExpand, len(rss))

		for j, rs := range rss {
			rsModel := rs.GetModel()
			rsStats := (*types.ServerStats)(rsModel.Stats)
			vsModel.RSs.Items[j] = rsModel
			vsStats.Increase(rsStats)
		}

		if shareSnapshot.NodeSpec.Laddrs == nil {
			laddr := types.NewLocalAddrFront()
			if err := laddr.ParseVipPortProto(vs.ID()); err != nil {
				// FIXME: Invalid
				return apiVs.NewGetVsOK()
			}

			laddrs, err := laddr.Get(h.connPool, h.logger)
			if err != nil {
				// FIXME: Invalid
				return apiVs.NewGetVsOK()
			}

			shareSnapshot.NodeSpec.Laddrs = new(models.LocalAddressExpandList)
			laddrModels := shareSnapshot.NodeSpec.Laddrs
			laddrModels.Items = make([]*models.LocalAddressSpecExpand, len(laddrs))
			for k, lip := range laddrs {
				laddrModels.Items[k] = lip.GetModel()
			}
		}

		shareSnapshot.ServiceLock(vs.ID())
		shareSnapshot.ServiceUpsert(vsModel)
		shareSnapshot.ServiceUnlock(vs.ID())
	}

	if params.Snapshot != nil && *params.Snapshot {
		shareSnapshot.DumpTo(settings.LocalConfigFile(), h.logger)
	}

	return apiVs.NewGetVsOK().WithPayload(shareSnapshot.GetModels(h.logger))
}
