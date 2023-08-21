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

type getVsLaddr struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewGetVsLaddr(cp *pool.ConnPool, parentLogger hclog.Logger) *getVsLaddr {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("GetVsVipPortLaddr")
	}
	return &getVsLaddr{connPool: cp, logger: logger}
}

func (h *getVsLaddr) Handle(params apiVs.GetVsVipPortLaddrParams) middleware.Responder {
	laddr := types.NewLocalAddrFront()
	if err := laddr.ParseVipPortProto(params.VipPort); err != nil {
		// FIXME: return all laddr
		h.logger.Error("Convert to virtual server failed.", "VipPort", params.VipPort, "Error", err.Error())
		return apiVs.NewGetVsVipPortLaddrNotFound()
	}

	lds, err := laddr.Get(h.connPool, h.logger)
	if err != nil {
		h.logger.Error("Get virtual server laddr failed.", "VipPort", params.VipPort, "Error", err.Error())
		return apiVs.NewGetVsVipPortLaddrNotFound()
	}

	h.logger.Info("Get virtual server laddr success.", "VipPort", params.VipPort, "local addr details", "lds", lds)
	laddrModels := new(models.LocalAddressExpandList)
	laddrModels.Items = make([]*models.LocalAddressSpecExpand, len(lds))
	for i, detail := range lds {
		h.logger.Info("Virtual Server", "VipPort", params.VipPort, "detail", detail)
		laddrModels.Items[i] = detail.GetModel()
	}

	return apiVs.NewGetVsVipPortLaddrOK().WithPayload(laddrModels)
}
