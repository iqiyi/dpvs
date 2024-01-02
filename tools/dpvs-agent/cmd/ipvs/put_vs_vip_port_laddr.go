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

	apiVs "github.com/dpvs-agent/restapi/operations/virtualserver"

	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

type putVsLaddr struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewPutVsLaddr(cp *pool.ConnPool, parentLogger hclog.Logger) *putVsLaddr {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("PutVsVipPortLaddr")
	}
	return &putVsLaddr{connPool: cp, logger: logger}
}

func (h *putVsLaddr) Handle(params apiVs.PutVsVipPortLaddrParams) middleware.Responder {
	laddr := types.NewLocalAddrFront()

	err := laddr.ParseVipPortProto(params.VipPort)
	if err != nil {
		h.logger.Error("Convert to virtual server failed.", "VipPort", params.VipPort, "Error", err.Error())
		return apiVs.NewPutVsVipPortLaddrInvalidFrontend()
	}

	lds := make([]*types.LocalAddrDetail, 1)

	lds[0] = types.NewLocalAddrDetail()
	lds[0].SetAddr(params.Spec.Addr)
	lds[0].SetIfName(params.Spec.Device)

	result := laddr.Add(lds, h.connPool, h.logger)
	switch result {
	case types.EDPVS_OK:
		h.logger.Info("Set virtual server Local IP success.", "VipPort", params.VipPort, "Local Addr", params.Spec.Addr)
		return apiVs.NewPutVsVipPortLaddrOK()
	case types.EDPVS_EXIST:
		h.logger.Warn("Local IP already exist.", "VipPort", params.VipPort, "Local Addr", params.Spec.Addr, "result", result.String())
		return apiVs.NewPutVsVipPortLaddrOK()
	default:
		h.logger.Error("Set virtual server Local IP failed.", "VipPort", params.VipPort, "Local Addr", params.Spec.Addr, "result", result.String())
	}

	return apiVs.NewPutVsVipPortLaddrFailure()
}
