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

type delVsLaddr struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewDelVsLaddr(cp *pool.ConnPool, parentLogger hclog.Logger) *delVsLaddr {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("DelVsVipPortLaddr")
	}
	return &delVsLaddr{connPool: cp, logger: logger}
}

func (h *delVsLaddr) Handle(params apiVs.DeleteVsVipPortLaddrParams) middleware.Responder {
	laddr := types.NewLocalAddrFront()
	if err := laddr.ParseVipPortProto(params.VipPort); err != nil {
		h.logger.Error("Convert to virtual server failed.", "VipPort", params.VipPort, "Error", err.Error())
		return apiVs.NewDeleteVsVipPortLaddrInvalidFrontend()
	}

	lds := make([]*types.LocalAddrDetail, 1)
	lds[0] = types.NewLocalAddrDetail()
	lds[0].SetAfByAddr(params.Spec.Addr)
	lds[0].SetAddr(params.Spec.Addr)
	lds[0].SetIfName(params.Spec.Device)

	result := laddr.Del(lds, h.connPool, h.logger)
	switch result {
	case types.EDPVS_OK:
		h.logger.Info("Delete local ip from virtual server success.", "VipPort", params.VipPort, "Addr", params.Spec.Addr, "Device", params.Spec.Device)
		return apiVs.NewDeleteVsVipPortLaddrOK()
	case types.EDPVS_NOTEXIST:
		h.logger.Warn("Delete not exist local ip from virtual server done.", "VipPort", params.VipPort, "Addr", params.Spec.Addr, "Device", params.Spec.Device)
		return apiVs.NewDeleteVsVipPortLaddrOK()
	default:
		h.logger.Error("Delete local ip from virtual server failed.", "VipPort", params.VipPort, "Addr", params.Spec.Addr, "Device", params.Spec.Device, "result", result.String())
	}

	return apiVs.NewDeleteVsVipPortLaddrFailure()
}
