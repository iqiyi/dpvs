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
	"github.com/dpvs-agent/pkg/settings"

	apiVs "github.com/dpvs-agent/restapi/operations/virtualserver"

	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

type delVsItem struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewDelVsItem(cp *pool.ConnPool, parentLogger hclog.Logger) *delVsItem {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("DelVsVipPort")
	}
	return &delVsItem{connPool: cp, logger: logger}
}

func (h *delVsItem) Handle(params apiVs.DeleteVsVipPortParams) middleware.Responder {
	vs := types.NewVirtualServerSpec()
	if err := vs.ParseVipPortProto(params.VipPort); err != nil {
		h.logger.Error("Convert to virtual server failed.", "VipPort", params.VipPort, "Error", err.Error())
		return apiVs.NewDeleteVsVipPortFailure()
	}

	shareSnapshot := settings.ShareSnapshot()
	snapshot := shareSnapshot.SnapshotGet(params.VipPort)
	if snapshot != nil {
		snapshot.Lock()
		defer snapshot.Unlock()
	}

	result := vs.Del(h.connPool, h.logger)
	switch result {
	case types.EDPVS_OK:
		shareSnapshot.ServiceDel(params.VipPort)
		h.logger.Info("Del virtual server success.", "VipPort", params.VipPort)
		return apiVs.NewDeleteVsVipPortOK()
	case types.EDPVS_NOTEXIST:
		shareSnapshot.ServiceDel(params.VipPort)
		h.logger.Warn("Del a not exist virtual server done.", "VipPort", params.VipPort, "result", result.String())
		return apiVs.NewDeleteVsVipPortNotFound()
	default:
		h.logger.Error("Del virtual server failed.", "VipPort", params.VipPort, "result", result.String())
	}
	return apiVs.NewDeleteVsVipPortFailure()
}
