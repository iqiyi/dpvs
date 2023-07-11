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

package device

import (
	// "github.com/dpvs-agent/models"
	"github.com/dpvs-agent/pkg/ipc/pool"
	"github.com/dpvs-agent/pkg/ipc/types"

	apiDevice "github.com/dpvs-agent/restapi/operations/device"

	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

type delDeviceVlan struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewDelDeviceVlan(cp *pool.ConnPool, parentLogger hclog.Logger) *delDeviceVlan {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("DelDeviceVlan")
	}
	return &delDeviceVlan{connPool: cp, logger: logger}
}

// dpip vlan del dpdk0.102
func (h *delDeviceVlan) Handle(params apiDevice.DeleteDeviceNameVlanParams) middleware.Responder {
	// vlan device delete is need device name only
	vlan := types.NewVlanDevice()
	vlan.SetIfName(params.Name)

	result := vlan.Del(h.connPool, h.logger)
	switch result {
	case types.EDPVS_OK:
		h.logger.Info("Delete dpvs vlan success.", "Vlan Name", params.Name)
		return apiDevice.NewDeleteDeviceNameVlanOK()
	case types.EDPVS_NOTEXIST:
		h.logger.Warn("Delete dpvs vlan done.", "Vlan Name", params.Name, "result", result.String())
		return apiDevice.NewDeleteDeviceNameVlanOK()
	default:
		h.logger.Error("Delete dpvs vlan failed.", "Vlan Name", params.Name, "result", result.String())
	}

	return apiDevice.NewDeleteDeviceNameVlanInternalServerError()
}
