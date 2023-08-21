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
	"github.com/dpvs-agent/pkg/ipc/pool"
	"github.com/dpvs-agent/pkg/ipc/types"

	apiDevice "github.com/dpvs-agent/restapi/operations/device"

	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

type delDeviceAddr struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewDelDeviceAddr(cp *pool.ConnPool, parentLogger hclog.Logger) *delDeviceAddr {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("DelDeviceAddr")
	}
	return &delDeviceAddr{connPool: cp, logger: logger}
}

// dpip addr add 192.168.88.16/32 dev dpdk0.102
func (h *delDeviceAddr) Handle(params apiDevice.DeleteDeviceNameAddrParams) middleware.Responder {
	addr := types.NewInetAddrDetail()
	addr.SetAddr(params.Spec.Addr)
	addr.SetIfName(params.Name)

	result := addr.Del(h.connPool, h.logger)
	switch result {
	case types.EDPVS_OK:
		h.logger.Info("Delete addr from device success.", "Device Name", params.Name, "Addr", params.Spec.Addr)
		return apiDevice.NewDeleteDeviceNameAddrOK()
	case types.EDPVS_NOTEXIST:
		h.logger.Warn("Delete a not exist addr from device done.", "Device Name", params.Name, "Addr", params.Spec.Addr, "result", result.String())
		return apiDevice.NewDeleteDeviceNameAddrOK()
	default:
		h.logger.Error("Delete addr from device failed.", "Device Name", params.Name, "Addr", params.Spec.Addr, "result", result.String())
	}

	return apiDevice.NewDeleteDeviceNameAddrInternalServerError()
}
