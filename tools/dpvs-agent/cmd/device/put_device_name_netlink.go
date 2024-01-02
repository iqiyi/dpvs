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
	"fmt"
	"syscall"

	"github.com/vishvananda/netlink"

	"github.com/dpvs-agent/pkg/ipc/pool"
	apiDevice "github.com/dpvs-agent/restapi/operations/device"

	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

// ip link set xxx up
type setDeviceNetlinkUp struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewSetDeviceNetlinkUp(cp *pool.ConnPool, parentLogger hclog.Logger) *setDeviceNetlinkUp {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("SetDeviceNetlinkUp")
	}
	return &setDeviceNetlinkUp{connPool: cp, logger: logger}
}

func (h *setDeviceNetlinkUp) Handle(params apiDevice.PutDeviceNameNetlinkParams) middleware.Responder {
	dev := &netlink.Device{LinkAttrs: netlink.LinkAttrs{MTU: 1500, Name: params.Name}}

	if err := netlink.LinkAdd(dev); err != syscall.EEXIST {
		h.logger.Error("Check device isExist failed.", "Device Name", params.Name, "Error", err.Error())
		return apiDevice.NewPutDeviceNameNetlinkInternalServerError()
	}

	if err := netlink.LinkSetUp(dev); err != nil {
		h.logger.Error("Set device link up failed.", "Device Name", params.Name, "Error", err.Error())
		return apiDevice.NewPutDeviceNameNetlinkInternalServerError()
	}

	cmd := fmt.Sprintf("ip link set %s up", params.Name)
	h.logger.Info("Set device link up success.", "cmd", cmd)
	return apiDevice.NewPutDeviceNameNetlinkOK()
}
