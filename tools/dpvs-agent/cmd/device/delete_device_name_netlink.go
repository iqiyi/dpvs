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

	"github.com/vishvananda/netlink"

	"github.com/dpvs-agent/pkg/ipc/pool"
	apiDevice "github.com/dpvs-agent/restapi/operations/device"

	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

// ip link set xxx down
type setDeviceNetlinkDown struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewSetDeviceNetlinkDown(cp *pool.ConnPool, parentLogger hclog.Logger) *setDeviceNetlinkDown {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("SetDeviceNetlinkDown")
	}
	return &setDeviceNetlinkDown{connPool: cp, logger: logger}
}

func (h *setDeviceNetlinkDown) Handle(params apiDevice.DeleteDeviceNameNetlinkParams) middleware.Responder {
	cmd := fmt.Sprintf("ip link set %s down", params.Name)
	dev, err := netlink.LinkByName(params.Name)
	if err != nil {
		h.logger.Error("Get iface failed.", "Name", params.Name, "Error", err.Error())
		return apiDevice.NewDeleteDeviceNameNetlinkInternalServerError()
	}

	if err := netlink.LinkSetDown(dev); err != nil {
		h.logger.Error("Set iface down failed.", "cmd", cmd, "Error", err.Error())
		return apiDevice.NewDeleteDeviceNameNetlinkInternalServerError()
	}

	if err := netlink.LinkDel(dev); err != nil {
		h.logger.Error("Delete iface failed.", "Name", params.Name, "Error", err.Error())
		return apiDevice.NewDeleteDeviceNameNetlinkInternalServerError()
	}

	h.logger.Info("Set down and remove iface success.", "cmd", cmd)
	return apiDevice.NewDeleteDeviceNameNetlinkOK()
}
