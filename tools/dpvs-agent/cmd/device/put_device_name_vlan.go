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
	"strconv"
	"strings"

	// "github.com/dpvs-agent/models"
	"github.com/dpvs-agent/pkg/ipc/pool"
	"github.com/dpvs-agent/pkg/ipc/types"

	apiDevice "github.com/dpvs-agent/restapi/operations/device"

	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

type putDeviceVlan struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewPutDeviceVlan(cp *pool.ConnPool, parentLogger hclog.Logger) *putDeviceVlan {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("PutDeviceVlan")
	}
	return &putDeviceVlan{connPool: cp, logger: logger}
}

// dpip vlan add dpdk0.102 link dpdk0 id 102
func (h *putDeviceVlan) Handle(params apiDevice.PutDeviceNameVlanParams) middleware.Responder {
	vlanName := strings.ToLower(params.Name)

	items := strings.Split(vlanName, ".")
	if len(items) != 2 {
		return apiDevice.NewPutDeviceNameVlanInternalServerError()
	}

	dev := params.Spec.Device
	if len(dev) == 0 {
		dev = items[0]
	}

	id := params.Spec.ID
	if len(id) == 0 {
		id = items[1]
	}

	cmd := fmt.Sprintf("dpip vlan add %s link %s id %s", params.Name, dev, id)

	vlan := types.NewVlanDevice()
	vlan.SetIfName(vlanName)
	vlan.SetRealDev(dev)
	i, err := strconv.Atoi(id)
	if err != nil {
		return apiDevice.NewPutDeviceNameVlanInternalServerError()
	}
	vlan.SetId(uint16(i))

	result := vlan.Add(h.connPool, h.logger)
	switch result {
	case types.EDPVS_OK:
		h.logger.Info("Set dpdk vlan success.", "cmd", cmd)
		return apiDevice.NewDeleteDeviceNameVlanOK()
	default:
		h.logger.Error("Set dpdk vlan failed.", "cmd", cmd, "result", result.String())
	}

	return apiDevice.NewDeleteDeviceNameVlanInternalServerError()
}
