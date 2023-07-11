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

	"github.com/dpvs-agent/pkg/ipc/pool"
	"github.com/dpvs-agent/pkg/ipc/types"

	apiDevice "github.com/dpvs-agent/restapi/operations/device"

	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

type putDeviceNameNic struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewPutDeviceNameNic(cp *pool.ConnPool, parentLogger hclog.Logger) *putDeviceNameNic {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("PutDeviceNameNic")
	}
	return &putDeviceNameNic{connPool: cp, logger: logger}
}

// ITEM  [promisc|forward2kni|tc-ingress|tc-egress] / [link]
// VALUE [on|off] / [up|down]
// dpip link set nic-name  $ITEM $VALUE
func (h *putDeviceNameNic) Handle(params apiDevice.PutDeviceNameNicParams) middleware.Responder {
	set := false
	cmd := ""
	desc := types.NewNetifNicDesc()
	if !set {
		set = desc.SetFwd2Kni(params.Name, *params.Forward2Kni)
		cmd = fmt.Sprintf("dpip link set %s %s", params.Name, params.Forward2Kni)
	}
	if !set {
		set = desc.SetLink(params.Name, *params.Link)
		cmd = fmt.Sprintf("dpip link set %s %s", params.Name, params.Link)
	}
	if !set {
		set = desc.SetPromisc(params.Name, *params.Promisc)
		cmd = fmt.Sprintf("dpip link set %s %s", params.Name, params.Promisc)
	}

	if !set {
		h.logger.Error("dpdk link port set failed.", "Name", params.Name)
		return apiDevice.NewPutDeviceNameNicInternalServerError()
	}

	result := desc.Set(h.connPool, h.logger)
	switch result {
	case types.EDPVS_OK:
		h.logger.Info("Set dpdk port success.", "cmd", cmd)
		return apiDevice.NewPutDeviceNameNicOK()
	default:
		h.logger.Info("Set dpdk port failed.", "cmd", cmd, "result", result.String())
	}

	return apiDevice.NewPutDeviceNameNicInternalServerError()
}
