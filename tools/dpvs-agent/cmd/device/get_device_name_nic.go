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
	"strings"

	"github.com/dpvs-agent/models"
	"github.com/dpvs-agent/pkg/ipc/pool"
	"github.com/dpvs-agent/pkg/ipc/types"

	apiDevice "github.com/dpvs-agent/restapi/operations/device"

	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

type getDeviceNameNic struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewGetDeviceNameNic(cp *pool.ConnPool, parentLogger hclog.Logger) *getDeviceNameNic {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("GetDeviceNameNic")
	}
	return &getDeviceNameNic{connPool: cp, logger: logger}
}

// dpip link show xxx
func (h *getDeviceNameNic) Handle(params apiDevice.GetDeviceNameNicParams) middleware.Responder {
	name := make([]byte, 0x10)
	copy(name[:], params.Name[:])

	desc := types.NewNetifNicDesc()
	list, err := desc.GetPortList(h.connPool, h.logger)
	if err != types.EDPVS_OK {
		h.logger.Info("Get netif ports failed.", "Error", err.String())
		return apiDevice.NewGetDeviceNameNicInternalServerError()
	}

	h.logger.Info("Get netif port success.", "port list", list)
	exist := false
	specModels := new(models.NicDeviceSpecList)
	specModels.Items = make([]*models.NicDeviceSpec, len(list.Entries))

	for i, entry := range list.Entries {
		specModels.Items[i] = new(models.NicDeviceSpec)
		if strings.EqualFold(strings.ToLower(string(name)), strings.ToLower(entry.GetName())) {
			exist = true
		}

		portName := entry.GetName()
		desc.SetName(portName)
		detail, err := desc.GetPortBasic(h.connPool, h.logger)
		if err != types.EDPVS_OK {
			h.logger.Error("Get netif port base info failed.", "portName", portName, "Error", err.String())
			return apiDevice.NewGetDeviceNameNicInternalServerError()
		}
		h.logger.Info("Get netif port base info success.", "portName", portName, "port detail", detail)

		stats, err := desc.GetPortStats(h.connPool, h.logger)
		if err != types.EDPVS_OK {
			h.logger.Error("Get netif port stats info failed.", "portName", portName, "Error", err.String())
			return apiDevice.NewGetDeviceNameNicInternalServerError()
		}
		h.logger.Info("Get netif port stats info success.", "portName", portName, "port stats", stats)

		specModels.Items[i].Detail = detail.GetModel()
		specModels.Items[i].Stats = stats.GetModel()
	}

	if exist {
		if *params.Stats {
		}
	}

	return apiDevice.NewGetDeviceNameNicOK().WithPayload(specModels)
}
