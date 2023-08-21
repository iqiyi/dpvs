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

type delDeviceRoute struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewDelDeviceRoute(cp *pool.ConnPool, parentLogger hclog.Logger) *delDeviceRoute {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("DelDeviceRoute")
	}
	return &delDeviceRoute{connPool: cp, logger: logger}
}

// dpip del route 192.168.88.16/32 dev dpdk0.102
func (h *delDeviceRoute) Handle(params apiDevice.DeleteDeviceNameRouteParams) middleware.Responder {

	// dest [addr], [mask] and [dev name] is useful of delete route only
	route := types.NewRouteDetail()
	route.SetDevice(params.Name)
	if params.Spec == nil {
		// FIXME: front error
		return apiDevice.NewDeleteDeviceNameRouteInternalServerError()
	}

	route.SetDst(params.Spec.Dst)
	route.SetScope(params.Spec.Scope)
	/*
		route.SetSrc(params.Spec.Src)
		route.SetGateway(params.Spec.Gateway)
		route.SetScope(params.Spec.Scope)
		route.SetMtu(params.Spec.Mtu)
		route.SetMetric(params.Spec.Metric)
	*/
	result := route.Del(h.connPool, h.logger)
	switch result {
	case types.EDPVS_OK:
		h.logger.Info("Delete route success.", "Device Name", params.Name, "route Dst", params.Spec.Dst)
		return apiDevice.NewDeleteDeviceNameRouteOK()
	case types.EDPVS_NOTEXIST:
		h.logger.Warn("Delete not exist route done.", "Device Name", params.Name, "route Dst", params.Spec.Dst, "result", result.String())
		return apiDevice.NewDeleteDeviceNameRouteOK()
	default:
		h.logger.Error("Delete route failed.", "Device Name", params.Name, "route Dst", params.Spec.Dst, "result", result.String())
	}

	return apiDevice.NewDeleteDeviceNameRouteInternalServerError()
}
