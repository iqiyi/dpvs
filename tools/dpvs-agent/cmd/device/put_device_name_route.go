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

type putDeviceRoute struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewPutDeviceRoute(cp *pool.ConnPool, parentLogger hclog.Logger) *putDeviceRoute {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("PutDeviceRoute")
	}
	return &putDeviceRoute{connPool: cp, logger: logger}
}

// dpip route add 192.168.88.16/32 dev dpdk0.102 scope kni_host
func (h *putDeviceRoute) Handle(params apiDevice.PutDeviceNameRouteParams) middleware.Responder {

	// dest [addr], [mask] and [dev name] is useful of delete route only
	route := types.NewRouteDetail()
	route.SetDevice(params.Name)
	if params.Spec == nil {
		// FIXME return front invalid
		return apiDevice.NewPutDeviceNameRouteInternalServerError()
	}

	src := ""
	route.SetDst(params.Spec.Dst)
	if route.SetSrc(params.Spec.Src) {
		src = fmt.Sprintf("src %s", params.Spec.Src)
	}

	gateway := ""
	if route.SetGateway(params.Spec.Gateway) {
		gateway = fmt.Sprintf("via %s", params.Spec.Gateway)
	}
	route.SetScope(params.Spec.Scope)
	route.SetMtu(params.Spec.Mtu)
	route.SetMetric(params.Spec.Metric)

	cmd := fmt.Sprintf("dpip route add %s %s dev %s %s", params.Spec.Dst, gateway, params.Name, src)
	result := route.Add(h.connPool, h.logger)
	switch result {
	case types.EDPVS_OK:
		h.logger.Info("Set dpdk route success.", "cmd", cmd)
		return apiDevice.NewPutDeviceNameRouteCreated()
	// case types.EDPVS_EXIST:
	// FIXME: update ? return apiDevice.NewPutDeviceNameRouteOK()
	default:
		h.logger.Info("Set dpdk route failed.", "cmd", cmd, "result", result.String())
	}

	return apiDevice.NewPutDeviceNameRouteInternalServerError()
}
