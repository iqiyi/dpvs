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
	"net"
	"strings"

	"github.com/vishvananda/netlink"

	"github.com/dpvs-agent/pkg/ipc/pool"
	apiDevice "github.com/dpvs-agent/restapi/operations/device"

	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

type delDeviceNetlinkAddr struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewDelDeviceNetlinkAddr(cp *pool.ConnPool, parentLogger hclog.Logger) *delDeviceNetlinkAddr {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("DelDeviceNetlinkAddr")
	}
	return &delDeviceNetlinkAddr{connPool: cp, logger: logger}
}

func (h *delDeviceNetlinkAddr) Handle(params apiDevice.DeleteDeviceNameNetlinkAddrParams) middleware.Responder {
	var cidr string
	if strings.Count(params.Spec.Addr, "/") == 0 {
		ip := net.ParseIP(params.Spec.Addr)
		if ip == nil {
			return apiDevice.NewDeleteDeviceNameNetlinkAddrInternalServerError()
		}

		if ip.To4() != nil {
			cidr = params.Spec.Addr + "/32"
		} else {
			cidr = params.Spec.Addr + "/128"
		}
	}

	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return apiDevice.NewDeleteDeviceNameNetlinkAddrInternalServerError()
	}

	cmd := fmt.Sprintf("ip addr del %s dev %s", cidr, params.Name)

	ipnet.IP = ip
	addr := &netlink.Addr{IPNet: ipnet}

	link, err := netlink.LinkByName(params.Name)
	if err != nil {
		h.logger.Error("Get linux network device by name failed.", "device Name", params.Name, "Error", err.Error())
		return apiDevice.NewDeleteDeviceNameNetlinkAddrInternalServerError()
	}

	if err := netlink.AddrDel(link, addr); err != nil {
		h.logger.Error("linux network operation failed.", "cmd", cmd, "Error", err.Error())
		return apiDevice.NewDeleteDeviceNameNetlinkAddrInternalServerError()
	}

	h.logger.Info("linux network operation success.", "cmd", cmd)
	return apiDevice.NewDeleteDeviceNameNetlinkAddrOK()
}
