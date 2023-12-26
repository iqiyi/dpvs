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
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/vishvananda/netlink"

	"github.com/dpvs-agent/pkg/ipc/pool"
	"github.com/dpvs-agent/pkg/settings"
	apiDevice "github.com/dpvs-agent/restapi/operations/device"

	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

type putDeviceNetlinkAddr struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewPutDeviceNetlinkAddr(cp *pool.ConnPool, parentLogger hclog.Logger) *putDeviceNetlinkAddr {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("PutDeviceNetlinkAddr")
	}
	return &putDeviceNetlinkAddr{connPool: cp, logger: logger}
}

// ip addr add 10.0.0.1/32 dev eth0
func (h *putDeviceNetlinkAddr) Handle(params apiDevice.PutDeviceNameNetlinkAddrParams) middleware.Responder {
	// h.logger.Info("/v2/device/", params.Name, "/netlink/addr ", params.Spec.Addr)
	if err := NetlinkAddrAdd(params.Spec.Addr, params.Name, h.logger); err != nil {
		return apiDevice.NewPutDeviceNameNetlinkAddrInternalServerError()
	}
	if params.Snapshot != nil && *params.Snapshot {
		AnnouncePort := settings.ShareSnapshot().NodeSpec.AnnouncePort
		AnnouncePort.Switch = params.Name
	}
	return apiDevice.NewPutDeviceNameNetlinkAddrOK()
}

func NetlinkAddrAdd(addr, device string, logger hclog.Logger) error {
	var cidr string
	if strings.Count(addr, "/") == 0 {
		ip := net.ParseIP(addr)
		if ip == nil {
			logger.Info("Parse IP failed.", "Addr", addr)
			return errors.New("Parse IP Failed.")
		}
		if ip.To4() != nil {
			cidr = addr + "/32"
		} else {
			cidr = addr + "/128"
		}
	} else {
		cidr = addr
	}

	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		logger.Error("Parse CIDR failed.", "cidr", cidr, "Error", err.Error())
		return err
	}

	ipnet.IP = ip
	netlinkAddr := &netlink.Addr{IPNet: ipnet}

	link, err := netlink.LinkByName(device)
	if err != nil {
		logger.Error("netlink.LinkByName() failed.", "device", device, "Error", err.Error())
		return err
	}

	if err := netlink.AddrAdd(link, netlinkAddr); err != nil {
		logger.Error("netlink.AddrAdd() failed.", "Error", err.Error())
		return err
	}

	cmd := fmt.Sprintf("ip addr add %s dev %s", cidr, device)
	logger.Info("Device add Addr success.", "cmd", cmd)
	return nil
}
