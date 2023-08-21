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

/*
// SIOCDIFADDR

import (
	"net"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"

	// "github.com/dpvs-agent/models"
	"github.com/dpvs-agent/pkg/ipc/pool"

	apiDevice "github.com/dpvs-agent/restapi/operations/device"

	"github.com/go-openapi/runtime/middleware"
)

type deleteDeviceNameLinuxAddr struct {
	connPool *pool.ConnPool
}

func NewDeleteDeviceNameLinuxAddr(cp *pool.ConnPool) *deleteDeviceNameLinuxAddr {
	return &deleteDeviceNameLinuxAddr{connPool: cp}
}

func (h *deleteDeviceNameLinuxAddr) Handler(params *apiDevice.DeleteDeviceNameLinuxAddrParams) middleware.Responder {
	if len(params.Spec.Addr) == 0 {
		return apiDevice.NewDeleteDeviceNameLinuxAddrInternalServerError()
	}

	items := strings.Split(params.Spec.Addr, "/")

	addr := net.ParseIP(items[0])
	if addr == nil {
		return apiDevice.NewDeleteDeviceNameLinuxAddrInternalServerError()
	}

	if addr.To4() != nil {
		mask := 32
		if len(items) > 1 {
			m, err := strconv.Atoi(items[1])
			if err == nil {
				mask = m
			}
		}
		if err := delAddr4(params.Name, addr, mask); err != nil {
			return apiDevice.NewDeleteDeviceNameLinuxAddrInternalServerError()
		}
	} else {
		mask := 128
		if len(items) > 1 {
			m, err := strconv.Atoi(items[1])
			if err == nil {
				mask = m
			}
		}
		if err := setAddr6(params.Name, addr, mask); err != nil {
			return apiDevice.NewDeleteDeviceNameLinuxAddrInternalServerError()
		}
	}
	return apiDevice.NewDeleteDeviceNameLinuxAddrOK()
}

func delAddr4(name string, ip net.IP, mask int) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}

	defer unix.Close(fd)
	sa := socketAddr4Request{}
	sa.addr.Family = unix.AF_INET
	copy(sa.name[:], name)

	buf, err := ip.MarshalText()
	if err != nil {
		return err
	}

	copy(sa.addr.Addr[:], buf)
	// delete address
	if err := ioctl(fd, unix.SIOCDIFADDR, uintptr(unsafe.Pointer(&sa))); err != nil {
		return err
	}

	return nil
}

func delAddr6(name string, ip net.IP, mask int) error {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}

	defer unix.Close(fd)
	sa := socketAddr6Request{}
	sa.addr.Family = unix.AF_INET6
	copy(sa.name[:], name)

	buf, err := ip.MarshalText()
	if err != nil {
		return err
	}

	copy(sa.addr.Addr[:], buf)
	// delete address
	if err := ioctl(fd, unix.SIOCDIFADDR, uintptr(unsafe.Pointer(&sa))); err != nil {
		return err
	}

	return nil
}
*/
