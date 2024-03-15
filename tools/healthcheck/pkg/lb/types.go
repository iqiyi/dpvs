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

package lb

import (
	"net"

	"github.com/iqiyi/dpvs/tools/healthcheck/pkg/utils"
)

type Checker uint16

const (
	CheckerNone Checker = iota
	CheckerTCP
	CheckerUDP
	CheckerPING
	CheckerUDPPING
	CheckerHTTP
)

type RealServer struct {
	IP        net.IP
	Port      uint16
	Weight    uint16
	Inhibited bool
}

type VirtualService struct {
	Id       string
	Version  uint64
	Checker  Checker
	Protocol utils.IPProto
	Port     uint16
	IP       net.IP
	RSs      []RealServer
}

type Comm interface {
	// Get the list of VS/RS prepared for healthcheck.
	ListVirtualServices() ([]VirtualService, error)
	// Update RSs health state, return nil error and the lastest info of RSs whose
	// weight have been changed administively on success, or error on failure.
	UpdateByChecker(targets *VirtualService) (*VirtualService, error)
}

func (checker Checker) String() string {
	switch checker {
	case CheckerNone:
		return "checker_none"
	case CheckerTCP:
		return "checker_tcp"
	case CheckerUDP:
		return "checker_udp"
	case CheckerPING:
		return "checker_ping"
	case CheckerUDPPING:
		return "checker_udpping"
	case CheckerHTTP:
		return "checker_http"
	}
	return "checker_unknown"
}
