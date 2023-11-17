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
//
// The healthcheck package refers to the framework of "github.com/google/
// seesaw/healthcheck" heavily, with only some adaption changes for DPVS.

package hc

import (
	"fmt"
	"time"
)

var _ CheckMethod = (*UDPPingChecker)(nil)

// UDPPingChecker contains configuration specific to a UDPPing healthcheck.
type UDPPingChecker struct {
	Config *CheckerConfig

	*UDPChecker
	*PingChecker
}

// NewUDPPingChecker returns an initialised UDPPingChecker.
func NewUDPPingChecker(recv, send string, proxyProto int) *UDPPingChecker {
	return &UDPPingChecker{
		UDPChecker:  NewUDPChecker(recv, send, proxyProto),
		PingChecker: NewPingChecker(),
	}
}

func (hc *UDPPingChecker) BindConfig(conf *CheckerConfig) {
	hc.Config = conf
}

// String returns the string representation of a UDPPing healthcheck.
func (hc *UDPPingChecker) String() string {
	return fmt.Sprintf("UDPPing checker for %v", hc.Config.Id)
}

// Check executes an UDPPing healthcheck.
func (hc *UDPPingChecker) Check(target Target, timeout time.Duration) *Result {
	start := time.Now()

	result := hc.PingChecker.Check(target, timeout)
	if result.Success != true {
		return result
	}

	result = hc.UDPChecker.Check(target, time.Until(start.Add(timeout)))
	result.Duration = time.Since(start)
	return result
}
