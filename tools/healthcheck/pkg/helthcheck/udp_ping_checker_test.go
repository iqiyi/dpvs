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
	"net"
	"testing"
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck/pkg/utils"
)

var udpping_targets = []Target{
	{net.ParseIP("192.168.88.30"), 6601, utils.IPProtoUDP},
	{net.ParseIP("11.22.33.44"), 6601, utils.IPProtoUDP},
	{net.ParseIP("192.168.88.30"), 6602, utils.IPProtoUDP},
	{net.ParseIP("2001::30"), 6601, utils.IPProtoUDP},
	{net.ParseIP("1234:5678::9"), 6601, utils.IPProtoUDP},
	{net.ParseIP("2001::30"), 6602, utils.IPProtoUDP},
}

func TestUDPPingChecker(t *testing.T) {
	for _, target := range udpping_targets {
		checker := NewUDPPingChecker("", "", 0)
		id := Id(target.String())
		config := NewCheckerConfig(&id, 0, checker,
			&target, StateUnknown, 0,
			3*time.Second, 2*time.Second, 3)
		result := checker.Check(target, config.Timeout)
		fmt.Printf("[ UDPPing ] %s ==> %v\n", target, result)
	}
}
