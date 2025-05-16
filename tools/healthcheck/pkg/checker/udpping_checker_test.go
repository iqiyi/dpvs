// /*
// Copyright 2025 IQiYi Inc. All Rights Reserved.
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
// */

package checker

import (
	"net"
	"testing"
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck/pkg/utils"
)

var udpping_targets = []utils.L3L4Addr{
	{net.ParseIP("192.168.88.130"), 6000, utils.IPProtoUDP},
	{net.ParseIP("11.22.33.44"), 6000, utils.IPProtoUDP},
	{net.ParseIP("192.168.88.130"), 6602, utils.IPProtoUDP},
	{net.ParseIP("2001::30"), 6000, utils.IPProtoUDP},
	{net.ParseIP("1234:5678::9"), 6000, utils.IPProtoUDP},
	{net.ParseIP("2001::30"), 6002, utils.IPProtoUDP},
}

func TestUDPPingChecker(t *testing.T) {
	timeout := 2 * time.Second

	for _, target := range udpping_targets {
		// TODO:
		//  Add tests for each supported params.

		checker, err := (&UDPPingChecker{}).create(nil)
		if err != nil {
			t.Fatalf("Failed to create udpping checker %v: %v", target, err)
		}

		state, err := checker.Check(&target, timeout)
		if err != nil {
			t.Errorf("Failed to execute  udpping checker %v: %v", target, err)
		} else {
			t.Logf("[ UDPPing ] %v ==> %v", target, state)
		}
	}
}
