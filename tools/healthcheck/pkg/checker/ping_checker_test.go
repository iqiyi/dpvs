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

var ping_targets = []utils.L3L4Addr{
	{net.ParseIP("127.0.0.1"), 0, 0},
	{net.ParseIP("192.168.88.30"), 0, 0},
	{net.ParseIP("8.8.8.8"), 0, 0},
	{net.ParseIP("11.22.33.44"), 0, 0},
	{net.ParseIP("::1"), 0, 0},
	{net.ParseIP("2001::1"), 0, 0},
	{net.ParseIP("2001::68"), 0, 0},
}

func TestPingChecker(t *testing.T) {
	timeout := 2 * time.Second

	for _, target := range ping_targets {
		checker, err := (&PingChecker{}).create(nil)
		if err != nil {
			t.Fatalf("Failed to create ping checker %v: %v", target, err)
		}

		state, err := checker.Check(&target, timeout)
		if err != nil {
			t.Errorf("Failed to execute ping checker %v: %v", target, err)
		} else {
			t.Logf("[ Ping ]%v ==>%v", target.IP, state)
		}
	}
}
