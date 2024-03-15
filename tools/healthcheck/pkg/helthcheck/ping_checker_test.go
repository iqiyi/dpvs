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
)

var ping_targets = []Target{
	{net.ParseIP("127.0.0.1"), 0, 0},
	{net.ParseIP("192.168.88.30"), 0, 0},
	{net.ParseIP("11.22.33.44"), 0, 0},
	{net.ParseIP("::1"), 0, 0},
	{net.ParseIP("2001::1"), 0, 0},
	{net.ParseIP("2001::68"), 0, 0},
}

func TestPingChecker(t *testing.T) {
	for _, target := range ping_targets {
		checker := NewPingChecker()
		id := Id(target.IP.String())
		config := NewCheckerConfig(&id, 0, checker,
			&target, StateUnknown, 0,
			3*time.Second, 1*time.Second, 3)
		result := checker.Check(target, config.Timeout)
		fmt.Printf("[ Ping ]%s ==>%v\n", target, result)
	}
}
