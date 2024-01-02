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
	"testing"
	"time"
)

func TestListAndUpdate(t *testing.T) {
	comm := NewDpvsAgentComm("")
	vss, err := comm.ListVirtualServices()
	if err != nil {
		t.Errorf("list error: %v", err)
	}
	t.Logf("list Results: %v", vss)
	if len(vss) < 2 {
		return
	}
	t.Logf("Updating %v", vss[1])
	vss[1].RSs[0].Weight = 0
	vss[1].RSs[0].Inhibited = true
	//vss[1].RSs[0].Port = 8081
	//vss[1].RSs[1].Weight = 100
	//vss[1].RSs[1].Inhibited = false
	//vss[1].RSs[1].IP = net.ParseIP("1.2.3.4")
	if err = comm.UpdateByChecker(vss[1:2]); err != nil {
		t.Errorf("inhibit rs error: %v", err)
	}
	time.Sleep(3 * time.Second)
	t.Logf("Restoring %v", vss[1])
	vss[1].RSs[0].Weight = 100
	vss[1].RSs[0].Inhibited = false
	if err = comm.UpdateByChecker(vss[1:2]); err != nil {
		t.Errorf("restore rs error: %v", err)
	}
}
