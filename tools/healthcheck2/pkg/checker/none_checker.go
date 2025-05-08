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

/*
None Checker Params:
-----------------------------------
name                value
-----------------------------------

------------------------------------
*/

import (
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var _ CheckMethod = (*NoneChecker)(nil)

// NoneChecker does nothing, and always returns Healthy state.
type NoneChecker struct{}

func init() {
	registerMethod(CheckMethodNone, &NoneChecker{})
}

func (c *NoneChecker) Check(target *utils.L3L4Addr, timeout time.Duration) (types.State, error) {
	return types.Healthy, nil
}

func (c *NoneChecker) validate(params map[string]string) error {
	return nil
}

func (c *NoneChecker) create(params map[string]string) (CheckMethod, error) {
	return &NoneChecker{}, nil
}
