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

package actioner

/*
Blank Actioner Params:
-------------------------------------------------
name                value
-------------------------------------------------

-------------------------------------------------
*/

import (
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var _ ActionMethod = (*BlankAction)(nil)

const blankActionerName = "Blank"

func init() {
	registerMethod(blankActionerName, &BlankAction{})
}

// BlankAction is an actioner that does nothing.
type BlankAction struct{}

func (a *BlankAction) Act(signal types.State, timeout time.Duration,
	data ...interface{}) (interface{}, error) {
	return nil, nil
}

func (a *BlankAction) create(target *utils.L3L4Addr, params map[string]string,
	extras ...interface{}) (ActionMethod, error) {
	return &BlankAction{}, nil
}

func (a *BlankAction) validate(params map[string]string) error {
	return nil
}
