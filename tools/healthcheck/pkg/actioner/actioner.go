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

import (
	"fmt"
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck/pkg/utils"
)

var methods map[string]ActionMethod

type ActionMethod interface {
	// Act performs actions corresponding to health state change signal.
	// The function MUST return in or immediately after `timeout` time.
	Act(signal types.State, timeout time.Duration, data ...interface{}) (interface{}, error)
	// create validates the given configs, returns an instance of the action
	// method, and binds configs to it.
	create(target *utils.L3L4Addr, configs map[string]string, extras ...interface{}) (ActionMethod, error)
	// validate checks if the "configs" given are valid for creating an action.
	validate(configs map[string]string) error
}

type ActionMethodWithVerdict interface {
	// Verdict checks the real state for an action method.
	// It's useful to correct inconsistency when action result can be changed externally.
	Verdict(timeout time.Duration) (types.State, error)
}

func registerMethod(name string, method ActionMethod) {
	if methods == nil {
		methods = make(map[string]ActionMethod)
	}
	methods[name] = method
}

func NewActioner(kind string, target *utils.L3L4Addr, configs map[string]string,
	extras ...interface{}) (ActionMethod, error) {
	method, ok := methods[kind]
	if !ok {
		return nil, fmt.Errorf("unsupported Action type %q", kind)
	}
	actioner, err := method.create(target, configs, extras...)
	if err != nil {
		return nil, fmt.Errorf("actioner create failed: %v", err)
	}
	return actioner, nil
}

func Validate(kind string, configs map[string]string) error {
	method, ok := methods[kind]
	if !ok {
		return fmt.Errorf("unsupported action type: %s", kind)
	}
	return method.validate(configs)
}
