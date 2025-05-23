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
DpvsAddrKernelRouteAddDel Actioner Params:
-------------------------------------------------------
name                value
-------------------------------------------------------
ifname              linux network interface name
dpvs-ifname         dpvs netif port name

-------------------------------------------------------
*/

import (
	"fmt"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/iqiyi/dpvs/tools/healthcheck/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck/pkg/utils"
)

var _ ActionMethod = (*DpvsAddrKernelRouteAction)(nil)

const addrRouteActionerName = "DpvsAddrKernelRouteAddDel"

func init() {
	registerMethod(addrRouteActionerName, &DpvsAddrKernelRouteAction{})
}

// DpvsAddrKernelRouteAction is a composite actioner, which executes KernelRouteAction
// actioner firtly, and when it succeeeds, then executes DpvsAddrAction.
type DpvsAddrKernelRouteAction struct {
	target *utils.L3L4Addr
	*DpvsAddrAction
	*KernelRouteAction
}

func (a *DpvsAddrKernelRouteAction) Act(signal types.State, timeout time.Duration,
	data ...interface{}) (interface{}, error) {
	addr := a.target.IP
	if timeout <= 0 {
		return nil, fmt.Errorf("zero timeout on %s actioner %v", addrRouteActionerName, addr)
	}
	operation := "UP"
	if signal == types.Unhealthy {
		operation = "DOWN"
	}

	start := time.Now()
	glog.V(7).Infof("starting %s actioner %v ...", addrRouteActionerName, addr)
	_, err := a.KernelRouteAction.Act(signal, timeout, data...)
	if err != nil {
		return nil, fmt.Errorf("%s actioner %v %v executes %s failed: %v",
			addrRouteActionerName, addr, operation, kernelRouteActionerName, err)
	}
	_, err = a.DpvsAddrAction.Act(signal, time.Until(start.Add(timeout)), data...)
	if err != nil {
		return nil, fmt.Errorf("%s actioner %v %s executes %s failed: %v",
			addrRouteActionerName, addr, operation, dpvsAddrActionerName, err)
	}

	glog.V(6).Infof("%s actioner %v %s succeed", addrRouteActionerName, addr, operation)
	return nil, nil
}

func (a *DpvsAddrKernelRouteAction) validate(params map[string]string) error {
	required := []string{"ifname", "dpvs-ifname"}
	var missed []string
	for _, param := range required {
		if _, ok := params[param]; !ok {
			missed = append(missed, param)
		}
	}
	if len(missed) > 0 {
		return fmt.Errorf("missing required action params: %v", strings.Join(missed, ","))
	}

	unsupported := make([]string, 0, len(params))
	for param, val := range params {
		switch param {
		case "ifname":
			if len(val) == 0 {
				return fmt.Errorf("empty action param %s", param)
			}
			// TODO: check if the interface exists on the system
		case "dpvs-ifname":
			if len(val) == 0 {
				return fmt.Errorf("empty action param %s", param)
			}
			// TODO: check if the interface exists in dpvs
		default:
			unsupported = append(unsupported, param)
		}
	}
	if len(unsupported) > 0 {
		return fmt.Errorf("unsupported action params: %s", strings.Join(unsupported, ","))
	}

	return nil
}

func (a *DpvsAddrKernelRouteAction) create(target *utils.L3L4Addr, params map[string]string,
	extras ...interface{}) (ActionMethod, error) {
	if target == nil || len(target.IP) == 0 {
		return nil, fmt.Errorf("no target address for %s actioner", addrRouteActionerName)
	}

	if err := a.validate(params); err != nil {
		return nil, fmt.Errorf("%s actioner param validation failed: %v", addrRouteActionerName, err)
	}
	krtParams := map[string]string{"ifname": params["ifname"]}
	daddrParams := map[string]string{"dpvs-ifname": params["dpvs-ifname"]}

	daddrAction, err := a.DpvsAddrAction.create(target, daddrParams, extras...)
	if err != nil {
		return nil, fmt.Errorf("fail to create %s for %s: %v", addrRouteActionerName,
			dpvsAddrActionerName, err)
	}

	krtAction, err := a.KernelRouteAction.create(target, krtParams, extras...)
	if err != nil {
		return nil, fmt.Errorf("fail to create %s for %s: %v", addrRouteActionerName,
			kernelRouteActionerName, err)
	}

	return &DpvsAddrKernelRouteAction{
		target:            target.DeepCopy(),
		DpvsAddrAction:    daddrAction.(*DpvsAddrAction),
		KernelRouteAction: krtAction.(*KernelRouteAction),
	}, nil
}
