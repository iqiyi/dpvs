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
KernelRouteAddDelVerdict Actioner Params:
-------------------------------------------------
name                value
-------------------------------------------------
ifname              network interface name

-------------------------------------------------
*/

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/glog"
	"github.com/iqiyi/dpvs/tools/healthcheck/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck/pkg/utils"
	"github.com/vishvananda/netlink"
)

var _ ActionMethod = (*KernelRouteVerdictAction)(nil)
var _ ActionMethodWithVerdict = (*KernelRouteVerdictAction)(nil)

const kernelRouteVerdictActionerName = "KernelRouteAddDelVerdict"

func init() {
	registerMethod(kernelRouteVerdictActionerName, &KernelRouteVerdictAction{})
}

// KernelRouteVerdictAction is the same as KernelRouteAction except it also implements
// ActionMethodWithVerdict interface.
type KernelRouteVerdictAction struct {
	KernelRouteAction
}

func (a *KernelRouteVerdictAction) Act(signal types.State, timeout time.Duration,
	data ...interface{}) (interface{}, error) {
	return a.KernelRouteAction.Act(signal, timeout, data)
}

func (a *KernelRouteVerdictAction) create(target *utils.L3L4Addr, params map[string]string,
	extras ...interface{}) (ActionMethod, error) {
	embeded, err := a.KernelRouteAction.create(target, params, extras)
	if embededObj, ok := embeded.(*KernelRouteAction); ok {
		method := &KernelRouteVerdictAction{
			KernelRouteAction: *embededObj,
		}
		return method, err
	}
	return nil, fmt.Errorf("failed to create %s embeded action for %s", kernelRouteVerdictActionerName,
		target.IP.String())
}

func (a *KernelRouteVerdictAction) validate(params map[string]string) error {
	return a.KernelRouteAction.validate(params)
}

func (a *KernelRouteVerdictAction) Verdict(timeout time.Duration) (types.State, error) {
	targetIP := a.target.IP
	if timeout <= 0 {
		return types.Unknown, fmt.Errorf("zero verdict timeout on %s actioner %v",
			kernelRouteVerdictActionerName, targetIP)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result := types.Unknown
	done := make(chan error, 1)

	go func() {
		link, err := netlink.LinkByName(a.ifname)
		if err != nil {
			done <- fmt.Errorf("failed to get link by name: %w", err)
			return
		}
		addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			done <- fmt.Errorf("failed to get addrs on %s: %w", a.ifname, err)
			return
		}
		for _, addr := range addrs {
			if targetIP.Equal(addr.IP) {
				result = types.Healthy
				done <- nil
				return
			}
		}
		result = types.Unhealthy
		done <- nil
	}()

	select {
	case <-ctx.Done():
		glog.Warningf("%s actioner %v verdict timeout", kernelRouteVerdictActionerName, targetIP)
		return types.Unknown, ctx.Err()
	case err := <-done:
		if err != nil {
			return types.Unknown, err
		}
		return result, nil
	}
	return types.Unknown, nil
}
