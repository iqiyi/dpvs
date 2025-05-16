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
BackendAction Actioner Params:
-------------------------------------------------------
name                value
-------------------------------------------------------
dpvs-ifname         dpvs netif port name

-------------------------------------------------------
*/

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/iqiyi/dpvs/tools/healthcheck/pkg/comm"
	"github.com/iqiyi/dpvs/tools/healthcheck/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck/pkg/utils"
)

var _ ActionMethod = (*DpvsAddrAction)(nil)

const dpvsAddrActionerName = "DpvsAddrAddDel"

func init() {
	registerMethod(dpvsAddrActionerName, &DpvsAddrAction{})
}

type DpvsAddrAction struct {
	target    *utils.L3L4Addr
	ifname    string
	apiServer string
}

func (a *DpvsAddrAction) Act(signal types.State, timeout time.Duration,
	data ...interface{}) (interface{}, error) {
	addr := a.target.IP

	operation := "UP"
	isAdd := true
	if signal == types.Unhealthy {
		operation = "DOWN"
		isAdd = false
	}

	if timeout <= 0 {
		return nil, fmt.Errorf("zero timeout on %s actioner %v", dpvsAddrActionerName, addr)
	}
	glog.V(7).Infof("starting %s actioner %v ...", dpvsAddrActionerName, addr)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := comm.AddDelDeviceAddr(isAdd, a.apiServer, a.ifname, addr, ctx); err != nil {
		glog.Errorf("%s actioner %v %s failed: %v", dpvsAddrActionerName, addr, operation, err)
		return nil, err
	}

	glog.V(6).Infof("%s actioner %v %s succeed", dpvsAddrActionerName, addr, operation)
	return nil, nil
}

func (a *DpvsAddrAction) validate(params map[string]string) error {
	required := []string{"dpvs-ifname"}
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

func (a *DpvsAddrAction) create(target *utils.L3L4Addr, params map[string]string,
	extras ...interface{}) (ActionMethod, error) {
	if target == nil || len(target.IP) == 0 {
		return nil, fmt.Errorf("no target address for %s actioner", dpvsAddrActionerName)
	}
	actioner := &DpvsAddrAction{
		target: target.DeepCopy(),
	}

	if len(extras) > 0 {
		if apiServer, ok := extras[0].(string); ok {
			actioner.apiServer = apiServer
		}
	}
	if len(actioner.apiServer) == 0 {
		return nil, fmt.Errorf("%s actioner misses dpvs api server config", dpvsAddrActionerName)
	}

	if err := a.validate(params); err != nil {
		return nil, fmt.Errorf("%s actioner param validation failed: %v", dpvsAddrActionerName, err)
	}
	actioner.ifname = params["dpvs-ifname"]

	return actioner, nil
}
