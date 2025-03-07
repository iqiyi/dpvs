package actioner

/*
BackendAction Actioner Params:
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
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var _ ActionMethod = (*DpvsAddrKernelRouteAction)(nil)

const addrRouteActionerName = "DpvsAddrKernelRouteAddDel"

func init() {
	registerMethod(addrRouteActionerName, &DpvsAddrKernelRouteAction{})
}

// DpvsAddrKernelRouteAction is a composit actioner, which executes KernelRouteAction
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

func (a *DpvsAddrKernelRouteAction) create(target *utils.L3L4Addr, params map[string]string,
	extras ...interface{}) (ActionMethod, error) {
	if target == nil || len(target.IP) == 0 {
		return nil, fmt.Errorf("no target address for %s actioner", addrRouteActionerName)
	}

	unsupported := make([]string, 0, len(params))
	daddrParams := make(map[string]string)
	krtParams := make(map[string]string)
	for param, val := range params {
		switch param {
		case "ifname":
			if len(val) == 0 {
				return nil, fmt.Errorf("empty %s actioner param: %s", addrRouteActionerName, param)
			}
			krtParams[param] = val
		case "dpvs-ifname":
			if len(val) == 0 {
				return nil, fmt.Errorf("empty %s actioner param: %s", addrRouteActionerName, param)
			}
			daddrParams[param] = val
		default:
			unsupported = append(unsupported, param)
		}
	}
	if len(unsupported) > 0 {
		return nil, fmt.Errorf("unsupported %s actioner params: %s", addrRouteActionerName,
			strings.Join(unsupported, ","))
	}

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
