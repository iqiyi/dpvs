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
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/comm"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
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

	unsupported := make([]string, 0, len(params))
	for param, val := range params {
		switch param {
		case "dpvs-ifname":
			if len(val) == 0 {
				return nil, fmt.Errorf("empty %s actioner param: %s", dpvsAddrActionerName, param)
			}
			actioner.ifname = val
		default:
			unsupported = append(unsupported, param)
		}
	}
	if len(unsupported) > 0 {
		return nil, fmt.Errorf("unsupported %s actioner params: %s",
			dpvsAddrActionerName, strings.Join(unsupported, ","))
	}

	if len(actioner.apiServer) == 0 {
		return nil, fmt.Errorf("%s actioner misses dpvs api server config", dpvsAddrActionerName)
	}

	if len(actioner.ifname) == 0 {
		return nil, fmt.Errorf("%s actioner misses param: dpvs-ifname", dpvsAddrActionerName)
	}

	return actioner, nil
}
