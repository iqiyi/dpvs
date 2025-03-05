package actioner

/*
BackendAction Actioner Params:
---------------------------------------------
name                value
---------------------------------------------
api-server-addr     dpvs-agent server address
---------------------------------------------
*/

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/comm"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var _ ActionMethod = (*BackendAction)(nil)

func init() {
	registerMethod("BackendUpdate", &BackendAction{})
}

type BackendAction struct {
	name      string
	apiServer string
}

func (a *BackendAction) Act(signal types.State, timeout time.Duration, data ...interface{}) (interface{}, error) {
	if timeout < 0 {
		return nil, fmt.Errorf("zero timeout on actioner %s", a.name)
	}
	if len(data) < 1 {
		return nil, fmt.Errorf("%s missing backend data", a.name)
	}
	vs, ok := data[0].(*comm.VirtualServer)
	if !ok || vs == nil || len(vs.RSs) == 0 {
		return nil, fmt.Errorf("invalid backend data for %s", a.name)
	}

	glog.V(7).Infof("starting BackendUpdate actioner %s ...", a.name)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	newVS, err := comm.UpdateCheckState(a.apiServer, vs, ctx)
	if err != nil {
		glog.Errorf("BackendUpdate actioner %s (VS: %v) failed: %v", a.name, *vs, err)
	} else if newVS != nil {
		glog.Warningf("BackendUpdate actioner %s (VS: %v) outdated and returned newVS %v",
			a.name, *vs, newVS)
	} else {
		glog.V(6).Infof("BackendUpdate actioner %s (VS %v) succeed", a.name, *vs)
	}

	return newVS, err
}

func (a *BackendAction) create(target *utils.L3L4Addr, params map[string]string) (ActionMethod, error) {
	actioner := &BackendAction{name: target.String()}

	unsupported := make([]string, 0, len(params))
	for param, val := range params {
		switch param {
		case "api-server-addr":
			if len(val) == 0 {
				return nil, fmt.Errorf("empty BackendUpdate actioner param: %s", param)
			}
			actioner.apiServer = val
		default:
			unsupported = append(unsupported, param)
		}
	}
	if len(unsupported) > 0 {
		return nil, fmt.Errorf("unsupported BackendUpdate actioner params: %s", strings.Join(unsupported, ","))
	}

	if len(actioner.apiServer) == 0 {
		return nil, errors.New("BackendUpdate actioner misses param: api-server-address")
	}

	return actioner, nil
}
