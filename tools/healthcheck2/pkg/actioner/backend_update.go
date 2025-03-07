package actioner

/*
BackendAction Actioner Params:
-------------------------------------------------------
name                value
-------------------------------------------------------

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

var _ ActionMethod = (*BackendAction)(nil)

const backendActionerName = "BackendUpdate"

func init() {
	registerMethod(backendActionerName, &BackendAction{})
}

type BackendAction struct {
	name      string
	apiServer string
}

func (a *BackendAction) Act(signal types.State, timeout time.Duration,
	data ...interface{}) (interface{}, error) {
	if timeout <= 0 {
		return nil, fmt.Errorf("zero timeout on actioner %s", a.name)
	}
	if len(data) < 1 {
		return nil, fmt.Errorf("%s missing backend data", a.name)
	}
	vs, ok := data[0].(*comm.VirtualServer)
	if !ok || vs == nil || len(vs.RSs) == 0 {
		return nil, fmt.Errorf("invalid backend data for %s", a.name)
	}

	glog.V(7).Infof("starting %s actioner %s ...", backendActionerName, a.name)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	newVS, err := comm.UpdateCheckState(a.apiServer, vs, ctx)
	if err != nil {
		glog.Errorf("%s actioner %s (VS: %v) failed: %v", backendActionerName, a.name, *vs, err)
	} else if newVS != nil {
		glog.Warningf("%s actioner %s (VS: %v) outdated and returned newVS %v",
			backendActionerName, a.name, *vs, newVS)
	} else {
		glog.V(6).Infof("%s actioner %s (VS %v) succeed", backendActionerName, a.name, *vs)
	}

	return newVS, err
}

func (a *BackendAction) create(target *utils.L3L4Addr, params map[string]string,
	extras ...interface{}) (ActionMethod, error) {
	actioner := &BackendAction{name: target.String()}

	if len(extras) > 0 {
		if apiServer, ok := extras[0].(string); ok {
			actioner.apiServer = apiServer
		}
	}

	unsupported := make([]string, 0, len(params))
	for param, _ := range params {
		switch param {
		default:
			unsupported = append(unsupported, param)
		}
	}
	if len(unsupported) > 0 {
		return nil, fmt.Errorf("unsupported %s actioner params: %s", backendActionerName,
			strings.Join(unsupported, ","))
	}

	if len(actioner.apiServer) == 0 {
		return nil, fmt.Errorf("%s actioner misses dpvs api server config", backendActionerName)
	}

	return actioner, nil
}
