package actioner

import (
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var _ ActionMethod = (*DpvsAddrKernelRouteAction)(nil)

const addrRouteActionerName = "DpvsAddrKernelRouteAddDel"

func init() {
	registerMethod(addrRouteActionerName, &DpvsAddrKernelRouteAction{})
}

type DpvsAddrKernelRouteAction struct {
	// TODO
}

func (a *DpvsAddrKernelRouteAction) Act(signal types.State, timeout time.Duration,
	data ...interface{}) (interface{}, error) {
	return nil, nil
}

func (a *DpvsAddrKernelRouteAction) create(target *utils.L3L4Addr, params map[string]string,
	extras ...interface{}) (ActionMethod, error) {
	return &DpvsAddrKernelRouteAction{}, nil
}
