package actioner

import (
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var _ ActionMethod = (*DpvsAddrKernelRouteAction)(nil)

func init() {
	registerMethod("DpvsAddrKernelRouteAddDel", &DpvsAddrKernelRouteAction{})
}

type DpvsAddrKernelRouteAction struct {
	// TODO
}

func (actioner *DpvsAddrKernelRouteAction) Act(signal types.State, timeout time.Duration, data ...interface{}) (interface{}, error) {
	return nil, nil
}

func (actioner *DpvsAddrKernelRouteAction) create(target *utils.L3L4Addr, configs map[string]string) (ActionMethod, error) {
	return &DpvsAddrKernelRouteAction{}, nil
}
