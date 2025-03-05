package actioner

import (
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var _ ActionMethod = (*KernelRouteAction)(nil)

func init() {
	registerMethod("KernelRouteAddDel", &KernelRouteAction{})
}

type KernelRouteAction struct {
	// TODO
}

func (actioner *KernelRouteAction) Act(signal types.State, timeout time.Duration, data ...interface{}) (interface{}, error) {
	return nil, nil
}

func (actioner *KernelRouteAction) create(target *utils.L3L4Addr, configs map[string]string) (ActionMethod, error) {
	return &KernelRouteAction{}, nil
}
