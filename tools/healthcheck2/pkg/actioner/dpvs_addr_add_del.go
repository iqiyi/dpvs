package actioner

import (
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var _ ActionMethod = (*DpvsAddrAction)(nil)

func init() {
	registerMethod("DpvsAddrAddDel", &DpvsAddrAction{})
}

type DpvsAddrAction struct {
	// TODO
}

func (actioner *DpvsAddrAction) Act(signal types.State, timeout time.Duration, data ...interface{}) (interface{}, error) {
	return nil, nil
}

func (actioner *DpvsAddrAction) create(target *utils.L3L4Addr, configs map[string]string) (ActionMethod, error) {
	return &DpvsAddrAction{}, nil
}
