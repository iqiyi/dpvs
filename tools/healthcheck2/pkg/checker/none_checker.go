package checker

/*
None Checker Params:
-----------------------------------
name                value
-----------------------------------

------------------------------------
*/

import (
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var _ CheckMethod = (*NoneChecker)(nil)

// NoneChecker does nothing, and always returns Healthy state.
type NoneChecker struct{}

func init() {
	registerMethod(CheckMethodNone, &NoneChecker{})
}

func (c *NoneChecker) Check(target *utils.L3L4Addr, timeout time.Duration) (types.State, error) {
	return types.Healthy, nil
}

func (c *NoneChecker) create(params map[string]string) (CheckMethod, error) {
	return &NoneChecker{}, nil
}
