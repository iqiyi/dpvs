package checker

import (
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var _ CheckMethod = (*PingChecker)(nil)

type PingChecker struct {
	// TODO
}

func init() {
	registerMethod(CheckMethodPing, &PingChecker{})
}

func (c *PingChecker) Check(target *utils.L3L4Addr, timeout time.Duration) (types.State, error) {
	// TODO
	return types.Healthy, nil
}

func (c *PingChecker) create(params map[string]string) (CheckMethod, error) {
	// TODO
	return &PingChecker{}, nil
}
