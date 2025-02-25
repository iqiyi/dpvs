package checker

import (
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var _ CheckMethod = (*HTTPChecker)(nil)

type HTTPChecker struct {
	// TODO
}

func init() {
	registerMethod(CheckMethodHTTP, &HTTPChecker{})
}

func (c *HTTPChecker) Check(target *utils.L3L4Addr, timeout time.Duration) (types.State, error) {
	// TODO
	return types.Healthy, nil
}

func (c *HTTPChecker) create(params map[string]string) (CheckMethod, error) {
	// TODO
	return &HTTPChecker{}, nil
}
