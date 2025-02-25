package checker

import (
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var _ CheckMethod = (*TCPChecker)(nil)

type TCPChecker struct {
	// TODO
}

func init() {
	registerMethod(CheckMethodTCP, &TCPChecker{})
}

func (c *TCPChecker) Check(target *utils.L3L4Addr, timeout time.Duration) (types.State, error) {
	// TODO
	return types.Healthy, nil
}

func (c *TCPChecker) create(params map[string]string) (CheckMethod, error) {
	// TODO
	return &TCPChecker{}, nil
}
