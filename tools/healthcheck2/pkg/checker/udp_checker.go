package checker

import (
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var _ CheckMethod = (*UDPChecker)(nil)

type UDPChecker struct {
	// TODO
}

func init() {
	registerMethod(CheckMethodUDP, &UDPChecker{})
}

func (c *UDPChecker) Check(target *utils.L3L4Addr, timeout time.Duration) (types.State, error) {
	// TODO
	return types.Healthy, nil
}

func (c *UDPChecker) create(params map[string]string) (CheckMethod, error) {
	// TODO
	return &UDPChecker{}, nil
}
