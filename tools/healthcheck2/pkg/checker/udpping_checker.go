package checker

import (
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var _ CheckMethod = (*UDPPingChecker)(nil)

type UDPPingChecker struct {
	// TODO
}

func init() {
	registerMethod(CheckMethodUDPPing, &UDPPingChecker{})
}

func (c *UDPPingChecker) Check(target *utils.L3L4Addr, timeout time.Duration) (types.State, error) {
	// TODO
	return types.Healthy, nil
}

func (c *UDPPingChecker) create(params map[string]string) (CheckMethod, error) {
	// TODO
	return &UDPPingChecker{}, nil
}
