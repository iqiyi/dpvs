package actioner

import (
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
)

type ActionMethod interface {
	// Act performs actions corresponding to health state change signal.
	Act(signal types.State, timeout time.Duration) error
	// BindConfig binds configs of the action method.
	// The configs MUST include target object, which generally can be
	// either net.IP or utils.L3L4Addr.
	BindConfig(configs map[string]interface{}) error
}
