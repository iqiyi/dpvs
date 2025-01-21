package checker

import (
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

type CheckMethod interface {
	// Check executes a healthcheck procedure of the method once.
	Check(target *utils.L3L4Addr, timeout time.Duration) (types.State, error)
	// BindConfig binds method specific configs.
	BindConfig(configs map[string]interface{}) error
}
