package actioner

import (
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var _ ActionMethod = (*BackendAction)(nil)

func init() {
	registerMethod("BackendUpdate", &BackendAction{})
}

type BackendAction struct {
	// TODO
}

func (actioner *BackendAction) Act(signal types.State, timeout time.Duration, data ...interface{}) (interface{}, error) {
	return nil, nil
}

func (actioner *BackendAction) create(target *utils.L3L4Addr, configs map[string]string) (ActionMethod, error) {
	return &BackendAction{}, nil
}
