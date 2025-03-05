package actioner

import (
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var _ ActionMethod = (*ScriptAction)(nil)

func init() {
	registerMethod("ScriptAddDel", &ScriptAction{})
}

type ScriptAction struct {
	// TODO
}

func (actioner *ScriptAction) Act(signal types.State, timeout time.Duration, data ...interface{}) (interface{}, error) {
	return nil, nil
}

func (actioner *ScriptAction) create(target *utils.L3L4Addr, configs map[string]string) (ActionMethod, error) {
	return &ScriptAction{}, nil
}
