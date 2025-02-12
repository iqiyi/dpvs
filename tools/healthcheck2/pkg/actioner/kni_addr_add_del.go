package actioner

import (
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var _ ActionMethod = (*KniAddrAction)(nil)

func init() {
	registerMethod("KniAddrAddDel", &KniAddrAction{})
}

type KniAddrAction struct {
	// TODO
}

func (actioner *KniAddrAction) Act(signal types.State, timeout time.Duration, data ...interface{}) (interface{}, error) {
	return nil, nil
}

func (actioner *KniAddrAction) create(target *utils.L3L4Addr, configs map[string]string) (ActionMethod, error) {
	return &KniAddrAction{}, nil
}
