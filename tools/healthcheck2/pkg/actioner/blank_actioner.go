package actioner

/*
Blank Actioner Params:
-------------------------------------------------
name                value
-------------------------------------------------

-------------------------------------------------
*/

import (
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var _ ActionMethod = (*BlankAction)(nil)

const blankActionerName = "Blank"

func init() {
	registerMethod(blankActionerName, &BlankAction{})
}

// BlankAction is an actioner that does nothing.
type BlankAction struct{}

func (a *BlankAction) Act(signal types.State, timeout time.Duration,
	data ...interface{}) (interface{}, error) {
	return nil, nil
}

func (a *BlankAction) create(target *utils.L3L4Addr, params map[string]string,
	extras ...interface{}) (ActionMethod, error) {
	return &BlankAction{}, nil
}
