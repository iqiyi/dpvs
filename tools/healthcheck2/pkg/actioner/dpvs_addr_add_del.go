package actioner

/*
BackendAction Actioner Params:
-------------------------------------------------------
name                value
-------------------------------------------------------
dpvs-ifname         dpvs netif port name
api-server-addr     dpvs-agent server address(internal)

-------------------------------------------------------
*/

import (
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var _ ActionMethod = (*DpvsAddrAction)(nil)

const dpvsAddrActionerName = "DpvsAddrAddDel"

func init() {
	registerMethod(dpvsAddrActionerName, &DpvsAddrAction{})
}

type DpvsAddrAction struct {
	apiServer string
}

func (a *DpvsAddrAction) Act(signal types.State, timeout time.Duration,
	data ...interface{}) (interface{}, error) {
	return nil, nil
}

func (a *DpvsAddrAction) create(target *utils.L3L4Addr, configs map[string]string,
	extras ...interface{}) (ActionMethod, error) {
	return &DpvsAddrAction{}, nil
}
