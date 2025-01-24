package manager

import (
	"sync"
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/actioner"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

// VSID represents the VirtualService ID.
// It must have the same format of L3L4Addr::String().
type VSID string

func (id *VSID) valid() bool {
	return len(*id) > 0
}

type VSBackend struct {
	addr         utils.L3L4Addr
	uweight      uint        // user specified weight
	version      uint64      // deployment version, MUST >= vs's version
	state        types.State // health state in dpvs
	checkerState types.State // health state reported from Checker
	checker      *Checker    // should not use, just for link
}

type BackendState struct {
	id    CheckerID
	state types.State
}

type VirtualService struct {
	// read-only members
	id      VSID
	subject utils.L3L4Addr
	conf    VSConf

	// vs's status
	state        types.State
	since        time.Time
	stats        Statistics
	downBackends uint
	upBackends   uint

	backends map[CheckerID]VSBackend
	actioner actioner.ActionMethod
	resync   *time.Ticker    // timer to resync backend state to dpvs
	va       *VirtualAddress // only access to va's notify chan & read-only members

	wg     sync.WaitGroup
	notify chan BackendState
	update chan VSConf
	metric chan Metric
	quit   chan bool
}
