package manager

import (
	"net"
	"sync"
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/actioner"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

// VAID represents VirtualAddress ID.
// It must have the same format of net.IP::String().
type VAID string

func (id *VAID) valid() bool {
	return len(*id) > 0
}

type VAVS struct {
	addr         utils.L3L4Addr
	version      uint64          // deployment version
	state        types.State     // real state, i.e., if the addr is online or not
	checkerState types.State     // state reported from VS & checkers
	vs           *VirtualService // should not use, just for link
}

type VSState struct {
	id    VSID
	state types.State
}

type VirtualAddress struct {
	// read-only members
	id      VAID
	subject net.IP
	conf    VAConf

	// va's status
	state   types.State
	since   time.Time
	stats   Statistics
	downVSs uint
	upVSs   uint

	vss      map[VSID]VAVS
	actioner actioner.ActionMethod
	resync   *time.Ticker // timer to resync VA's state to dpvs

	wg     sync.WaitGroup
	notify chan VSState
	update chan VAConf
	metric chan Metric
	quit   chan bool
}
