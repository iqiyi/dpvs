package manager

import (
	"context"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/actioner"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/comm"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var VSThreads ThreadStats

// VSID represents the VirtualService ID.
// It must have the same format of L3L4Addr::String().
type VSID string

func (id *VSID) valid() bool {
	return len(*id) > 0
}

type VSBackend struct {
	addr         utils.L3L4Addr
	uweight      uint        // user specified weight
	version      uint64      // deployment version, may < vs's version due to partial update
	state        types.State // health state in dpvs
	checkerState types.State // health state reported from Checker
	checker      *Checker    // Restriction: access only to its thread-safe members
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

	backends map[CheckerID]*VSBackend
	actioner actioner.ActionMethod
	resync   *time.Ticker    // timer to resync backend state to dpvs
	va       *VirtualAddress // only access to va's notify chan & read-only members

	wg     *sync.WaitGroup
	notify chan BackendState
	update chan VSConfExt
	metric chan Metric
	quit   chan bool
}

func NewVS(sub *comm.VirtualServer, conf *VSConf, m *Manager) (*VirtualService, error) {
	// TODO
	return nil, nil
}

func NewVSBackend(version uint64, rs *comm.RealServer, checker *Checker) *VSBackend {
	rsAddrCopied := rs.Addr.DeepCopy()
	vsb := &VSBackend{
		version:      version,
		addr:         *rsAddrCopied,
		uweight:      uint(rs.Weight),
		checkerState: types.Unknown,
		checker:      checker,
	}
	if rs.Inhibited {
		vsb.state = types.Unhealthy
	} else {
		vsb.state = types.Healthy
	}
	return vsb
}

func (vs *VirtualService) Update(conf *VSConfExt) {
	// TODO
}

func (vs *VirtualService) Stop() {
	glog.Info("stopping VS %s ...", vs.id)
	vs.quit <- true
}

func (vs *VirtualService) Run(ctx context.Context, wg *sync.WaitGroup, start <-chan time.Time) {
	// TODO
}
