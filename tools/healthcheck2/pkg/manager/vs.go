package manager

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/actioner"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/checker"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/comm"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

const (
	DefaultCheckerWeight uint = 1
	CheckerStartDelayMax      = 3 * time.Second
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
	version      uint64      // deployment version, may > vs's version due to partial update
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
	va      *VirtualAddress // Restrictions: only access to its read-only/thread-safe members

	// status members
	state        types.State
	since        time.Time
	stats        Statistics
	downBackends int
	upBackends   int

	backends map[CheckerID]*VSBackend
	actioner actioner.ActionMethod
	resync   *time.Ticker // timer to resync backend state to dpvs

	// metric members
	metricTaint  bool
	metricTicker *time.Ticker
	metric       chan<- Metric

	// thread-safe members
	wg     *sync.WaitGroup
	notify chan BackendState
	update chan VSConfExt
	quit   chan bool
}

func NewVS(sub *comm.VirtualServer, conf *VSConf, va *VirtualAddress) (*VirtualService, error) {
	if !conf.Valid() {
		return nil, fmt.Errorf("invalid VSConf %v", *conf)
	}

	vsid := VSID(sub.Addr.String())
	confCopied := conf.DeepCopy()
	confCopied.methodParams = confCopied.MergeDpvsCheckerConf(sub, confCopied.methodParams)
	if confCopied.method == checker.CheckMethodAuto {
		confCopied.method = confCopied.method.TranslateAuto(sub.Addr.Proto)
	}

	act, err := actioner.NewActioner(conf.actioner, &sub.Addr, confCopied.actionParams)
	if err != nil {
		return nil, fmt.Errorf("VS actioner created failed: %v", err)
	}

	vs := &VirtualService{
		id:      vsid,
		subject: *(sub.Addr.DeepCopy()),
		conf:    *confCopied,
		va:      va,

		state: types.Unknown,
		since: time.Now(),

		backends: make(map[CheckerID]*VSBackend),
		actioner: act,
		resync:   nil, // init it in func `Run`

		metricTaint:  true,
		metricTicker: nil, // init it in func `Run`
		metric:       va.metric,

		wg:     &sync.WaitGroup{},
		update: make(chan VSConfExt),
		notify: make(chan BackendState, va.m.appConf.CheckerNotifyChanSize),
		quit:   make(chan bool, 1),
	}

	glog.Infof("VS %s created", vsid)
	return vs, nil
}

func (vs *VirtualService) Update(conf *VSConfExt) {
	// Note: conf has been deep-copied already
	vs.update <- *conf
}

func (vs *VirtualService) calcState() types.State {
	var ups, downs int
	for _, rs := range vs.backends {
		if rs.checkerState == types.Unhealthy {
			downs++
		} else {
			ups++ // including types.Unknown
		}
	}

	vs.upBackends = ups
	vs.downBackends = downs
	return vs.judge()
}

func (vs *VirtualService) judge() types.State {
	if vs.upBackends < 0 || vs.downBackends < 0 {
		glog.Warningf("got minus state number in VS %s, UPs %d DOWNs %d, recalculate",
			vs.id, vs.upBackends, vs.downBackends)
		return vs.calcState()
	}

	// TODO: Support more VS healthy criteria with VSConf, such as
	//   minimum healthy backends, minimum healthy ratio, ...
	if vs.upBackends > 0 {
		return types.Healthy
	}
	return types.Unhealthy
}

func (vs *VirtualService) sendStateChangeNotice(newState types.State) {
	vs.va.notify <- VSState{
		id:    vs.id,
		state: newState,
	}
}
func (vs *VirtualService) updateStateTo(newState types.State) {
	vs.state = newState
	vs.since = time.Now()
	if newState == types.Unhealthy {
		vs.stats.down++
	} else {
		vs.stats.up++
	}
	vs.metricTaint = true
}

func (vs *VirtualService) act(changed []CheckerID) error {
	targets := make([]comm.RealServer, 0, len(changed))
	for _, ckid := range changed {
		rs := vs.backends[ckid]
		targets = append(targets, comm.RealServer{
			Addr:      rs.addr,
			Weight:    uint16(rs.uweight),
			Inhibited: rs.checkerState == types.Unhealthy,
		})
	}

	// Batch update, real checker states are carried by param `targets`.
	resp, err := vs.actioner.Act(types.Unknown, vs.conf.actionTimeout, targets)
	if err != nil {
		// FIXME: Partial update may have happened,
		//  how to know exactly the number of failed backends?
		var ups, downs int
		for _, rs := range targets {
			if rs.Inhibited {
				downs++
			} else {
				ups++
			}
		}
		if ups > 0 {
			vs.stats.upFailed++
			vs.metricTaint = true
		}
		if downs > 0 {
			vs.stats.downFailed++
			vs.metricTaint = true
		}
		if svc, ok := resp.(*comm.VirtualServer); ok {
			// TODO: process the returned new VS conf
			vsConf := vs.va.m.conf.GetVSConf(vs.id) // refetch VSConf
			vsConfExt := &VSConfExt{
				VSConf: *vsConf,
				vs:     *svc,
			}
			vs.doUpdate(vsConfExt.DeepCopy())
		} else {
			return fmt.Errorf("%v, response: %v", err, resp)
		}
		return err // never reach here
	} else {
		// act succeeded, backend checkerState reflects its real state now
		for _, ckid := range changed {
			rs := vs.backends[ckid]
			rs.state = rs.checkerState
		}
	}
	return nil
}

func (vs *VirtualService) doUpdate(conf *VSConfExt) {
	// Update VSConf
	vscf := conf.GetVSConf()

	vscf.methodParams = vscf.MergeDpvsCheckerConf(&conf.vs, vscf.methodParams)
	if vscf.method == checker.CheckMethodAuto {
		vscf.method = vscf.method.TranslateAuto(conf.vs.Addr.Proto)
	}

	if !vscf.DeepEqual(&vs.conf) {
		skip := false
		if vscf.actionSyncTime > 0 && vscf.actionSyncTime != vs.conf.actionSyncTime {
			if vs.resync != nil {
				vs.resync.Stop()
				vs.resync = time.NewTicker(vscf.actionSyncTime)
			}
			vs.conf.actionSyncTime = vscf.actionSyncTime
		}
		if vscf.actionTimeout > 0 && vscf.actionTimeout != vs.conf.actionTimeout {
			vs.conf.actionTimeout = vscf.actionTimeout
		}
		if !vscf.ActionConf.DeepEqual(&vs.conf.ActionConf) {
			// Restore Healthy state before changing Actioner to avoid inconsistency.
			changed := make([]CheckerID, 0, vs.downBackends)
			for ckid, rs := range vs.backends {
				if rs.checkerState == types.Unhealthy {
					changed = append(changed, ckid)
				}
			}
			if len(changed) > 0 {
				if err := vs.act(changed); err != nil {
					glog.Warningf("restore %s before changing VS %s actioner failed -- checkers: %v, error: %v",
						types.Healthy, vs.id, changed, err)
					skip = true
				} else {
					// Set checkerState to Healthy manually.
					for _, ckid := range changed {
						vs.backends[ckid].checkerState = types.Healthy
					}
					vs.upBackends = len(vs.backends)
					vs.downBackends = 0
					vsState := vs.judge()
					if vsState != vs.state {
						vs.sendStateChangeNotice(vsState)
						vs.updateStateTo(vsState)
					}
				}
			}
		}
		if !skip {
			vs.conf = *vscf
			glog.V(5).Infof("VSConf for %s updated successfully", vs.id)
		} else {
			vs.conf.CheckerConf = vscf.CheckerConf
			glog.Warningf("VSConf for %s partially updated", vs.id)
		}
	}

	// Remove staled Backends
	staled := make(map[CheckerID]struct{})
	for ckid, _ := range vs.backends {
		staled[ckid] = struct{}{}
	}
	for _, rs := range conf.vs.RSs {
		ckid := CheckerID(rs.Addr.String())
		if _, ok := staled[ckid]; ok {
			delete(staled, ckid)
		}
	}
	for ckid, _ := range staled {
		rs := vs.backends[ckid]
		delete(vs.backends, ckid)
		if rs.checkerState == types.Unhealthy {
			vs.downBackends--
		} else {
			vs.upBackends--
		}
		vs.metricTaint = true
		rs.checker.Stop()
	}
	if len(staled) > 0 {
		vsState := vs.judge()
		if vsState != vs.state {
			vs.sendStateChangeNotice(vsState)
			vs.updateStateTo(vsState)
		}
	}

	// Create new or update existing Backends
	for _, rs := range conf.vs.RSs {
		ckid := CheckerID(rs.Addr.String())
		ckConf := vscf.GetCheckerConf()
		state := types.Healthy
		if rs.Inhibited {
			state = types.Unhealthy
		}
		vsb, ok := vs.backends[ckid]
		if !ok { // create
			uuid := fmt.Sprintf("%s/%s", vs.id, ckid)
			checker, err := NewChecker(&rs.Addr, ckConf, vs)
			if err != nil {
				glog.Errorf("checker %s created failed: %v", uuid, err)
				continue
			}
			uweight := uint(rs.Weight)
			if rs.Inhibited && rs.Weight == 0 {
				// FIXME: How to determine uweight in this case?
				glog.Warningf("created checker %s with undetermined uweight, use default %d",
					uuid, DefaultCheckerWeight)
				uweight = DefaultCheckerWeight
			}
			vsb = &VSBackend{
				addr:         *(rs.Addr.DeepCopy()),
				uweight:      uweight,
				version:      conf.vs.Version,
				state:        state,
				checkerState: types.Unknown,
				checker:      checker,
			}
			vs.backends[ckid] = vsb
			vs.metricTaint = true
			vs.wg.Add(1)
			delay := time.NewTicker(time.Duration(1+rand.Intn(int(
				CheckerStartDelayMax.Milliseconds()))) * time.Millisecond)
			go checker.Run(vs.wg, delay.C)
		} else { // update
			uuid := vsb.checker.UUID()
			if vsb.version > conf.vs.Version {
				glog.Warningf("received VSBackend %s with eailier version, skip it", uuid)
				continue
			}
			if vsb.version == conf.vs.Version {
				// ??? Is it safe to skip Backend with version unchanged?
				// It relies on dpvs-agent, an alien factor. But it worths taking a risk
				// for the notewothy performance gains.
				glog.V(7).Infof("skip VSBackend %s with version unchanged", uuid)
				continue
			}
			if !rs.Inhibited || rs.Weight > 0 { // ??? Is it necessary?
				vsb.uweight = uint(rs.Weight)
			}
			vsb.version = conf.vs.Version
			if vsb.state != state {
				glog.Warningf("rectify VSBackend %s state from config: %s->%s",
					uuid, vsb.state, state)
				vsb.state = state
			}
			if vsb.state != vsb.checkerState {
				if err := vs.act([]CheckerID{ckid}); err != nil {
					glog.Warningf("VS %s update backend %s to %s failed: %v", vs.id, ckid, err)
				}
			}
			vsb.checker.Update(ckConf.DeepCopy())
		}
	}
}

func (vs *VirtualService) recvNotice(state *BackendState) {
	if state.state == types.Unhealthy {
		vs.stats.downNoticed++
	} else {
		vs.stats.upNoticed++
	}
	vs.metricTaint = true

	rs, ok := vs.backends[state.id]
	if !ok {
		// State notice of expired backend recieved. It should never reach here!
		glog.Warningf("Backend %s of VS %v not found upon recieved state notice!",
			state.id, vs.id)
		return
	}

	if rs.checkerState == state.state {
		return
	}
	rs.checkerState = state.state

	if err := vs.act([]CheckerID{state.id}); err != nil {
		glog.Warningf("VS %s update backend %s to %s failed: %v", vs.id, state.id, err)
	}

	if state.state == types.Unhealthy {
		vs.downBackends++
		if vs.upBackends > 0 {
			vs.upBackends--
		}
		vsState := vs.judge()
		if vsState != vs.state {
			vs.sendStateChangeNotice(vsState)
			vs.updateStateTo(vsState)
		}
	} else {
		vs.upBackends++
		if vs.downBackends > 0 {
			vs.downBackends--
		}
		vsState := vs.judge()
		if vsState != vs.state {
			vs.sendStateChangeNotice(vsState)
			vs.updateStateTo(vsState)
		}
	}
}

func (vs *VirtualService) doResync() {
	// resync checkers state
	changed := make([]CheckerID, 0)
	for ckid, rs := range vs.backends {
		if rs.checkerState != types.Unknown && rs.state != rs.checkerState {
			changed = append(changed, ckid)
		}
	}
	if len(changed) > 0 {
		if err := vs.act(changed); err != nil {
			glog.Warningf("VS %s resync checkers state failed -- checkers: %v, error: %v",
				vs.id, changed, err)
		} else {
			glog.Infof("VS %s resync checkers state succeeded -- checkers: %v", vs.id, changed)
		}
	}

	// recalculate and sync VS state
	glog.V(7).Infof("VS %s state before resync: %v, upBackends %d, downBackends %d",
		vs.id, vs.state, vs.upBackends, vs.downBackends)
	vsState := vs.calcState()
	if vsState != vs.state {
		glog.Warningf("VS %s state changed %s->%s after recalculation",
			vs.id, vs.state, vsState)
		vs.sendStateChangeNotice(vsState)
		vs.updateStateTo(vsState)
	}
}

func (vs *VirtualService) doMetricSend() {
	if !vs.metricTaint {
		return
	}

	metric := Metric{
		kind: MetricTypeVS,
		vaID: vs.va.id,
		vsID: vs.id,
		state: State{
			state: vs.state,
			since: vs.since,
		},
		stats: vs.stats,
	}
	vs.metric <- metric

	vs.metricTaint = false
}

func (vs *VirtualService) metricClean() {
	metric := Metric{
		kind: MetricTypeDelVS,
		vaID: vs.va.id,
		vsID: vs.id,
	}
	vs.metric <- metric
}

func (vs *VirtualService) cleanup() {
	if vs.resync != nil {
		vs.resync.Stop()
	}
	if vs.metricTicker != nil {
		vs.metricTicker.Stop()
	}
	for _, rs := range vs.backends {
		rs.checker.Stop()
	}
	vs.wg.Wait()

	vs.metricClean()

	// close and drain channels
	// Notes: No write to these channels any more,
	//   so it's safe to close the channels from the read side.
	close(vs.notify)
	for {
		if _, ok := <-vs.notify; !ok {
			break
		}
	}
	close(vs.update)
	<-vs.update
	close(vs.quit)
	<-vs.quit
}

func (vs *VirtualService) Run(wg *sync.WaitGroup, start <-chan time.Time) {
	glog.Infof("starting VS %s ...", vs.id)

	VSThreads.RunningInc()
	defer func() {
		wg.Done()
		VSThreads.StoppingDec()
		VSThreads.FinishedInc()
		glog.Infof("VS %s stopped successfully", vs.id)
	}()

	// wait for initial config
	select {
	case <-vs.quit:
		VSThreads.RunningDec()
		VSThreads.StoppingInc()
		return
	case conf := <-vs.update:
		vs.doUpdate(&conf)
	}

	// wait for a tick to avoid thundering herd at startup and to stagger
	// periodic jobs in VS such as resync.
	if start != nil {
		<-start
	}

	if vs.resync == nil {
		vs.resync = time.NewTicker(vs.conf.actionSyncTime)
	}
	if vs.metricTicker == nil {
		vs.metricTicker = time.NewTicker(vs.va.m.appConf.MetricDelay)
	}

	glog.V(5).Infof("VS %v loop started\n", vs.id)

	for {
		select {
		case <-vs.quit:
			VSThreads.RunningDec()
			VSThreads.StoppingInc()
			vs.cleanup()
			return
		case conf := <-vs.update:
			vs.doUpdate(&conf)
		case state := <-vs.notify:
			vs.recvNotice(&state)
		case <-vs.resync.C:
			vs.doResync()
		case <-vs.metricTicker.C:
			vs.doMetricSend()
		}
	}
}

func (vs *VirtualService) Stop() {
	glog.Infof("stopping VS %s ...", vs.id)
	vs.quit <- true
}
