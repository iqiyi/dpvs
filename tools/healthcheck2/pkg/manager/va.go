package manager

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/actioner"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

const (
	VSStartDelayMax = 3 * time.Second
)

var VAThreads ThreadStats

// VAID represents VirtualAddress ID.
// It must have the same format of net.IP::String().
type VAID string

func (id *VAID) valid() bool {
	return len(*id) > 0
}

type VAVS struct {
	addr         utils.L3L4Addr
	version      uint64          // deployment version
	checkerState types.State     // state reported from VS
	vs           *VirtualService // Restrictions: access only to its thread-safe members
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
	m       *Manager // Caution: access only to its thread-safe members

	// status members
	state   types.State
	since   time.Time
	stats   Statistics
	downVSs int
	upVSs   int

	vss      map[VSID]*VAVS
	actioner actioner.ActionMethod
	resync   *time.Ticker // timer to resync VA's state to dpvs

	// metric members
	metricTaint  bool
	metricTicker *time.Ticker
	metric       chan<- Metric

	// thread-safe members
	wg     *sync.WaitGroup
	update chan VAConfExt
	notify chan VSState
	quit   chan bool
}

func newVAVS(addr *utils.L3L4Addr, version uint64, vs *VirtualService) *VAVS {
	addrCopied := addr.DeepCopy()
	vavs := &VAVS{
		addr:         *addrCopied,
		version:      version,
		checkerState: types.Unknown,
		vs:           vs,
	}
	return vavs
}

func NewVA(sub net.IP, conf *VAConf, m *Manager) (*VirtualAddress, error) {
	if !conf.Valid() {
		return nil, fmt.Errorf("invalid VAConf %v", *conf)
	}

	vaid := VAID(sub.String())
	confCopied := conf.DeepCopy()
	act, err := actioner.NewActioner(conf.actioner, &utils.L3L4Addr{IP: sub},
		confCopied.actionParams)
	if err != nil {
		return nil, fmt.Errorf("VA actioner created failed: %v", err)
	}

	va := &VirtualAddress{
		id:      vaid,
		subject: utils.IPAddrClone(sub),
		conf:    *confCopied,
		m:       m,

		state: types.Unknown,
		since: time.Now(),

		vss:      make(map[VSID]*VAVS),
		actioner: act,
		resync:   nil, // init it in func `Run`

		metricTaint:  true,
		metricTicker: nil, // init it in func `Run`
		metric:       m.metricServer.notify,

		wg:     &sync.WaitGroup{},
		update: make(chan VAConfExt),
		notify: make(chan VSState, m.appConf.VSNotifyChanSize),
		quit:   make(chan bool),
	}

	glog.Infof("VA %s created", vaid)
	return va, nil
}

func (va *VirtualAddress) Update(conf *VAConfExt) {
	confCopied := conf.DeepCopy()
	va.update <- *confCopied
}

func (va *VirtualAddress) Stop() {
	glog.Infof("stoping VA %s ...", va.id)
	va.quit <- true
}

// calcState sums each state of VS in VA, updates VA's upVSs/downVSs,
// and finally concludes the VA state.
func (va *VirtualAddress) calcState() types.State {
	var ups, downs int
	for _, vs := range va.vss {
		if vs.checkerState == types.Unhealthy {
			downs++
		} else {
			ups++ // including types.Unknown
		}
	}

	va.upVSs = ups
	va.downVSs = downs
	return va.judge()
}

// judge concludes the VA state with upVSs/downVSs in it with respect to
// its configured downPolicy.
// Note that the initial state Unknown is counted as Healthy.
func (va *VirtualAddress) judge() types.State {
	if va.upVSs < 0 || va.downVSs < 0 {
		glog.Warningf("got minus state number in VA %s, UPs %d DOWNs %d, recalculate",
			va.id, va.upVSs, va.downVSs)
		return va.calcState()
	}
	switch va.conf.downPolicy {
	case VAPolicyAllOf:
		if va.upVSs == 0 {
			return types.Unhealthy
		}
		return types.Healthy
	case VAPolicyOneOf:
		if va.downVSs == 0 {
			return types.Healthy
		}
		return types.Unhealthy
	default:
		return types.Healthy
	}
}

func (va *VirtualAddress) actUP() error {
	if _, err := va.actioner.Act(types.Healthy, va.conf.actionTimeout); err != nil {
		va.stats.upFailed++
		va.metricTaint = true
		return err
	}
	va.state = types.Healthy
	va.since = time.Now()
	va.stats.up++
	va.metricTaint = true
	return nil
}

func (va *VirtualAddress) actDOWN() error {
	if _, err := va.actioner.Act(types.Unhealthy, va.conf.actionTimeout); err != nil {
		va.stats.downFailed++
		va.metricTaint = true
		return err
	}
	va.state = types.Unhealthy
	va.since = time.Now()
	va.stats.down++
	va.metricTaint = true
	return nil
}

func (va *VirtualAddress) act(state types.State) error {
	if state == types.Unhealthy {
		return va.actDOWN()
	}
	return va.actUP()
}

func (va *VirtualAddress) doUpdate(conf *VAConfExt) {
	vacf := conf.GetVAConf()

	// Update VAConf
	if !vacf.DeepEqual(&va.conf) {
		skip := false
		needResync := false
		if vacf.downPolicy != va.conf.downPolicy {
			vacf.downPolicy = va.conf.downPolicy
			needResync = true
		}
		if vacf.actionSyncTime > 0 && vacf.actionSyncTime != va.conf.actionSyncTime {
			if va.resync != nil {
				va.resync.Stop()
				va.resync = time.NewTicker(vacf.actionSyncTime)
			}
			va.conf.actionSyncTime = vacf.actionSyncTime
		}
		if vacf.actionTimeout > 0 && vacf.actionTimeout != va.conf.actionTimeout {
			va.conf.actionTimeout = vacf.actionTimeout
		}
		if !vacf.ActionConf.DeepEqual(&va.conf.ActionConf) {
			if va.state == types.Unhealthy {
				// Restore Healthy state before changing Actioner to avoid inconsistency.
				if err := va.actUP(); err != nil {
					glog.Errorf("restore %s before changing VA %s actioner failed: %v, abort change",
						types.Healthy, va.id, err)
					skip = true
				}
			}
			if !skip {
				if act, err := actioner.NewActioner(vacf.actioner, &utils.L3L4Addr{IP: va.subject},
					vacf.actionParams); err != nil {
					glog.Errorf("VA %s actioner recreated failed: %v", va.id, err)
					skip = true
				} else {
					va.actioner = act
					needResync = true
				}
			}
		}
		if !skip {
			va.conf = *vacf
			glog.V(5).Infof("VAConf for %s updated successfully", va.id)
		} else {
			glog.Warningf("VAConf for %s partially updated", va.id)
		}
		if needResync {
			va.doResync()
		}
	}

	// Remove staled VSs
	staled := make(map[VSID]struct{})
	for vsid, _ := range va.vss {
		staled[vsid] = struct{}{}
	}
	for _, svc := range conf.vss {
		vsid := VSID(svc.Addr.String())
		if _, ok := staled[vsid]; ok {
			delete(staled, vsid)
		}
	}
	for vsid, _ := range staled {
		vavs := va.vss[vsid]
		delete(va.vss, vsid)
		if vavs.checkerState == types.Unhealthy {
			va.downVSs--
		} else {
			va.upVSs--
		}
		va.metricTaint = true
		vavs.vs.Stop()
	}
	if len(staled) > 0 {
		vaState := va.judge()
		if vaState != va.state {
			if err := va.act(vaState); err != nil {
				glog.Warningf("VA %s state change to %s failed: %v", va.id, vaState, err)
			}
		}
	}

	// Create new or update existing VSs
	for _, svc := range conf.vss {
		vsid := VSID(svc.Addr.String())
		vsConf := va.m.conf.GetVSConf(vsid)
		vavs, ok := va.vss[vsid]
		if !ok { // create
			vs, err := NewVS(&svc, vsConf, va)
			if err != nil {
				glog.Errorf("VS created failed for %s: %v", vsid, err)
				continue
			}
			addr := svc.Addr.DeepCopy()
			vavs = &VAVS{
				addr:         *addr,
				version:      svc.Version,
				checkerState: types.Unknown,
				vs:           vs,
			}
			va.vss[vsid] = vavs
			va.metricTaint = true
			va.wg.Add(1)
			delay := time.NewTicker(time.Duration(1+rand.Intn(int(
				VSStartDelayMax.Milliseconds()))) * time.Millisecond)
			go vs.Run(va.wg, delay.C)
		} else { // update
			if vavs.version > svc.Version {
				glog.Warningf("received VS %s with eariler version, skip it", vsid)
				continue
			}
			if vavs.version == svc.Version {
				// ??? Is it safe to skip VS with version unchanged?
				// It relies on dpvs-agent, an alien factor. But it worths taking a risk
				// for the notewothy performance gains.
				glog.V(7).Infof("skip VS %s with version unchanged", vsid)
				continue
			}
			vavs.version = svc.Version
		}
		vsConfExt := &VSConfExt{
			VSConf: *vsConf.DeepCopy(),
			vs:     svc, // svc has already been deep-copied in VAConfExt
		}
		vavs.vs.Update(vsConfExt)
	}
}

func (va *VirtualAddress) recvNotice(state *VSState) {
	if state.state == types.Unhealthy {
		va.stats.downNoticed++
	} else {
		va.stats.upNoticed++
	}
	va.metricTaint = true

	vavs, ok := va.vss[state.id]
	if !ok {
		// State notice of expired VS recieved. It should never reach here.
		glog.Warningf("VS %s not found upon recieved state notice!", state.id)
		return
	}

	if vavs.checkerState == state.state {
		return
	}
	vavs.checkerState = state.state

	if state.state == types.Unhealthy {
		va.downVSs++
		if va.upVSs > 0 {
			va.upVSs--
		}
		vaState := va.judge()
		if vaState != va.state {
			if err := va.act(vaState); err != nil {
				glog.Warningf("VA %s state change to %s failed: %v", va.id, state, err)
			}
		}
	} else {
		va.upVSs++
		if va.downVSs > 0 {
			va.downVSs--
		}
		vaState := va.judge()
		if vaState != va.state {
			if err := va.act(vaState); err != nil {
				glog.Warningf("VA %s state change to %s failed: %v", va.id, state, err)
			}
		}
	}
}

func (va *VirtualAddress) doResync() {
	glog.V(7).Infof("VA %s state before resync: %v, upVSs %d, downVSs %d",
		va.id, va.state, va.upVSs, va.downVSs)
	state := va.calcState()
	if state != va.state {
		if err := va.act(state); err != nil {
			glog.Warningf("VA %s state resync to %s failed: %v", va.id, state, err)
		} else {
			glog.Infof("VA %s state resync to %s succeeded", va.id, state)
		}
	}
}

func (va *VirtualAddress) doMetricSend() {
	if !va.metricTaint {
		return
	}

	metric := Metric{
		kind: MetricTypeVA,
		vaID: va.id,
		state: State{
			state: va.state,
			since: va.since,
		},
		stats: va.stats,
	}
	va.metric <- metric

	va.metricTaint = false
}

func (va *VirtualAddress) cleanup() {
	if va.resync != nil {
		va.resync.Stop()
	}
	if va.metricTicker != nil {
		va.metricTicker.Stop()
	}
	for _, vavs := range va.vss {
		vavs.vs.Stop()
	}
	va.wg.Wait()

	// close and drain channels
	// Notes: No write to these channels now, so it's safe to close the channels
	//   from the read side.
	close(va.notify)
	for {
		if _, ok := <-va.notify; !ok {
			break
		}
	}
	close(va.update)
	<-va.update
	close(va.quit)
	<-va.quit
}

func (va *VirtualAddress) Run(wg *sync.WaitGroup, start <-chan time.Time) {
	glog.Infof("starting VA %s ...", va.id)
	VAThreads.RunningInc()
	defer func() {
		wg.Done()
		VAThreads.StoppingDec()
		VAThreads.FinishedInc()
		glog.Infof("VA %s stopped successfully", va.id)
	}()

	// wait for initial config
	select {
	case <-va.quit:
		VAThreads.RunningDec()
		VAThreads.StoppingInc()
		return
	case conf := <-va.update:
		va.doUpdate(&conf)
	}

	// wait for a tick to avoid thundering herd at startup and to stagger
	// periodic jobs in VA such as resync.
	if start != nil {
		<-start
	}

	if va.resync == nil {
		va.resync = time.NewTicker(va.conf.actionSyncTime)
	}
	if va.metricTicker == nil {
		va.metricTicker = time.NewTicker(va.m.appConf.MetricDelay)
	}

	glog.V(5).Infof("VA %v loop started\n", va.id)

	for {
		select {
		case <-va.quit:
			VAThreads.RunningDec()
			VAThreads.StoppingInc()
			va.cleanup()
			return
		case conf := <-va.update:
			va.doUpdate(&conf)
		case state := <-va.notify:
			va.recvNotice(&state)
		case <-va.resync.C:
			va.doResync()
		case <-va.metricTicker.C:
			va.doMetricSend()
		}
	}
}
