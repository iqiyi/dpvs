package manager

import (
	"context"
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

const VSStartDelayMax = 3 * time.Second

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
	downVSs uint
	upVSs   uint

	vss      map[VSID]*VAVS
	actioner actioner.ActionMethod
	resync   *time.Ticker // timer to resync VA's state to dpvs

	// thread-safe members
	wg     *sync.WaitGroup
	update chan VAConfExt
	notify chan VSState
	metric chan<- Metric
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
		confCopied.ActionConf.actionParams)
	if err != nil {
		return nil, fmt.Errorf("VA actioner created failed: %v", err)
	}
	resyncTicker := time.NewTicker(confCopied.actionSyncTime)

	vs := &VirtualAddress{
		id:      vaid,
		subject: utils.IPAddrClone(sub),
		conf:    *confCopied,
		m:       m,

		state: types.Unknown,
		since: time.Now(),

		vss:      make(map[VSID]*VAVS),
		actioner: act,
		resync:   resyncTicker,

		wg:     &sync.WaitGroup{},
		update: make(chan VAConfExt),
		notify: make(chan VSState, m.appConf.VSNotifyChanSize),
		metric: m.metricServer.notify,
		quit:   make(chan bool),
	}

	glog.Infof("VA %s created", vaid)
	return vs, nil
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
	var ups, downs uint
	for _, vs := range va.vss {
		if vs.checkerState == types.Unhealthy {
			downs++
		} else {
			ups++
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
	if err := va.actioner.Act(types.Healthy, va.conf.actionTimeout); err != nil {
		va.stats.upFailed++
		return err
	}
	va.state = types.Healthy
	va.since = time.Now()
	va.stats.up++
	return nil
}

func (va *VirtualAddress) actDOWN() error {
	if err := va.actioner.Act(types.Unhealthy, va.conf.actionTimeout); err != nil {
		va.stats.downFailed++
		return err
	}
	va.state = types.Unhealthy
	va.since = time.Now()
	va.stats.down++
	return nil
}

func (va *VirtualAddress) act(state types.State) error {
	if state == types.Unhealthy {
		return va.actDOWN()
	}
	return va.actUP()
}

func (va *VirtualAddress) doUpdate(ctx context.Context, conf *VAConfExt) {
	vacf := conf.GetVAConf()

	// update VAConf
	if !vacf.DeepEqual(&va.conf) {
		va.conf = *vacf
		va.doResync()
	}

	// remove staled VSs
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
		vavs.vs.Stop()
	}

	// add new or update existing VSs
	for _, svc := range conf.vss {
		vsid := VSID(svc.Addr.String())
		vsConf := va.m.conf.GetVSConf(vsid)
		vavs, ok := va.vss[vsid]
		if !ok { // create
			vs, err := NewVS(&svc, vsConf, va.m)
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
			va.wg.Add(1)
			delay := time.NewTicker(time.Duration(1+rand.Intn(int(
				VSStartDelayMax.Milliseconds()))) * time.Millisecond)
			go vs.Run(ctx, va.wg, delay.C)
		} else { // update
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

	vavs, ok := va.vss[state.id]
	if !ok {
		// State notice of expired VS recieved. Need to resync?
		// No! It has resync-ed when config was updated.
		glog.V(4).Infof("VS %s not found for recieved VS state notice", state.id)
		return
	}

	if vavs.checkerState == state.state {
		return
	}
	vavs.checkerState = state.state

	if state.state == types.Unhealthy {
		va.downVSs++
		vaState := va.judge()
		if vaState != va.state {
			if err := va.act(vaState); err != nil {
				glog.Warningf("VA %s state change to %s failed: %v", va.id, state, err)
			}
		}
	} else {
		va.upVSs++
		vaState := va.judge()
		if vaState != va.state {
			if err := va.act(vaState); err != nil {
				glog.Warningf("VA %s state change to %s failed: %v", va.id, state, err)
			}
		}
	}
}

func (va *VirtualAddress) doResync() {
	state := va.calcState()
	if state != va.state {
		if err := va.act(state); err != nil {
			glog.Warningf("VA %s state resync to %s failed: %v", va.id, state, err)
		} else {
			glog.Infof("VA %s state resync to %s succeeded", va.id, state)
		}
	}
}

func (va *VirtualAddress) cleanup() {
	va.resync.Stop()
	for _, vavs := range va.vss {
		vavs.vs.Stop()
	}
	va.wg.Wait()

	// close and drain channels
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

func (va *VirtualAddress) Run(ctx context.Context, wg *sync.WaitGroup, start <-chan time.Time) {
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
	case <-ctx.Done():
		VAThreads.RunningDec()
		VAThreads.StoppingInc()
		return
	case conf := <-va.update:
		va.doUpdate(ctx, &conf)
	}

	// wait for a tick to avoid thundering herd at startup and to stagger
	// periodic jobs in VA such as resync.
	if start != nil {
		<-start
	}

	for {
		select {
		case <-ctx.Done():
			VAThreads.RunningDec()
			VAThreads.StoppingInc()
			va.cleanup()
			return
		case <-va.quit:
			VAThreads.RunningDec()
			VAThreads.StoppingInc()
			va.cleanup()
			return
		case conf := <-va.update:
			va.doUpdate(ctx, &conf)
		case state := <-va.notify:
			va.recvNotice(&state)
		case <-va.resync.C:
			va.doResync()
		}
	}
}
