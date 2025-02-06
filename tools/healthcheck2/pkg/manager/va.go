package manager

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/actioner"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/comm"
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
	checkerState types.State     // state reported from VS & checkers
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

	// va's status
	state   types.State
	since   time.Time
	stats   Statistics
	downVSs uint
	upVSs   uint

	vss      map[VSID]*VAVS
	actioner actioner.ActionMethod
	resync   *time.Ticker // timer to resync VA's state to dpvs

	wg     *sync.WaitGroup
	notify chan VSState
	update chan VAConf
	metric chan Metric
	quit   chan bool
}

func NewVAVS(sub *comm.VirtualServer, vs *VirtualService) *VAVS {
	addrCopied := sub.Addr.DeepCopy()
	vavs := &VAVS{
		addr:         *addrCopied,
		checkerState: types.Unknown,
		vs:           vs,
	}
	return vavs
}

func NewVA(sub *comm.VirtualServer, conf *VAConf) *VirtualAddress {
	// TODO
	return nil
}

func (va *VirtualAddress) calcState() (types.State, uint, uint) {
	var ups, downs uint
	for _, vs := range va.vss {
		if vs.checkerState == types.Unhealthy {
			downs++
		} else {
			ups++
		}
	}
	switch va.conf.downPolicy {
	case VAPolicyAllOf:
		if downs == 0 {
			return types.Unhealthy, ups, downs
		}
		return types.Healthy, ups, downs
	case VAPolicyOneOf:
		if (ups > 0) || (ups+downs == 0) {
			return types.Healthy, ups, downs
		}
		return types.Unhealthy, ups, downs
	default:
		return types.Healthy, ups, downs
	}
}

func (va *VirtualAddress) actUP() error {
	// TODO

	va.state = types.Healthy
	va.since = time.Now()
	return nil
}

func (va *VirtualAddress) actDOWN() error {
	// TODO

	va.state = types.Unhealthy
	va.since = time.Now()
	return nil
}

func (va *VirtualAddress) Update(conf *VAConf) {
	if conf == nil || conf.DeepEqual(&va.conf) {
		return
	}
	confCopied := conf.DeepCopy()
	va.update <- *confCopied
}

func (va *VirtualAddress) Stop() {
	va.quit <- true
}

func (va *VirtualAddress) doUpdate(conf *VAConf) {
	if conf.actioner != va.conf.actioner {
		if va.state == types.Unhealthy {
			if err := va.actUP(); err != nil {
				va.stats.upFailed++
				// NOTE: We shall NOT retrigger the update using the `update` channel because
				//  it may override the upcoming new configs. Just emit an error log and return.
				glog.Errorf("%s: actUP failed before updating configs: %v\n", va.id, err)
				return
			}
		}
		va.conf = *conf
		state, ups, downs := va.calcState()
		if state == types.Unhealthy {
			err := va.actDOWN()
			if err != nil {
				va.stats.downFailed++
				glog.Warningf("%s: actDown failed after updating configs: %v\n", va.id, err)
			} else {
				va.upVSs = ups
				va.downVSs = downs
			}
		}
	} else {
		va.conf = *conf
	}
}

func (va *VirtualAddress) Run(ctx context.Context, wg *sync.WaitGroup) {
	// TODO
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-va.quit:
			return
		case vaConf := <-va.update:
			fmt.Println(vaConf)
			// TODO
		case vsState := <-va.notify:
			fmt.Println(vsState)
			// TODO
			//case <-va.resync:
			// TODO
		}
	}
}
