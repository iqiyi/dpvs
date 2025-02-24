package manager

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/checker"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var CheckerThreads, HealthCheckThreads ThreadStats

// CheckerID represents VS-scoped Checker ID.
// It has the format of L3L4Addr::String().
type CheckerID string

func (id *CheckerID) valid() bool {
	return len(*id) > 0
}

type Checker struct {
	// read-only members
	id     CheckerID
	target utils.L3L4Addr
	conf   CheckerConf

	// status members
	state types.State
	count uint
	since time.Time
	stats Statistics // downFailed: check error; upFailed: check timeout

	method      checker.CheckMethod
	checkTicker *time.Ticker
	vs          *VirtualService // Restrictions: only access to its read-only/thread-safe members

	// metric members
	metricTaint  bool
	metricTicker *time.Ticker
	metric       chan<- Metric

	// thread-safe members
	update chan CheckerConf
	quit   chan bool
}

func NewChecker(target *utils.L3L4Addr, conf *CheckerConf, vs *VirtualService) (*Checker, error) {
	if !conf.Valid() {
		return nil, fmt.Errorf("invalid CheckerConf %v", *conf)
	}

	ckid := CheckerID(target.String())
	confCopied := conf.DeepCopy()

	method, err := checker.NewChecker(confCopied.method, target, confCopied.methodParams)
	if err != nil {
		return nil, fmt.Errorf("fail to create checker method %v: %v", confCopied.method, err)
	}
	checkTicker := time.NewTicker(confCopied.interval)
	metricTicker := time.NewTicker(vs.va.m.appConf.MetricDelay)

	checker := &Checker{
		id:     ckid,
		target: *target,
		conf:   *confCopied,

		state: types.Unknown,
		since: time.Now(),

		method:      method,
		checkTicker: checkTicker,
		vs:          vs,

		metricTaint:  true,
		metricTicker: metricTicker,
		metric:       vs.metric,

		update: make(chan CheckerConf),
		quit:   make(chan bool),
	}

	return checker, nil
}

// UUID returns a global unique ID for the checker.
func (c *Checker) UUID() string {
	return fmt.Sprintf("%s/%s", c.vs.id, c.id)
}

func (c *Checker) sendNotice() {
	if c.state == types.Unknown {
		return
	}
	c.vs.notify <- BackendState{
		id:    c.id,
		state: c.state,
	}
	if c.state == types.Unhealthy {
		c.stats.downNoticed++
	} else {
		c.stats.upNoticed++
	}
}

func (c *Checker) doPostCheck(newState types.State) {
	if newState != c.state {
		c.state = newState
		c.since = time.Now()
		c.count = 0
	}
	c.count++

	switch newState {
	case types.Healthy:
		c.stats.up++
		if c.count == c.conf.upRetry {
			c.sendNotice()
		}
	case types.Unhealthy:
		c.stats.down++
		if c.count == c.conf.downRetry {
			c.sendNotice()
		}
	}
}

func (c *Checker) doUpdate(conf *CheckerConf) {
	if conf.DeepEqual(&c.conf) {
		return
	}

	skip := false

	if conf.interval != c.conf.interval {
		c.checkTicker.Stop()
		c.checkTicker = time.NewTicker(conf.interval)
		conf.interval = c.conf.interval
	}
	if conf.downRetry != c.conf.downRetry {
		c.conf.downRetry = conf.downRetry
		c.sendNotice()
	}
	if conf.upRetry != c.conf.upRetry {
		c.conf.upRetry = conf.upRetry
		c.sendNotice()
	}
	if conf.timeout != c.conf.timeout {
		c.conf.timeout = conf.timeout
	}
	if !conf.DeepEqual(&c.conf) { // method or its params changed
		method, err := checker.NewChecker(conf.method, &c.target, conf.methodParams)
		if err != nil {
			glog.Errorf("fail to update checker method %v-%v: %v",
				c.conf.method, conf.method, err)
			skip = true
		} else {
			c.method = method
		}
	}

	if !skip {
		glog.V(5).Infof("CheckerConf for %s updated successfully", c.UUID())
		c.conf = *conf
	} else {
		glog.Warningf("CheckerConf for %s partially updated", c.UUID())
	}
}

func (c *Checker) doCheck() {
	ch := make(chan types.State)

	go func() {
		// TODO: Determine a way to ensure that this go routine does not linger.
		HealthCheckThreads.RunningInc()
		if state, err := c.method.Check(&c.target, c.conf.timeout); err != nil {
			ch <- state
		} else {
			glog.Warningf("Checker %s executes healthcheck failed: %v", c.UUID(), err)
			ch <- types.Unknown
		}
		HealthCheckThreads.RunningDec()
		HealthCheckThreads.FinishedInc()
	}()

	select {
	case state := <-ch:
		if state != types.Unknown {
			c.doPostCheck(state)
		} else {
			c.stats.downFailed++
		}
	case <-time.After(c.conf.timeout + time.Second):
		c.stats.upFailed++
		glog.Warningf("Checker %s executes healthcheck timeout", c.UUID())
	}
}

func (c *Checker) doMetricSend() {
	if !c.metricTaint {
		return
	}

	metric := Metric{
		kind:      MetricTypeChecker,
		vaID:      c.vs.va.id,
		vsID:      c.vs.id,
		checkerID: c.id,
		state: State{
			state: c.state,
			since: c.since,
		},
	}
	c.metric <- metric

	c.metricTaint = false
}

func (c *Checker) Update(conf *CheckerConf) {
	// Note: conf has been deep-copied already
	c.update <- *conf
}

func (c *Checker) Run(ctx context.Context, wg *sync.WaitGroup, start <-chan time.Time) {
	uuid := c.UUID()
	glog.Infof("starting Checker %s ...", uuid)

	CheckerThreads.RunningInc()
	defer func() {
		wg.Done()
		CheckerThreads.StoppingDec()
		CheckerThreads.FinishedInc()
		glog.Infof("Checker %s stopped successfully", uuid)
	}()

	// wait for a tick to avoid thundering herd at startup and to stagger
	if start != nil {
		<-start
	}

	for {
		select {
		case <-ctx.Done():
			CheckerThreads.RunningDec()
			CheckerThreads.StoppingInc()
			c.cleanup()
			return
		case <-c.quit:
			CheckerThreads.RunningDec()
			CheckerThreads.StoppingInc()
			c.cleanup()
			return
		case conf := <-c.update:
			c.doUpdate(&conf)
		case <-c.checkTicker.C:
			c.doCheck()
		case <-c.metricTicker.C:
			c.doMetricSend()
		}
	}
}

func (c *Checker) cleanup() {
	c.checkTicker.Stop()
	c.metricTicker.Stop()

	// Notes: No write to these channels any more,
	//   so it's safe to close the channels from the read side.
	close(c.update)
	<-c.update
	close(c.quit)
	<-c.quit
}

func (c *Checker) Stop() {
	glog.Infof("Stopping Checker %d ...", c.UUID())
	c.quit <- true
}
