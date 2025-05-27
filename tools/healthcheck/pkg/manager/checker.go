// /*
// Copyright 2025 IQiYi Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// */

package manager

import (
	"fmt"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/iqiyi/dpvs/tools/healthcheck/pkg/checker"
	"github.com/iqiyi/dpvs/tools/healthcheck/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck/pkg/utils"
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
	// Notes: conf has been validated, do not repeat the work!
	// if err := conf.Valid(); err != nil {
	// return nil, fmt.Errorf("invalid CheckerConf %v: %v", *conf, err)
	// }

	ckid := CheckerID(target.String())
	confCopied := conf.DeepCopy()

	method, err := checker.NewChecker(confCopied.Method, target, confCopied.MethodParams)
	if err != nil {
		return nil, fmt.Errorf("fail to create checker method %v: %v", confCopied.Method, err)
	}

	checker := &Checker{
		id:     ckid,
		target: *target,
		conf:   *confCopied,

		state: types.Unknown,
		since: time.Now(),

		method:      method,
		checkTicker: nil, // init it in func `Run`
		vs:          vs,

		metricTaint:  true,
		metricTicker: nil, // init it in func `Run`
		metric:       vs.metric,

		update: make(chan CheckerConf, 1),
		quit:   make(chan bool, 1),
	}

	return checker, nil
}

// UUID returns a global unique ID for the checker.
func (c *Checker) UUID() string {
	return fmt.Sprintf("%s/%s", c.vs.id, c.id)
}

func (c *Checker) sendNotice() {
	glog.V(5).Infof("Checker %v sending %v notice to VS", c.UUID(), c.state)
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
	c.metricTaint = true
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
		c.metricTaint = true
		if c.count == c.conf.UpRetry+1 {
			c.sendNotice()
		}
	case types.Unhealthy:
		c.stats.down++
		c.metricTaint = true
		if c.count == c.conf.DownRetry+1 {
			c.sendNotice()
		}
	}
}

func (c *Checker) doUpdate(conf *CheckerConf) {
	if conf.DeepEqual(&c.conf) {
		return
	}

	skip := false

	if conf.Interval != c.conf.Interval {
		glog.Infof("Updating Interval of checker %s: %v->%v", c.UUID(), c.conf.Interval, conf.Interval)
		c.checkTicker.Stop()
		c.checkTicker = time.NewTicker(conf.Interval)
		c.conf.Interval = conf.Interval
	}
	if conf.DownRetry != c.conf.DownRetry {
		glog.Infof("Updating DownRetry of checker %s: %v->%v", c.UUID(), c.conf.DownRetry, conf.DownRetry)
		c.conf.DownRetry = conf.DownRetry
		if c.state == types.Unhealthy && conf.DownRetry <= c.count {
			c.sendNotice()
		}
	}
	if conf.UpRetry != c.conf.UpRetry {
		glog.Infof("Updating UpRetry of checker %s: %v->%v", c.UUID(), c.conf.UpRetry, conf.UpRetry)
		c.conf.UpRetry = conf.UpRetry
		if c.state == types.Healthy && conf.UpRetry <= c.count {
			c.sendNotice()
		}
	}
	if conf.Timeout != c.conf.Timeout {
		glog.Infof("Updating Timeout of checker %s: %v->%v", c.UUID(), c.conf.Timeout, conf.Timeout)
		c.conf.Timeout = conf.Timeout
	}
	if !conf.DeepEqual(&c.conf) { // method or its params changed
		glog.Infof("Updating Method of checker %s: %v(%v)->%v(%v)", c.UUID(), c.conf.Method,
			c.conf.MethodParams, conf.Method, conf.MethodParams)
		method, err := checker.NewChecker(conf.Method, &c.target, conf.MethodParams)
		if err != nil {
			glog.Errorf("fail to update checker method %v-%v: %v",
				c.conf.Method, conf.Method, err)
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
	glog.V(9).Infof("Checking %s ...", c.UUID())
	ch := make(chan types.State)

	go func() {
		// TODO: Determine a way to ensure that this go routine does not linger.
		HealthCheckThreads.RunningInc()
		if state, err := c.method.Check(&c.target, c.conf.Timeout); err != nil {
			glog.Warningf("Checker %s executes healthcheck failed: %v", c.UUID(), err)
			ch <- types.Unknown
		} else {
			ch <- state
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
			c.metricTaint = true
		}
	case <-time.After(c.conf.Timeout + time.Second):
		c.stats.upFailed++
		c.metricTaint = true
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
		stats: c.stats,
	}
	c.metric <- metric

	c.metricTaint = false
}

func (c *Checker) metricClean() {
	metric := Metric{
		kind:      MetricTypeDelChecker,
		vaID:      c.vs.va.id,
		vsID:      c.vs.id,
		checkerID: c.id,
	}
	c.metric <- metric
}

func (c *Checker) Update(conf *CheckerConf) {
	// Note: conf has been deep-copied already
	c.update <- *conf
}

func (c *Checker) Run(wg *sync.WaitGroup, start <-chan time.Time) {
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

	if c.checkTicker == nil {
		c.checkTicker = time.NewTicker(c.conf.Interval)
	}
	if c.metricTicker == nil {
		c.metricTicker = time.NewTicker(c.vs.va.m.appConf.MetricDelay)
	}

	glog.V(5).Infof("Checker %v loop started\n", uuid)

	for {
		select {
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
	if c.checkTicker != nil {
		c.checkTicker.Stop()
	}
	if c.metricTicker != nil {
		c.metricTicker.Stop()
	}
	c.metricClean()

	// Notes: No write to these channels any more,
	//   so it's safe to close the channels from the read side.
	close(c.update)
	<-c.update
	close(c.quit)
	<-c.quit
}

func (c *Checker) Stop() {
	glog.Infof("Stopping Checker %v ...", c.UUID())
	c.quit <- true
}
