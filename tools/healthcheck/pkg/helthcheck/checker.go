// Copyright 2023 IQiYi Inc. All Rights Reserved.
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
//
// The healthcheck package refers to the framework of "github.com/google/
// seesaw/healthcheck" heavily, with only some adaption changes for DPVS.

package hc

import (
	"sync"
	"time"

	log "github.com/golang/glog"
)

const uweightDefault uint16 = 100

var (
	proxyProtoV1LocalCmd        = "PROXY UNKNOWN\r\n"
	proxyProtoV2LocalCmd []byte = []byte{
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51,
		0x55, 0x49, 0x54, 0x0A, 0x20, 0x00, 0x00, 0x00,
	}
)

// Checks provides a map of healthcheck configurations.
type CheckerConfigs struct {
	Configs map[Id]*CheckerConfig
}

// Checker represents a healthcheck instance.
type Checker struct {
	CheckerConfig

	lock      sync.RWMutex
	dryrun    bool
	uweight   uint16
	start     time.Time
	successes uint64
	failures  uint64
	failed    uint64
	state     State
	result    *Result

	update chan CheckerConfig
	notify chan<- *Notification
	quit   chan bool
}

// NewCheck returns an initialised Checker.
func NewChecker(notify chan<- *Notification, state State, weight uint16) *Checker {
	// FIXME: how to obtain the original weight if the checker's
	//        initial state is unhealthy?
	if state == StateUnhealthy && weight == 0 {
		weight = uweightDefault
	}
	return &Checker{
		state:   state,
		uweight: weight,
		notify:  notify,
		update:  make(chan CheckerConfig, 2),
		quit:    make(chan bool, 1),
	}
}

// Status returns the current status for this healthcheck instance.
func (hc *Checker) Status() Status {
	hc.lock.RLock()
	defer hc.lock.RUnlock()
	status := Status{
		Version:   hc.Version,
		LastCheck: hc.start,
		Failures:  hc.failures,
		Successes: hc.successes,
		State:     hc.state,
	}
	if hc.state == StateHealthy {
		status.Weight = hc.uweight
	}
	if hc.result != nil {
		status.Duration = hc.result.Duration
		status.Message = hc.result.String()
	}
	return status
}

func (hc *Checker) updateConfig(conf *CheckerConfig) {
	// Note:
	//   The conf::Weight must be the original weight not modified by healthcheck program,
	//   while conf::State reflects the health state derived from the inhibited flag set by
	//   the healthcheck program.

	//log.Infof("[updateConfig] id(%v) version(%d->%d) target(%v) %v->%v weight(%d->%d)\n", conf.Id,
	//	hc.Version, conf.Version, conf.Target, hc.State, conf.State, hc.Weight, conf.Weight)

	if len(hc.Id) == 0 {
		hc.CheckerConfig = *conf
		return
	}

	if conf.Version < hc.Version {
		return
	}

	hc.State = conf.State
	hc.lock.Lock()
	state := hc.state
	hc.state = conf.State
	hc.lock.Unlock()
	if state != conf.State {
		log.Warningf("%v: healthcheck's state changed externally %v -> %v",
			hc.Id, state, conf.State)
	}

	if conf.State != StateUnhealthy || conf.State == StateUnhealthy && conf.Weight > 0 {
		// Update all the checker configs when conf's state is healthy.
		hc.Weight = conf.Weight
		if conf.Interval > 0 {
			hc.Interval = conf.Interval
		}
		if conf.Timeout > 0 {
			hc.Timeout = conf.Timeout
		}
		if conf.Retry > 0 {
			hc.Retry = conf.Retry
		}

		hc.lock.Lock()
		weight := hc.uweight
		hc.uweight = conf.Weight
		hc.lock.Unlock()

		hc.Version = conf.Version
		if weight != conf.Weight {
			log.Warningf("%v: healthcheck's user weight changed %d -> %d",
				hc.Id, weight, conf.Weight)
		}
	}
}

// execute invokes the given healthcheck checker with the configured timeout.
func (hc *Checker) execute() *Result {
	ch := make(chan *Result, 1)
	checker := hc.CheckMethod
	timeout := hc.Timeout
	target := hc.Target
	go func() {
		// TODO: Determine a way to ensure that this go routine does not linger.
		ch <- checker.Check(target, timeout)
	}()
	select {
	case result := <-ch:
		return result
	case <-time.After(timeout + time.Second):
		return &Result{"Timed out", false, timeout, nil}
	}
}

// Notification generates a healthcheck notification for this checker.
func (hc *Checker) Notification() *Notification {
	return &Notification{
		Id:     hc.Id,
		Target: hc.Target,
		Status: hc.Status(),
	}
}

// Notify sends a healthcheck notification for this checker.
func (hc *Checker) Notify() {
	hc.notify <- hc.Notification()
}

// healthcheck executes the given checker.
func (hc *Checker) healthcheck() {
	if hc.CheckMethod == nil {
		return
	}
	start := time.Now()

	var result *Result
	if hc.dryrun {
		result = NewResult(start, "dryrun mode; always succeed", true, nil)
	} else {
		result = hc.execute()
	}

	status := "SUCCESS"
	state := StateHealthy
	if !result.Success {
		status = "FAILURE"
		state = StateUnhealthy
	}
	log.Infof("%v: %s: %v", hc.Id, status, result)

	hc.lock.Lock()

	hc.start = start
	hc.result = result

	if result.Success {
		hc.failed = 0
		hc.successes++
	} else {
		hc.failed++
		hc.failures++
	}

	if hc.state == StateHealthy && hc.failed > 0 && hc.failed <= uint64(hc.CheckerConfig.Retry) {
		log.Infof("%v: Failure %d - retrying...", hc.Id, hc.failed)
		state = StateHealthy
	}
	transition := (hc.state != state)
	hc.state = state

	hc.lock.Unlock()

	if transition {
		hc.Notify()
	}
}

// Run invokes a healthcheck. It waits for the initial configuration to be
// provided via the configuration channel, after which the configured
// healthchecker is invoked at the given interval. If a new configuration
// is provided the healthchecker is updated and checks are scheduled at the
// new interval. Notifications are generated and sent via the notification
// channel whenever a state transition occurs. Run will terminate once a
// value is received on the quit channel.
func (hc *Checker) Run(start <-chan time.Time) {
	// Wait for initial configuration.
	select {
	case config := <-hc.update:
		hc.updateConfig(&config)
	case <-hc.quit:
		return
	}

	// Wait for a tick to avoid a thundering herd at startup and to
	// stagger healthchecks that have the same interval.
	if start != nil {
		<-start
	}
	log.Infof("Starting healthchecker for %v", hc.Id)

	ticker := time.NewTicker(hc.Interval)
	hc.healthcheck()
	for {
		select {
		case <-hc.quit:
			ticker.Stop()
			log.Infof("Stopping healthchecker for %v", hc.Id)
			return

		case config := <-hc.update:
			if config.Interval > 0 && hc.Interval != config.Interval {
				ticker.Stop()
				if start != nil {
					<-start
				}
				ticker = time.NewTicker(config.Interval)
			}
			hc.updateConfig(&config)

		case <-ticker.C:
			hc.healthcheck()
		}
	}
}

// Stop notifies a running healthcheck that it should quit.
func (hc *Checker) Stop() {
	select {
	case hc.quit <- true:
	default:
	}
}

// SetDryrun enables or disables dryrun mode for a healthcheck.
func (hc *Checker) SetDryrun(dryrun bool) {
	hc.dryrun = dryrun
}

// Update queues a healthcheck configuration update for processing.
func (hc *Checker) Update(config *CheckerConfig) {
	select {
	case hc.update <- *config:
	default:
		log.Warningf("Unable to update %v, last two update still queued", hc.Id)
	}
}
