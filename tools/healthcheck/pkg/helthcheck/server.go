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
	"fmt"
	"math/rand"
	"time"

	log "github.com/golang/glog"
	"github.com/iqiyi/dpvs/tools/healthcheck/pkg/lb"
	"github.com/iqiyi/dpvs/tools/healthcheck/pkg/utils"
)

// Server contains the data needed to run a healthcheck server.
type Server struct {
	config *ServerConfig
	comm   lb.Comm

	healthchecks map[Id]*Checker
	configs      chan map[Id]*CheckerConfig
	notify       chan *Notification

	quit chan bool
}

// NewServer returns an initialised healthcheck server.
func NewServer(cfg *ServerConfig) *Server {
	rand.Seed(time.Now().UnixNano())

	if cfg == nil {
		defaultCfg := DefaultServerConfig()
		cfg = &defaultCfg
	}

	var comm lb.Comm
	switch cfg.LbIfaceType {
	case "dpvs-agent":
		comm = lb.NewDpvsAgentComm(cfg.LbIfaceAddr)
	default:
		panic(fmt.Sprintf("lb_iface_type %q not supported", cfg.LbIfaceType))
	}

	return &Server{
		config: cfg,
		comm:   comm,

		healthchecks: make(map[Id]*Checker),
		notify:       make(chan *Notification, cfg.NotifyChannelSize),
		configs:      make(chan map[Id]*CheckerConfig),

		quit: make(chan bool, 1),
	}
}

func (s *Server) NewChecker(typ lb.Checker, proto utils.IPProto) CheckMethod {
	// TODO: support user specified Send/Receive data for TCP/UDP checker
	var checker CheckMethod
	switch typ {
	case lb.CheckerTCP:
		checker = NewTCPChecker("", "", 0)
	case lb.CheckerUDP:
		checker = NewUDPChecker("", "", 0)
	case lb.CheckerPING:
		checker = NewPingChecker()
	case lb.CheckerUDPPing:
		checker = NewUDPPingChecker("", "", 0)
	case lb.CheckerNone:
		if s.config.LbAutoMethod {
			switch proto {
			case utils.IPProtoTCP:
				checker = NewTCPChecker("", "", 0)
			case utils.IPProtoUDP:
				checker = NewUDPPingChecker("", "", 0)
			}
		}
	}
	return checker
}

// getHealthchecks attempts to get the current healthcheck configurations from DPVS
func (s *Server) getHealthchecks() (*Checkers, error) {
	vss, err := s.comm.ListVirtualServices()
	if err != nil {
		return nil, err
	}
	results := &Checkers{Configs: make(map[Id]*CheckerConfig)}
	for _, vs := range vss {
		for _, rs := range vs.RSs {
			target := &Target{rs.IP, rs.Port, vs.Protocol}
			id := NewId(vs.Id, target)
			checker := s.NewChecker(vs.Checker, vs.Protocol)
			if checker == nil {
				log.Info("Skip checking vs %v with %v", vs.Id, vs.Checker)
				continue
			}
			weight := rs.Weight
			state := StateUnknown
			if weight > 0 && rs.Inhibited == false {
				state = StateHealthy
			} else if weight == 0 && rs.Inhibited == true {
				state = StateUnhealthy
			}
			// TODO: allow users to specify check interval, timeout and retry
			config := NewCheckerConfig(id, checker,
				target, state, weight,
				DefaultCheckConfig.Interval,
				DefaultCheckConfig.Timeout,
				DefaultCheckConfig.Retry)
			results.Configs[*id] = config
		}
	}
	return results, nil
}

// updater attempts to fetch healthcheck configurations at regular intervals.
// When configurations are successfully retrieved they are provided to the
// manager via the configs channel.
func (s *Server) updater() {
	for {
		log.Info("Getting healthchecks from DPVS ...")
		checkers, err := s.getHealthchecks()
		if err != nil {
			log.Errorf("Getting healthchecks failed: %v, retry later", err)
			time.Sleep(5 * time.Second)
		} else if checkers != nil {
			log.Infof("DPVS returned %d healthcheck(s)", len(checkers.Configs))
			s.configs <- checkers.Configs
			time.Sleep(s.config.FetchInterval)
		} else { // It should not happen.
			log.Warning("No healthcheck returned from DPVS")
			time.Sleep(s.config.FetchInterval)
		}
	}
}

// notifier batches healthcheck notifications and sends them to DPVS.
func (s *Server) notifier() {
	// TODO: support more concurrency and rate limit
	for {
		select {
		case notification := <-s.notify:
			log.Infof("Sending notification >>> %v", notification)
			//fmt.Println("Sending notification >>>", notification)
			inhibited := false
			if notification.Status.State == StateUnhealthy {
				inhibited = true
			}
			vs := &lb.VirtualService{
				Id:       notification.Id.Vs(),
				Protocol: notification.Target.Proto,
				RSs: []lb.RealServer{{
					IP:        notification.Target.IP,
					Port:      notification.Target.Port,
					Weight:    notification.Status.Weight,
					Inhibited: inhibited,
				}},
			}

			if err := s.comm.UpdateByChecker([]lb.VirtualService{*vs}); err != nil {
				log.Warningf("Failed to Update %v healthy status to %v(weight: %d): %v",
					notification.Id, notification.State, notification.Status.Weight, err)
			}
		}
	}
}

// manager is responsible for controlling the healthchecks that are currently
// running. When healthcheck configurations become available, the manager will
// stop and remove deleted healthchecks, spawn new healthchecks and provide
// the current configurations to each of the running healthchecks.
func (s *Server) manager() {
	notifyTicker := time.NewTicker(s.config.NotifyInterval)
	var configs map[Id]*CheckerConfig
	for {
		select {
		case configs = <-s.configs:

			// Remove healthchecks that have been deleted.
			for id, hc := range s.healthchecks {
				if configs[id] == nil {
					hc.Stop()
					delete(s.healthchecks, id)
				}
			}

			// Spawn new healthchecks.
			for id, conf := range configs {
				if s.healthchecks[id] == nil {
					hc := NewChecker(s.notify, conf.State, conf.Weight)
					hc.SetDryrun(s.config.DryRun)
					s.healthchecks[id] = hc
					checkTicker := time.NewTicker(time.Duration((1 + rand.Intn(
						int(DefaultCheckConfig.Interval.Milliseconds())))) * time.Millisecond)
					go hc.Run(checkTicker.C)
				}
			}

			// Update configurations.
			for id, hc := range s.healthchecks {
				hc.Update(configs[id])
			}

		case <-notifyTicker.C:
			log.Infof("Total checkers: %d", len(s.healthchecks))
			// Send notifications when status changed.
			for id, hc := range s.healthchecks {
				notification := hc.Notification()
				if configs[id].State != notification.State {
					// FIXME: Don't resend the notification after a successful one.
					hc.notify <- notification
				}
			}
		}
	}
}

// Run runs a healthcheck server.
func (s *Server) Run() {
	log.Infof("Starting healthcheck server (%v) ...", s.config)
	go s.updater()
	go s.notifier()
	go s.manager()

	<-s.quit
}

// Shutdown notifies a healthcheck server to shutdown.
func (s *Server) Shutdown() {
	log.Info("Closing healthcheck server ...")
	select {
	case s.quit <- true:
	default:
	}
}
