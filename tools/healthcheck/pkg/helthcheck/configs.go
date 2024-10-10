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
	"time"
)

// ServerConfig specifies the configuration for a healthcheck server.
type ServerConfig struct {
	NotifyChannelSize uint
	NotifyInterval    time.Duration
	FetchInterval     time.Duration
	LbIfaceType       string
	LbIfaceAddr       string
	LbAutoMethod      bool
	DryRun            bool
	Debug             bool
}

func (cfg *ServerConfig) String() string {
	return fmt.Sprintf("notitfy-channel-size: %v, ", cfg.NotifyChannelSize) +
		fmt.Sprintf("notify-interval: %v, ", cfg.NotifyInterval) +
		fmt.Sprintf("fetch-interval: %v, ", cfg.FetchInterval) +
		fmt.Sprintf("lb-auto-method: %v, ", cfg.LbAutoMethod) +
		fmt.Sprintf("dryrun: %v, ", cfg.DryRun) +
		fmt.Sprintf("debug: %v", cfg.Debug)
}

var defaultServerConfig = ServerConfig{
	NotifyChannelSize: 1000,
	NotifyInterval:    15 * time.Second,
	FetchInterval:     15 * time.Second,
	LbIfaceType:       "dpvs-agent", // only type supported now
	LbIfaceAddr:       "localhost:53225",
	LbAutoMethod:      true,
	DryRun:            false,
	Debug:             false,
}

// DefaultServerConfig returns the default server configuration.
func DefaultServerConfig() ServerConfig {
	return defaultServerConfig
}

// CheckerConfig contains the configuration for a healthcheck.
type CheckerConfig struct {
	Id

	// Version denotes the virtual service version. It used to protect the vs from
	// incorrect weight updates by healthcheck when the vs's weight changed externally.
	Version uint64

	Target
	State
	Weight uint16
	CheckMethod

	Interval time.Duration
	Timeout  time.Duration
	Retry    uint
}

var DefaultCheckConfig CheckerConfig

// NewConfig returns an initialised Config.
func NewCheckerConfig(id *Id, version uint64, checker CheckMethod,
	target *Target, state State, weight uint16, interval,
	timeout time.Duration, retry uint) *CheckerConfig {
	config := CheckerConfig{
		Id:          *id,
		Version:     version,
		Target:      *target,
		State:       state,
		Weight:      weight,
		CheckMethod: checker,
		Interval:    interval,
		Timeout:     timeout,
		Retry:       retry,
	}
	if config.CheckMethod != nil {
		config.BindConfig(&config)
	}
	return &config
}
