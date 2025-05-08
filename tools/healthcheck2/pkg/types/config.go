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

package types

import "time"

type AppConf struct {
	// enable debug mode or not
	Debug bool
	// channel size for checker state change notice and resync
	CheckerNotifyChanSize uint
	// channel size for virtual service state change notice and resync
	VSNotifyChanSize uint
	// healthcheck config file path
	HcCfgFile string
	// time interval to reload healthcheck config file
	HcCfgReloadInterval time.Duration
	// dpvs-agent server address
	DpvsAgentAddr string
	// time interval to refetch dpvs services
	DpvsServiceListInterval time.Duration
	// metric server address
	MetricServerAddr string
	// metric server http uri for exporting healthcheck statistics
	MetricServerUri string
	// metric server http uri for showing current effective configs
	MetricServerConfUri string
	// metric server http uri for checking if config file valid
	MetricServerConfCheckUri string
	// channel size for metric data sent from va/vs/checker to metric server
	MetricNotifyChanSize uint
	// max delayed time to send changed metric to metric server
	MetricDelay time.Duration
}

var DefaultAppConf = AppConf{
	Debug:                    false,
	CheckerNotifyChanSize:    100,
	VSNotifyChanSize:         100,
	HcCfgFile:                "/etc/healthcheck.conf",
	HcCfgReloadInterval:      177 * time.Second,
	DpvsAgentAddr:            ":8082",
	DpvsServiceListInterval:  15 * time.Second,
	MetricServerAddr:         ":6601",
	MetricServerUri:          "/metrics",
	MetricServerConfUri:      "/conf",
	MetricServerConfCheckUri: "/conf/check",
	MetricNotifyChanSize:     1000,
	MetricDelay:              2 * time.Second,
}
