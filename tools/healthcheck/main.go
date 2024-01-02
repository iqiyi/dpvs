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

package main

import (
	"flag"
	"time"

	"github.com/golang/glog"
	gops "github.com/google/gops/agent"

	hc "github.com/iqiyi/dpvs/tools/healthcheck/pkg/helthcheck"
	"github.com/iqiyi/dpvs/tools/healthcheck/pkg/server"
)

var (
	notifyChannelSize = flag.Uint("channel_size",
		hc.DefaultServerConfig().NotifyChannelSize,
		"The size of the notification channel")

	notifyInterval = flag.Duration("notify_interval",
		hc.DefaultServerConfig().NotifyInterval,
		"The time between notifications")

	fetchInterval = flag.Duration("fetch_interval",
		hc.DefaultServerConfig().FetchInterval,
		"The time between healthcheck config fetches from DPVS")

	checkInterval = flag.Duration("check_interval",
		3*time.Second,
		"The default time interval to run a check")

	checkTimeout = flag.Duration("check_timeout",
		1*time.Second,
		"The default timeout before a check fails")

	checkRetry = flag.Uint("check_retry",
		1,
		"The default retry count when a check fails")

	dryRun = flag.Bool("dry_run",
		hc.DefaultServerConfig().DryRun,
		"Skips actual check and always return healthy as result")

	debug = flag.Bool("debug",
		hc.DefaultServerConfig().Debug,
		"Enable gops for debug")

	lbIfaceType = flag.String("lb_iface_type",
		hc.DefaultServerConfig().LbIfaceType,
		"Type of load-balancer interface via which to get check objects and update results")

	lbIfaceAddr = flag.String("lb_iface_addr",
		hc.DefaultServerConfig().LbIfaceAddr,
		"Address of load-balancer interface via which to get check objects and update results")

	lbAutoMethod = flag.Bool("lb_auto_method",
		hc.DefaultServerConfig().LbAutoMethod,
		"Use default check method for the backends if not specified")
)

func main() {
	flag.Parse()
	defer glog.Flush()

	cfg := hc.DefaultServerConfig()
	cfg.NotifyChannelSize = *notifyChannelSize
	cfg.NotifyInterval = *notifyInterval
	cfg.FetchInterval = *fetchInterval
	cfg.LbIfaceType = *lbIfaceType
	cfg.LbIfaceAddr = *lbIfaceAddr
	cfg.LbAutoMethod = *lbAutoMethod
	cfg.DryRun = *dryRun
	cfg.Debug = *debug

	hc.DefaultCheckConfig.Interval = *checkInterval
	hc.DefaultCheckConfig.Timeout = *checkTimeout
	hc.DefaultCheckConfig.Retry = *checkRetry

	if cfg.Debug {
		if err := gops.Listen(gops.Options{}); err != nil {
			glog.Warningf("Unable to start gops: %v", err)
		} else {
			defer gops.Close()
		}
	}

	hcs := hc.NewServer(&cfg)
	server.ShutdownHandler(hcs)
	hcs.Run()
}
