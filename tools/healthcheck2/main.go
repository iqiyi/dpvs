package main

import (
	"flag"
	"math/rand"
	"time"

	"github.com/golang/glog"
	gops "github.com/google/gops/agent"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/manager"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var appConf types.AppConf = types.DefaultAppConf

func init() {
	debug := flag.Bool("debug",
		types.DefaultAppConf.Debug,
		"Enable gops for debug.")
	checkerNotifyChanSize := flag.Uint("checker-notify-channel-size",
		types.DefaultAppConf.CheckerNotifyChanSize,
		"Channel size for checker state change notice and resync.")
	vsNotifyChanSize := flag.Uint("vs-notify-channel-size",
		types.DefaultAppConf.VSNotifyChanSize,
		"Channel size for virtual service state change notice and resync.")
	hcCfgFile := flag.String("config-file",
		types.DefaultAppConf.HcCfgFile,
		"File path of healthcheck config file.")
	hcCfgReloadInterval := flag.Duration("config-reload-interval",
		types.DefaultAppConf.HcCfgReloadInterval,
		"Time interval to reload healthcheck config file.")
	dpvsAgentAddr := flag.String("dpvs-agent-addr",
		types.DefaultAppConf.DpvsAgentAddr,
		"Server address of dpvs-agent.")
	dpvsWeightStateUri := flag.String("dpvs-weight-state-uri",
		types.DefaultAppConf.DpvsWeightStateUri,
		"Http URI of dpvs-agent for updating backend's health state and weight in dpvs.")
	dpvsServiceListUri := flag.String("dpvs-service-list-uri",
		types.DefaultAppConf.DpvsServiceListUri,
		"Http URI of dpvs-agent for listing all services.")
	dpvsServiceListInterval := flag.Duration("dpvs-service-list-interval",
		types.DefaultAppConf.DpvsServiceListInterval,
		"Time interval to refetch dpvs services.")
	metricServerAddr := flag.String("metric-server-addr",
		types.DefaultAppConf.MetricServerAddr,
		"Server address for exporting healthcheck state and statistics.")
	metricServerUri := flag.String("metric-server-uri",
		types.DefaultAppConf.MetricServerUri,
		"Http URI for exporting healthcheck state and statistics.")

	flag.Parse()

	if debug != nil {
		appConf.Debug = *debug
	}
	if checkerNotifyChanSize != nil {
		appConf.CheckerNotifyChanSize = *checkerNotifyChanSize
	}
	if vsNotifyChanSize != nil {
		appConf.VSNotifyChanSize = *vsNotifyChanSize
	}
	if hcCfgFile != nil {
		appConf.HcCfgFile = *hcCfgFile
	}
	if hcCfgReloadInterval != nil {
		appConf.HcCfgReloadInterval = *hcCfgReloadInterval
	}
	if dpvsAgentAddr != nil {
		appConf.DpvsAgentAddr = *dpvsAgentAddr
	}
	if dpvsWeightStateUri != nil {
		appConf.DpvsWeightStateUri = *dpvsWeightStateUri
	}
	if dpvsServiceListUri != nil {
		appConf.DpvsServiceListUri = *dpvsServiceListUri
	}
	if dpvsServiceListInterval != nil {
		appConf.DpvsServiceListInterval = *dpvsServiceListInterval
	}
	if metricServerAddr != nil {
		appConf.MetricServerAddr = *metricServerAddr
	}
	if metricServerUri != nil {
		appConf.MetricServerUri = *metricServerUri
	}
}

func main() {
	defer glog.Flush()

	if appConf.Debug {
		if err := gops.Listen(gops.Options{}); err != nil {
			glog.Warningf("Unable to start gops: %v", err)
		} else {
			defer gops.Close()
		}
	}

	rand.Seed(time.Now().UnixNano())

	m := manager.NewManager(&appConf)
	if m == nil {
		glog.Fatalf("NewManager failed!")
	}

	utils.ShutdownHandler(m)
	m.Run()
}
