package main

import (
	"flag"
	"math/rand"
	"strings"
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
	dpvsServiceListInterval := flag.Duration("dpvs-service-list-interval",
		types.DefaultAppConf.DpvsServiceListInterval,
		"Time interval to refetch dpvs services.")
	metricServerAddr := flag.String("metric-server-addr",
		types.DefaultAppConf.MetricServerAddr,
		"Server address for exporting healthcheck state and statistics.")
	metricServerUri := flag.String("metric-server-uri",
		types.DefaultAppConf.MetricServerUri,
		"Http URI for exporting healthcheck state and statistics.")
	metricNotifyChanSize := flag.Uint("metic-notify-channel-size",
		types.DefaultAppConf.MetricNotifyChanSize,
		"Channel size for metric data sent from checkers to metric server.")

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
	if !strings.HasPrefix(appConf.DpvsAgentAddr, "http") {
		appConf.DpvsAgentAddr += "http://"
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
	if metricNotifyChanSize != nil {
		appConf.MetricNotifyChanSize = *metricNotifyChanSize
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
