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

/* Log Level Convention (glog.V().Info):

| level |   Type    | importance | frequency |
|-------|-----------|------------|-----------|
|   0   |   Fatal   |     \      |     \     |
|   1   |   Error   |     \      |     \     |
|   2   |  Warning  |     \      |     \     |
|   3   |   Info    |     \      |     \     |
|   4   |   Debug   |    high    |    low    |
|   5   |   Debug   |   medium   |    low    |
|   6   |   Debug   |    high    |    high   |
|   7   |   Debug   |   medium   |    high   |
|   8   |   Debug   |    low     |    low    |
|   9   |   Debug   |    low     |    high   |
*/

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
	metricServerConfUri := flag.String("conf-uri",
		types.DefaultAppConf.MetricServerConfUri,
		"Http URI for showing current effective configs.")
	metricServerConfCheckUri := flag.String("conf-check-uri",
		types.DefaultAppConf.MetricServerConfCheckUri,
		"Http URI for checking if config file valid.")
	metricNotifyChanSize := flag.Uint("metic-notify-channel-size",
		types.DefaultAppConf.MetricNotifyChanSize,
		"Channel size for metric data sent from checkers to metric server.")
	metricDelay := flag.Duration("metric-delay",
		types.DefaultAppConf.MetricDelay,
		"Max delayed time to send changed metric to metric server.")

	flag.Parse()

	if debug != nil {
		appConf.Debug = *debug
	}
	if checkerNotifyChanSize != nil && *checkerNotifyChanSize > 0 {
		appConf.CheckerNotifyChanSize = *checkerNotifyChanSize
	}
	if vsNotifyChanSize != nil && *vsNotifyChanSize > 0 {
		appConf.VSNotifyChanSize = *vsNotifyChanSize
	}
	if hcCfgFile != nil && utils.IsFile(*hcCfgFile) {
		appConf.HcCfgFile = *hcCfgFile
	}
	if hcCfgReloadInterval != nil && *hcCfgReloadInterval > 0 {
		appConf.HcCfgReloadInterval = *hcCfgReloadInterval
	}
	if dpvsAgentAddr != nil && len(*dpvsAgentAddr) > 0 {
		appConf.DpvsAgentAddr = *dpvsAgentAddr
	}
	if !strings.HasPrefix(appConf.DpvsAgentAddr, "http") {
		appConf.DpvsAgentAddr = "http://" + appConf.DpvsAgentAddr
	}
	if dpvsServiceListInterval != nil && *dpvsServiceListInterval > 0 {
		appConf.DpvsServiceListInterval = *dpvsServiceListInterval
	}
	if metricServerAddr != nil && len(*metricServerAddr) > 0 {
		appConf.MetricServerAddr = *metricServerAddr
	}
	if metricServerUri != nil && len(*metricServerUri) > 0 {
		appConf.MetricServerUri = *metricServerUri
	}
	if metricServerConfUri != nil && len(*metricServerConfUri) > 0 {
		appConf.MetricServerConfUri = *metricServerConfUri
	}
	if metricServerConfCheckUri != nil && len(*metricServerConfCheckUri) > 0 {
		appConf.MetricServerConfCheckUri = *metricServerConfCheckUri
	}
	if metricNotifyChanSize != nil && *metricNotifyChanSize > 0 {
		appConf.MetricNotifyChanSize = *metricNotifyChanSize
	}
	if metricDelay != nil && *metricDelay > 0 {
		appConf.MetricDelay = *metricDelay
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
	manager.SetAppManager(m)

	utils.ShutdownHandler(m)
	m.Run()
}
