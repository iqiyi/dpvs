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
	// dpvs-agent http uri for updating backend's health state and weight in dpvs
	DpvsWeightStateUri string
	// dpvs-agent http uri for listing all services
	DpvsServiceListUri string
	// time interval to refetch dpvs services
	DpvsServiceListInterval time.Duration
	// metric server address
	MetricServerAddr string
	// metric server http uri for exporting healthcheck statistics
	MetricServerUri string
	// channel size for metric data sent from va/vs/checker to metric server
	MetricNotifyChanSize uint
}

var DefaultAppConf = AppConf{
	Debug:                   false,
	CheckerNotifyChanSize:   100,
	VSNotifyChanSize:        100,
	HcCfgFile:               "/etc/healthcheck.conf",
	HcCfgReloadInterval:     177 * time.Second,
	DpvsAgentAddr:           ":8082",
	DpvsWeightStateUri:      "",
	DpvsServiceListUri:      "",
	DpvsServiceListInterval: 15 * time.Second,
	MetricServerAddr:        ":6601",
	MetricServerUri:         "/metrics",
	MetricNotifyChanSize:    1000,
}
