package manager

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var (
	_ utils.Task = (*cfgFileReloader)(nil)
	_ utils.Task = (*svcLister)(nil)
)

type cfgFileReloader struct {
	name     string
	interval time.Duration
	filename string
}

func NewCfgFileReloader(conf *types.AppConf) *cfgFileReloader {
	return &cfgFileReloader{
		name:     "config-file-reloader",
		interval: conf.HcCfgReloadInterval,
		filename: conf.HcCfgFile,
	}
}

func (t *cfgFileReloader) Name() string {
	return t.name
}

func (t *cfgFileReloader) Interval() time.Duration {
	return t.interval
}

func (t *cfgFileReloader) Job() {
	// TODO
	glog.Info("This is config-file-reloader Job.")
}

type svcLister struct {
	name     string
	interval time.Duration
	server   string
	uri      string
}

func NewSvcLister(conf *types.AppConf) *svcLister {
	return &svcLister{
		name:     "service-lister",
		interval: conf.DpvsServiceListInterval,
		server:   conf.DpvsAgentAddr,
		uri:      conf.DpvsServiceListUri,
	}
}

func (t *svcLister) Name() string {
	return t.name
}

func (t *svcLister) Interval() time.Duration {
	return t.interval
}

func (t *svcLister) Job() {
	// TODO
	glog.Info("This is service-lister Job!")
}

type metricServer struct {
	addr string
	uri  string

	server *http.Server
}

func metricHandler(w http.ResponseWriter, r *http.Request) {
	// TODO
	fmt.Fprintf(w, "This is Metric Server Handler!")

}

func NewMetricServer(conf *types.AppConf) *metricServer {
	httpSvr := http.Server{
		Addr:    conf.MetricServerAddr,
		Handler: http.DefaultServeMux,
	}

	svr := metricServer{
		addr:   conf.MetricServerAddr,
		uri:    conf.MetricServerUri,
		server: &httpSvr,
	}

	return &svr
}

func (s *metricServer) Run() {
	http.HandleFunc(s.uri, metricHandler)

	glog.Infof("Starting metric server listening on %s ...", s.addr)
	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		glog.Errorf("Metric server started failed: %v", err)
	}
	glog.Info("Metric server finished.")
}

func (s *metricServer) Shutdown(wg *sync.WaitGroup) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() {
		cancel()
		if wg != nil {
			wg.Done()
		}
	}()

	if err := s.server.Shutdown(ctx); err != nil {
		glog.Warningf("Fail to shutdown metric server: %v.", err)
	} else {
		glog.Info("Metric server shutdown succeeded.")
	}
}

type Manager struct {
	appConf types.AppConf
	vas     map[VAID]*VirtualAddress

	cfgFileReloader *cfgFileReloader
	svcLister       *svcLister
	metricServer    *metricServer

	wg   *sync.WaitGroup
	quit chan bool
}

func NewManager(conf *types.AppConf) *Manager {
	m := Manager{}
	if conf != nil {
		m.appConf = *conf
	} else {
		m.appConf = types.DefaultAppConf
	}

	m.vas = make(map[VAID]*VirtualAddress)

	m.cfgFileReloader = NewCfgFileReloader(conf)
	m.svcLister = NewSvcLister(conf)
	m.metricServer = NewMetricServer(conf)

	m.wg = &sync.WaitGroup{}
	m.quit = make(chan bool, 1)
	return &m
}

func (m *Manager) Run() {
	ctx, cancel := context.WithCancel(context.Background())

	m.wg.Add(1)
	go utils.RunTask(m.cfgFileReloader, ctx, m.wg, nil)
	m.wg.Add(1)
	go utils.RunTask(m.svcLister, ctx, m.wg, nil)
	m.wg.Add(1)
	go m.metricServer.Run()

	<-m.quit
	cancel()
	m.metricServer.Shutdown(m.wg)

	m.wg.Wait()
	glog.Info("Manager server closed successfully.")
}

func (m *Manager) Shutdown() {
	glog.Info("Closing manager server ...")
	select {
	case m.quit <- true:
	default:
	}
}
