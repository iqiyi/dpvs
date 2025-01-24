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
	m        *Manager // the Manager instance controlling the Task
}

func NewCfgFileReloader(m *Manager) *cfgFileReloader {
	return &cfgFileReloader{
		name:     "config-file-reloader",
		interval: m.appConf.HcCfgReloadInterval,
		filename: m.appConf.HcCfgFile,
		m:        m,
	}
}

func (t *cfgFileReloader) Name() string {
	return t.name
}

func (t *cfgFileReloader) Interval() time.Duration {
	return t.interval
}

func (t *cfgFileReloader) Job() {
	conf, err := LoadFileConf(t.filename)
	if err != nil {
		glog.Errorf("Fail to load config file %s: %v.", t.filename, err)
	}
	t.m.conf = conf
}

type svcLister struct {
	name     string
	interval time.Duration
	server   string
	uri      string
	m        *Manager // the Manager instance controlling the Task
}

func NewSvcLister(m *Manager) *svcLister {
	return &svcLister{
		name:     "service-lister",
		interval: m.appConf.DpvsServiceListInterval,
		server:   m.appConf.DpvsAgentAddr,
		uri:      m.appConf.DpvsServiceListUri,
		m:        m,
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

	notify chan Metric
	server *http.Server
}

func metricHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "%s\n", time.Now())
	if _, err := fmt.Fprintf(w, "%s", metricDB); err != nil {
		glog.Warningf("metric handler failed: %v", err)
	}
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
	svr.notify = make(chan Metric, conf.MetricNotifyChanSize)

	return &svr
}

func (s *metricServer) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	http.HandleFunc(s.uri, metricHandler)

	wg.Add(1)
	go func() {
		glog.Infof("Starting metric http server listening on %s ...", s.addr)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			glog.Errorf("Metric http server started failed: %v", err)
		}
		glog.Info("Metric http server finished.")
	}()

	for {
		select {
		case <-ctx.Done():
			glog.Info("Metric collector finished.")
			return
		case m := <-s.notify:
			if err := metricDB.Update(&m); err != nil {
				glog.Warningf("MetricDB update failed: %v.", err)
			}
		default:
		}
	}
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
	conf    *Conf

	cfgFileReloader *cfgFileReloader
	svcLister       *svcLister
	metricServer    *metricServer

	wg   *sync.WaitGroup
	quit chan bool
}

func NewManager(conf *types.AppConf) *Manager {
	m := &Manager{}
	if conf != nil {
		m.appConf = *conf
	} else {
		m.appConf = types.DefaultAppConf
	}

	m.vas = make(map[VAID]*VirtualAddress)

	m.cfgFileReloader = NewCfgFileReloader(m)
	m.svcLister = NewSvcLister(m)
	m.metricServer = NewMetricServer(conf)

	m.wg = &sync.WaitGroup{}
	m.quit = make(chan bool, 1)
	return m
}

func (m *Manager) Run() {
	ctx, cancel := context.WithCancel(context.Background())

	m.wg.Add(1)
	go utils.RunTask(m.cfgFileReloader, ctx, m.wg, nil)
	m.wg.Add(1)
	go utils.RunTask(m.svcLister, ctx, m.wg, nil)
	m.wg.Add(1)
	go m.metricServer.Run(ctx, m.wg)

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
