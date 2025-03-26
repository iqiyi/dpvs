package manager

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/comm"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

const VAStartDelayMax = 3 * time.Second

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

func (t *cfgFileReloader) Job(ctx context.Context) {
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
	m        *Manager // the Manager instance controlling the Task
}

func NewSvcLister(m *Manager) *svcLister {
	return &svcLister{
		name:     "service-lister",
		interval: m.appConf.DpvsServiceListInterval,
		server:   m.appConf.DpvsAgentAddr,
		m:        m,
	}
}

func (t *svcLister) Name() string {
	return t.name
}

func (t *svcLister) Interval() time.Duration {
	return t.interval
}

func (t *svcLister) Job(ctx context.Context) {
	var err error

	// get the latest service list
	dsvcs, err := comm.GetServiceFromDPVS(t.server, ctx)
	if err != nil {
		glog.Warningf("Fail to get services from DPVS: %v.", err)
		return
	}
	glog.V(7).Infof("Succeed to get services from DPVS:\n%v", dsvcs)

	// remove staled VAs
	staled := make(map[VAID]bool)
	for vaid, _ := range t.m.vas {
		staled[vaid] = true
	}
	for _, svc := range dsvcs {
		vaid := VAID(svc.Addr.IP.String())
		if _, ok := staled[vaid]; ok {
			delete(staled, vaid)
		}
	}
	for vaid, _ := range staled {
		va := t.m.vas[vaid]
		delete(t.m.vas, vaid)
		va.Stop()
	}

	// add new or update existing VAs
	vsgroup := make(map[VAID][]comm.VirtualServer)
	for _, svc := range dsvcs {
		vaid := VAID(svc.Addr.IP.String())
		if _, ok := vsgroup[vaid]; !ok {
			vsgroup[vaid] = make([]comm.VirtualServer, 0, 2)
		}
		vsgroup[vaid] = append(vsgroup[vaid], svc)
	}
	for vaid, vss := range vsgroup {
		addr := vss[0].Addr.IP
		vaConf := t.m.conf.GetVAConf(vaid)
		va, ok := t.m.vas[vaid]
		if !ok {
			if vaConf.Disable {
				continue
			}
			va, err = NewVA(addr, vaConf, t.m)
			if err != nil {
				glog.Errorf("VA created failed for %s: %v", addr, err)
				continue
			}
			t.m.vas[vaid] = va
			t.m.wg.Add(1)
			delay := time.NewTicker(time.Duration(1+rand.Intn(int(
				VAStartDelayMax.Milliseconds()))) * time.Millisecond)
			go va.Run(t.m.wg, delay.C)
		} else {
			if vaConf.Disable {
				delete(t.m.vas, vaid)
				va.Stop()
				continue
			}
		}
		vaConfExt := &VAConfExt{
			VAConf: *vaConf,
			vss:    vss,
		}
		va.Update(vaConfExt)
	}
}

type metricServer struct {
	addr string
	uri  string

	notify chan Metric
	server *http.Server
}

func metricHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "%s\n\n", time.Now())
	fmt.Fprintf(w, "Thread Statistics:\n%s\n", AppThreadStatsDump())
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

func (s *metricServer) Run(ctx context.Context) {
	http.HandleFunc(s.uri, metricHandler)

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
	cancel          context.CancelFunc

	metricServer *metricServer

	wg       *sync.WaitGroup
	quit     chan bool
	stopping bool
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
	m.cancel = cancel

	m.wg.Add(1)
	go utils.RunTask(m.cfgFileReloader, ctx, m.wg, nil)
	m.wg.Add(1)
	go utils.RunTask(m.svcLister, ctx, m.wg, nil)

	ctx2, cancel2 := context.WithCancel(context.Background())
	go m.metricServer.Run(ctx2)

	<-m.quit
	m.wg.Wait()

	// Metric server MUST stop after everything is done.
	cancel2()
	m.metricServer.Shutdown(nil)

	glog.Info("Manager server closed successfully.")
}

func (m *Manager) Shutdown() {
	if m.stopping {
		return
	}
	m.stopping = true

	glog.Info("Closing manager server ...")
	select {
	case m.quit <- true:
		// Stop tasks: cfgFileReloader, svcLister.
		m.cancel()
		// Stop all VAs, VSs, and Checkers.
		for _, va := range m.vas {
			va.Stop()
		}
	default:
	}
}
