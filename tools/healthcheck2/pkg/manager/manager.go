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

package manager

import (
	"context"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/checker"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/comm"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
	"gopkg.in/yaml.v2"
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
	raw      *ConfFileLayout // conf file content after merged default
	m        *Manager        // the Manager instance controlling the Task
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
	if err != nil || conf == nil {
		glog.Errorf("Fail to load config file %s: %v.", t.filename, err)
		return
	}
	t.m.conf = conf
	glog.V(6).Infof("Config file reloaded!")
}

func (t *cfgFileReloader) SetRaw(fc *ConfFileLayout) {
	t.raw = fc
}

func (t *cfgFileReloader) GetRaw() *ConfFileLayout {
	return t.raw
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
				glog.Infof("VA %s is getting disabled", vaid)
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
	addr         string
	uri          string
	uriConf      string
	uriConfCheck string

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

func metricConfHandler(w http.ResponseWriter, r *http.Request) {
	m := GetAppManager()
	if m.cfgFileReloader == nil {
		fmt.Fprintf(w, "Error: Config file reloader not functioning!")
		return
	}

	data, err := yaml.Marshal(m.cfgFileReloader.GetRaw())
	if err != nil {
		fmt.Fprintf(w, "Yaml marshal failed: %v.", err)
		return
	}
	fmt.Fprintf(w, "# Check Method Annotations: %s\n", strings.Join(checker.DumpMethods(), ", "))
	fmt.Fprintf(w, "# VA DownPolicy Annotations: %s\n\n", strings.Join(DumpVAPolicies(), ", "))
	fmt.Fprintf(w, string(data))
}

func metricConfCheckHandler(w http.ResponseWriter, r *http.Request) {
	m := GetAppManager()
	if m.cfgFileReloader == nil || len(m.cfgFileReloader.filename) == 0 {
		fmt.Fprintf(w, "Config File Default: VALID")
		return
	}
	filename := m.cfgFileReloader.filename

	fmt.Fprintf(w, "Config File %s: ", filename)
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(w, "INVALID (File Read Error: %v)", err)
		return
	}

	defer func() {
		fmt.Fprintf(w, "\n\n\nRaw Configs from %s:\n", filename)
		fmt.Fprintf(w, "# Check Method Annotations: %s\n", strings.Join(checker.DumpMethods(), ", "))
		fmt.Fprintf(w, "# VA DownPolicy Annotations: %s\n", strings.Join(DumpVAPolicies(), ", "))
		w.Write(data)
	}()

	var fileConf ConfFileLayout
	err = yaml.Unmarshal(data, &fileConf)
	if err != nil {
		fmt.Fprintf(w, "INVALID (Yaml Format Error: %v)", err)
		return
	}

	fileConf.Merge(&confDefault)
	err = fileConf.Validate()
	if err != nil {
		fmt.Fprintf(w, "INVALID (Validation Error: %v)", err)
		return
	}

	fmt.Fprintf(w, "VALID")
}

func NewMetricServer(conf *types.AppConf) *metricServer {
	httpSvr := http.Server{
		Addr:    conf.MetricServerAddr,
		Handler: http.DefaultServeMux,
	}

	svr := metricServer{
		addr:         conf.MetricServerAddr,
		uri:          conf.MetricServerUri,
		uriConf:      conf.MetricServerConfUri,
		uriConfCheck: conf.MetricServerConfCheckUri,
		server:       &httpSvr,
	}
	svr.notify = make(chan Metric, conf.MetricNotifyChanSize)

	return &svr
}

func (s *metricServer) Run(ctx context.Context) {
	http.HandleFunc(s.uri, metricHandler)
	http.HandleFunc(s.uriConf, metricConfHandler)
	http.HandleFunc(s.uriConfCheck, metricConfCheckHandler)

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

	// wait until m.conf loaded
	glog.Infof("Awaiting manager conf to be populated ...")
	for i := 0; i < 300 && m.conf == nil; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if m.conf == nil {
		glog.Errorf("Manager conf populating failed!")
		return
	}

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

var appManager *Manager

func SetAppManager(m *Manager) {
	appManager = m
}

func GetAppManager() *Manager {
	return appManager
}
