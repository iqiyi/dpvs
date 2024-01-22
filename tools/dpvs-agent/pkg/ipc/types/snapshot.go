package types

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/dpvs-agent/models"
	"github.com/hashicorp/go-hclog"
)

type ServiceSnapshot struct {
	Service *models.VirtualServerSpecExpand
	lock    *sync.RWMutex
}

type NodeSnapshot struct {
	NodeSpec *models.DpvsNodeSpec
	Snapshot map[string]*ServiceSnapshot
}

func (snap *ServiceSnapshot) Lock() {
	snap.lock.Lock()
}

func (snap *ServiceSnapshot) Unlock() {
	snap.lock.Unlock()
}

func (snap *ServiceSnapshot) RLock() {
	snap.lock.RLock()
}

func (snap *ServiceSnapshot) RUnlock() {
	snap.lock.RUnlock()
}

func (node *NodeSnapshot) ServiceRLock(id string) bool {
	snap, exist := node.Snapshot[strings.ToLower(id)]
	if exist {
		snap.RLock()
	}

	return exist
}

func (node *NodeSnapshot) ServiceRUnlock(id string) {
	if snap, exist := node.Snapshot[strings.ToLower(id)]; exist {
		snap.RUnlock()
	}
}

func (node *NodeSnapshot) ServiceLock(id string) bool {
	snap, exist := node.Snapshot[strings.ToLower(id)]
	if exist {
		snap.Lock()
	}

	return exist
}

func (node *NodeSnapshot) ServiceUnlock(id string) {
	if snap, exist := node.Snapshot[strings.ToLower(id)]; exist {
		snap.Unlock()
	}
}

func (node *NodeSnapshot) ServiceVersionUpdate(id string, logger hclog.Logger) {
	snapshot := node.Snapshot
	logger.Info("Update server version begin.", "id", id, "services snapshot", snapshot)
	if _, exist := snapshot[strings.ToLower(id)]; exist {
		snapshot[strings.ToLower(id)].Service.Version = strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
		return
	}
	logger.Error("Update service version failed. Service not Exist.", "id", id)
}

func (node *NodeSnapshot) SnapshotGet(id string) *ServiceSnapshot {
	if snap, exist := node.Snapshot[strings.ToLower(id)]; exist {
		return snap
	}
	return nil
}

func (node *NodeSnapshot) ServiceGet(id string) *models.VirtualServerSpecExpand {
	if snap, exist := node.Snapshot[strings.ToLower(id)]; exist {
		return snap.Service
	}
	return nil
}

func (node *NodeSnapshot) ServiceDel(id string) {
	if _, exist := node.Snapshot[strings.ToLower(id)]; exist {
		delete(node.Snapshot, strings.ToLower(id))
	}
}

func (node *NodeSnapshot) ServiceVersion(id string) string {
	if _, exist := node.Snapshot[strings.ToLower(id)]; exist {
		return node.Snapshot[strings.ToLower(id)].Service.Version
	}
	return strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
}

func (node *NodeSnapshot) ServiceAdd(vs *VirtualServerSpec) {
	version := node.ServiceVersion(vs.ID())

	svc := vs.GetModel()
	svc.Version = version

	node.Snapshot[strings.ToLower(vs.ID())] = &ServiceSnapshot{Service: svc, lock: new(sync.RWMutex)}
}

func (node *NodeSnapshot) ServiceUpsert(spec *models.VirtualServerSpecExpand) {
	svc := (*VirtualServerSpecExpandModel)(spec)

	version := node.ServiceVersion(svc.ID())

	if _, exist := node.Snapshot[strings.ToLower(svc.ID())]; !exist {
		node.Snapshot[strings.ToLower(svc.ID())] = &ServiceSnapshot{Service: spec, lock: new(sync.RWMutex)}
	}

	node.Snapshot[strings.ToLower(svc.ID())].Service.Version = version
}

func (node *NodeSnapshot) GetModels(logger hclog.Logger) *models.VirtualServerList {
	services := &models.VirtualServerList{Items: make([]*models.VirtualServerSpecExpand, len(node.Snapshot))}
	i := 0
	for _, snap := range node.Snapshot {
		services.Items[i] = snap.Service
		i++
	}
	return services
}

type VirtualServerSpecExpandModel models.VirtualServerSpecExpand

func (spec *VirtualServerSpecExpandModel) ID() string {
	proto := "tcp"
	if spec.Proto == unix.IPPROTO_UDP {
		proto = "udp"
	}
	return fmt.Sprintf("%s-%d-%s", spec.Addr, spec.Port, proto)
}

func (node *NodeSnapshot) LoadFrom(cacheFile string, logger hclog.Logger) error {
	content, err := os.ReadFile(cacheFile)
	if err != nil {
		logger.Error("Read dpvs service cache file failed.", "Error", err.Error())
		return err
	}
	var nodeSnapshot models.NodeServiceSnapshot
	if err := json.Unmarshal(content, &nodeSnapshot); err != nil {
		logger.Error("Deserialization Failed.", "content", content, "Error", err.Error())
		return err
	}

	node.NodeSpec = nodeSnapshot.NodeSpec
	for _, svcModel := range nodeSnapshot.Services.Items {
		svc := (*VirtualServerSpecExpandModel)(svcModel)
		node.Snapshot[strings.ToLower(svc.ID())].Service = svcModel
	}

	return nil
}

func (node *NodeSnapshot) DumpTo(cacheFile string, logger hclog.Logger) error {
	nodeSnapshot := &models.NodeServiceSnapshot{
		NodeSpec: node.NodeSpec,
		Services: node.GetModels(logger),
	}

	content, err := json.Marshal(nodeSnapshot)
	if err != nil {
		logger.Error(err.Error())
		return err
	}

	nowStr := time.Now().Format("2006-01-02 15:04:05")
	nowStr = strings.ReplaceAll(nowStr, " ", "+")
	bakName := cacheFile + nowStr
	if err := os.Rename(cacheFile, bakName); err != nil {
		logger.Error(err.Error())
		return err
	}

	if err := os.WriteFile(cacheFile, []byte(content), 0644); err != nil {
		logger.Error(err.Error())
		return err
	}

	return nil
}
