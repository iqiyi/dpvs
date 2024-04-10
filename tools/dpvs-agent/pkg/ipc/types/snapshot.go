package types

import (
	"encoding/json"
	"fmt"
	"net"
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

func (node *NodeSnapshot) SnapshotID(id string) string {
	items := strings.Split(id, "-")
	if len(items) != 3 {
		return ""
	}

	proto := items[2]
	svcProto := "tcp"
	switch strings.ToLower(proto) {
	case "udp", "tcp":
		svcProto = strings.ToLower(proto)
	default:
		return ""
	}

	port, err := strconv.Atoi(items[1])
	if err != nil {
		return ""
	}
	vsPort := uint16(port)

	vip := net.ParseIP(items[0])
	if vip == nil {
		return ""
	}

	return fmt.Sprintf("%s-%d-%s", strings.ToLower(vip.String()), vsPort, svcProto)
}

func (node *NodeSnapshot) ServiceRLock(id string) bool {
	snapID := node.SnapshotID(id)

	snap, exist := node.Snapshot[strings.ToLower(snapID)]
	if exist {
		snap.RLock()
	}

	return exist
}

func (node *NodeSnapshot) ServiceRUnlock(id string) {
	snapID := node.SnapshotID(id)
	if snap, exist := node.Snapshot[strings.ToLower(snapID)]; exist {
		snap.RUnlock()
	}
}

func (node *NodeSnapshot) ServiceLock(id string) bool {
	snapID := node.SnapshotID(id)
	snap, exist := node.Snapshot[strings.ToLower(snapID)]
	if exist {
		snap.Lock()
	}

	return exist
}

func (node *NodeSnapshot) ServiceUnlock(id string) {
	snapID := node.SnapshotID(id)
	if snap, exist := node.Snapshot[strings.ToLower(snapID)]; exist {
		snap.Unlock()
	}
}

func (node *NodeSnapshot) ServiceVersionUpdate(id string, logger hclog.Logger) {
	snapID := node.SnapshotID(id)
	snapshot := node.Snapshot
	logger.Info("Update server version begin.", "id", id, "services snapshot", snapshot)
	if _, exist := snapshot[strings.ToLower(snapID)]; exist {
		expireVersion := snapshot[strings.ToLower(snapID)].Service.Version
		snapshot[strings.ToLower(snapID)].Service.Version = strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
		latestVersion := snapshot[strings.ToLower(snapID)].Service.Version

		logger.Info("Service version update done.", "expireVersion", expireVersion, "latest Version", latestVersion)
		return
	}
	logger.Error("Update service version failed. Service not Exist.", "id", id)
}

func (node *NodeSnapshot) SnapshotGet(id string) *ServiceSnapshot {
	snapID := node.SnapshotID(id)
	if snap, exist := node.Snapshot[strings.ToLower(snapID)]; exist {
		return snap
	}
	return nil
}

func (node *NodeSnapshot) ServiceGet(id string) *models.VirtualServerSpecExpand {
	snapID := node.SnapshotID(id)
	if snap, exist := node.Snapshot[strings.ToLower(snapID)]; exist {
		return snap.Service
	}
	return nil
}

func (node *NodeSnapshot) ServiceDel(id string) {
	snapID := node.SnapshotID(id)
	if _, exist := node.Snapshot[strings.ToLower(snapID)]; exist {
		delete(node.Snapshot, strings.ToLower(snapID))
	}
}

func (node *NodeSnapshot) ServiceVersion(id string) string {
	snapID := node.SnapshotID(id)
	if _, exist := node.Snapshot[strings.ToLower(snapID)]; exist {
		return node.Snapshot[strings.ToLower(snapID)].Service.Version
	}
	return strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
}

func (node *NodeSnapshot) ServiceAdd(vs *VirtualServerSpec) {
	version := node.ServiceVersion(vs.ID())

	svc := vs.GetModel()
	svc.Version = version
	if svc.RSs == nil {
		svc.RSs = &models.RealServerExpandList{Items: make([]*models.RealServerSpecExpand, 0)}
	}

	node.Snapshot[strings.ToLower(vs.ID())] = &ServiceSnapshot{Service: svc, lock: new(sync.RWMutex)}
}

func (node *NodeSnapshot) ServiceUpsert(spec *models.VirtualServerSpecExpand) {
	svc := (*VirtualServerSpecExpandModel)(spec)

	version := node.ServiceVersion(svc.ID())

	if _, exist := node.Snapshot[strings.ToLower(svc.ID())]; !exist {
		node.Snapshot[strings.ToLower(svc.ID())] = &ServiceSnapshot{Service: spec, lock: new(sync.RWMutex)}
	} else {
		node.Snapshot[strings.ToLower(svc.ID())].Service = spec
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

	logger.Info("services", services)
	return services
}

type RealServerSpecExpandModel models.RealServerSpecExpand

func (rs *RealServerSpecExpandModel) ID() string {
	return fmt.Sprintf("%s:%d", net.ParseIP(rs.Spec.IP), rs.Spec.Port)
}

type VirtualServerSpecExpandModel models.VirtualServerSpecExpand

func (spec *VirtualServerSpecExpandModel) ID() string {
	proto := "tcp"
	if spec.Proto == unix.IPPROTO_UDP {
		proto = "udp"
	}

	return fmt.Sprintf("%s-%d-%s", net.ParseIP(spec.Addr).String(), spec.Port, proto)
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
