package types

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/dpvs-agent/models"
	"github.com/hashicorp/go-hclog"
)

type NodeSnapshot struct {
	NodeSpec *models.DpvsNodeSpec
	Services map[string]*models.VirtualServerSpecExpand
}

func (snapshot *NodeSnapshot) ServiceVersionUpdate(id string, logger hclog.Logger) {
	services := snapshot.Services
	logger.Info("Update server version begin.", "id", id, "services", services)
	if _, exist := services[strings.ToLower(id)]; exist {
		services[strings.ToLower(id)].Version = strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
		return
	}
	logger.Error("Update service version failed.", "id", id)
}

func (snapshot *NodeSnapshot) ServiceGet(id string) *models.VirtualServerSpecExpand {
	if svc, exist := snapshot.Services[strings.ToLower(id)]; exist {
		return svc
	}
	return nil
}

func (snapshot *NodeSnapshot) ServiceDel(id string) {
	if _, exist := snapshot.Services[strings.ToLower(id)]; exist {
		delete(snapshot.Services, strings.ToLower(id))
	}
}

func (snapshot *NodeSnapshot) ServiceVersion(id string) string {
	if _, exist := snapshot.Services[strings.ToLower(id)]; exist {
		return snapshot.Services[strings.ToLower(id)].Version
	}
	return strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
}

func (snapshot *NodeSnapshot) ServiceAdd(vs *VirtualServerSpec) {
	version := snapshot.ServiceVersion(vs.ID())

	snapshot.Services[strings.ToLower(vs.ID())] = vs.GetModel()

	snapshot.Services[strings.ToLower(vs.ID())].Version = version
}

func (snapshot *NodeSnapshot) ServiceUpsert(spec *models.VirtualServerSpecExpand) {
	svc := (*VirtualServerSpecExpandModel)(spec)

	version := snapshot.ServiceVersion(svc.ID())

	snapshot.Services[strings.ToLower(svc.ID())] = spec

	snapshot.Services[strings.ToLower(svc.ID())].Version = version
}

func (snapshot *NodeSnapshot) GetModels(logger hclog.Logger) *models.VirtualServerList {
	services := &models.VirtualServerList{Items: make([]*models.VirtualServerSpecExpand, len(snapshot.Services))}
	i := 0
	for _, svc := range snapshot.Services {
		services.Items[i] = svc
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

func (snapshot *NodeSnapshot) LoadFrom(cacheFile string, logger hclog.Logger) error {
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

	snapshot.NodeSpec = nodeSnapshot.NodeSpec
	for _, svcModel := range nodeSnapshot.Services.Items {
		svc := (*VirtualServerSpecExpandModel)(svcModel)
		snapshot.Services[strings.ToLower(svc.ID())] = svcModel
	}

	return nil
}

func (snapshot *NodeSnapshot) DumpTo(cacheFile string, logger hclog.Logger) error {
	nodeSnapshot := &models.NodeServiceSnapshot{
		NodeSpec: snapshot.NodeSpec,
		Services: snapshot.GetModels(logger),
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
