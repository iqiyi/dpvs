// +k8s:deepcopy-gen=package
package manager

import (
	"reflect"
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/checker"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/comm"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
)

type VAPolicy int

const (
	VAPolicyOneOf VAPolicy = 1
	VAPolicyAllOf VAPolicy = 2
)

// +k8s:deepcopy-gen=true
type ActionConf struct {
	actioner       string
	actionTimeout  time.Duration
	actionSyncTime time.Duration
	actionParams   map[string]string
}

// +k8s:deepcopy-gen=true
type VAConf struct {
	disable    bool
	downPolicy VAPolicy
	ActionConf
}

func (va *VAConf) DeepEqual(other *VAConf) bool {
	return reflect.DeepEqual(va, other)
}

// +k8s:deepcopy-gen=true
type VSConf struct {
	CheckerConf
	ActionConf
	backends map[CheckerID]VSBackendConf
}

func (vs *VSConf) DeepEqual(other *VSConf) bool {
	return reflect.DeepEqual(vs, other)
}

func (c *VSConf) GetCheckerConf() *CheckerConf {
	return &c.CheckerConf
}

// Merge configs from dpvs and files. Configs from dpvs takes precede than files.
func (c *VSConf) MergeConf(vs *comm.VirtualServer) {
	if vs.DestCheck != checker.NoneChecker && c.method != vs.DestCheck {
		c.method = vs.DestCheck
	}

	if vs.ProxyProto&comm.ProxyProtoV1 == comm.ProxyProtoV1 {
		c.methodParams[checker.ParamProxyProto] = "v1"
	} else if vs.ProxyProto&comm.ProxyProtoV2 == comm.ProxyProtoV2 {
		c.methodParams[checker.ParamProxyProto] = "v2"
	}

	if vs.Quic {
		c.methodParams[checker.ParamQuic] = "true"
	}

	if len(vs.RSs) == 0 {
		return
	}
	if c.backends == nil {
		c.backends = make(map[CheckerID]VSBackendConf)
	}
	for _, rs := range vs.RSs {
		checkerID := CheckerID(rs.Addr.String())
		backend := VSBackendConf{
			version: vs.Version,
			uweight: uint(rs.Weight),
			state:   types.Healthy,
		}
		if rs.Inhibited {
			backend.state = types.Unhealthy
		}
		c.backends[checkerID] = backend
	}
}

// +k8s:deepcopy-gen=true
type VSBackendConf struct {
	version uint64
	state   types.State
	uweight uint
}

// +k8s:deepcopy-gen=true
type CheckerConf struct {
	method       checker.Method
	interval     time.Duration
	downRetry    uint
	upRetry      uint
	timeout      time.Duration
	methodParams map[string]string
}

func (c *CheckerConf) DeepEqual(other *CheckerConf) bool {
	return reflect.DeepEqual(c, other)
}

// +k8s:deepcopy-gen=true
type Conf struct {
	vaGlobal VAConf
	vsGlobal VSConf
	vaConf   map[VAID]VAConf
	vsConf   map[VSID]VSConf
}

func (c *Conf) GetVAConf(id VAID) *VAConf {
	if conf, ok := c.vaConf[id]; ok {
		return &conf
	}
	return &c.vaGlobal
}

func (c *Conf) GetVSConf(id VSID) *VSConf {
	if conf, ok := c.vsConf[id]; ok {
		return &conf
	}
	return &c.vsGlobal
}

var (
	vaConfDefault VAConf = VAConf{
		disable:    false,
		downPolicy: VAPolicyAllOf,
		ActionConf: ActionConf{
			actioner:       "kniAddrAddDel",
			actionTimeout:  2 * time.Second,
			actionSyncTime: 60 * time.Second,
		},
	}

	vsConfDefault VSConf = VSConf{
		CheckerConf: CheckerConf{
			method:    checker.AutoChecker,
			interval:  2 * time.Second,
			downRetry: 1,
			upRetry:   1,
			timeout:   2 * time.Second,
		},
		ActionConf: ActionConf{
			actioner:       "updateWeightState",
			actionTimeout:  2 * time.Second,
			actionSyncTime: 15 * time.Second,
		},
	}

	confDefault Conf = Conf{
		vaGlobal: vaConfDefault,
		vsGlobal: vsConfDefault,
	}
)

func LoadFileConf(filename string) (*Conf, error) {
	// TODO: load config from file

	return &confDefault, nil
}
