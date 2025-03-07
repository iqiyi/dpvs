// +k8s:deepcopy-gen=package
package manager

import (
	"reflect"
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/checker"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/comm"
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

func (acf *ActionConf) Valid() bool {
	return acf.actionTimeout > 0 && acf.actionSyncTime > 0 && len(acf.actioner) > 0
}

func (acf *ActionConf) DeepEqual(other *ActionConf) bool {
	return reflect.DeepEqual(acf, other)
}

// +k8s:deepcopy-gen=true
type VAConf struct {
	disable    bool
	downPolicy VAPolicy
	ActionConf
}

func (va *VAConf) Valid() bool {
	return va.ActionConf.Valid()
}

func (va *VAConf) DeepEqual(other *VAConf) bool {
	return reflect.DeepEqual(va, other)
}

// +k8s:deepcopy-gen=true
type VSConf struct {
	CheckerConf
	ActionConf
}

func (vs *VSConf) Valid() bool {
	return vs.CheckerConf.Valid() && vs.ActionConf.Valid()
}

func (vs *VSConf) DeepEqual(other *VSConf) bool {
	return reflect.DeepEqual(vs, other)
}

func (c *VSConf) GetCheckerConf() *CheckerConf {
	return &c.CheckerConf
}

func (c *VSConf) GetActionConf() *ActionConf {
	return &c.ActionConf
}

// Merge configs from dpvs and files. Configs from dpvs takes precede over files.
// Append new params to "params" if given (not nil), otherwise created one.
func (c *VSConf) MergeDpvsCheckerConf(vs *comm.VirtualServer, params map[string]string) map[string]string {
	rc := params
	if rc == nil {
		rc = make(map[string]string)
	}

	if vs.DestCheck != checker.CheckMethodNone {
		c.method = vs.DestCheck
	}

	if vs.ProxyProto&comm.ProxyProtoV1 == comm.ProxyProtoV1 {
		params[checker.ParamProxyProto] = "v1"
	} else if vs.ProxyProto&comm.ProxyProtoV2 == comm.ProxyProtoV2 {
		params[checker.ParamProxyProto] = "v2"
	}

	if vs.Quic {
		params[checker.ParamQuic] = "true"
	}

	return rc
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

func (c *CheckerConf) Valid() bool {
	return c.interval > 0 && c.timeout > 0 && (c.method <= checker.CheckMethodAuto && c.method > checker.CheckMethodNone)
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
			actioner:       "KernelRouteAddDel",
			actionTimeout:  2 * time.Second,
			actionSyncTime: 60 * time.Second,
			actionParams:   map[string]string{"ifname": "lo"},
		},
		/*
			ActionConf: ActionConf{
				actioner:       "DpvsAddrKernelRouteAddDel",
				actionTimeout:  2 * time.Second,
				actionSyncTime: 60 * time.Second,
				actionParams: map[string]string{
					"ifname":      "lo",
					"dpvs-ifname": "dpdk0.102",
				},
			},
			ActionConf: ActionConf{
				actioner:       "DpvsAddrAddDel",
				actionTimeout:  2 * time.Second,
				actionSyncTime: 60 * time.Second,
				actionParams:   map[string]string{"dpvs-ifname": "dpdk0.102"},
			},
			ActionConf: ActionConf{
				actioner:       "Script",
				actionTimeout:  2 * time.Second,
				actionSyncTime: 60 * time.Second,
				actionParams: map[string]string{
					"script": "./pkg/actioner/quorum_script.sh",
					"args":   "dpdk0.102",
				},
			},
		*/
	}

	vsConfDefault VSConf = VSConf{
		CheckerConf: CheckerConf{
			method:    checker.CheckMethodAuto,
			interval:  3 * time.Second,
			downRetry: 1,
			upRetry:   1,
			timeout:   2 * time.Second,
		},
		ActionConf: ActionConf{
			actioner:       "BackendUpdate",
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

// +k8s:deepcopy-gen=true
type VAConfExt struct {
	VAConf
	vss []comm.VirtualServer
}

func (c *VAConfExt) GetVAConf() *VAConf {
	return &c.VAConf
}

// +k8s:deepcopy-gen=true
type VSConfExt struct {
	VSConf
	vs comm.VirtualServer
}

func (c *VSConfExt) GetVSConf() *VSConf {
	return &c.VSConf
}
