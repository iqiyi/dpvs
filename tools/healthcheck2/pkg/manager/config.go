// +k8s:deepcopy-gen=package
package manager

import (
	"fmt"
	"io/ioutil"
	"reflect"
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/checker"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/comm"
	"gopkg.in/yaml.v2"
)

type VAPolicy int

const (
	VAPolicyOneOf VAPolicy = 1
	VAPolicyAllOf VAPolicy = 2
)

// +k8s:deepcopy-gen=true
type ActionConf struct {
	Actioner       string            `yaml:"actioner"`
	ActionTimeout  time.Duration     `yaml:"action-timeout"`
	ActionSyncTime time.Duration     `yaml:"action-sync-time"`
	ActionParams   map[string]string `yaml:"action-params"`
}

func (acf *ActionConf) Valid() bool {
	return acf.ActionTimeout > 0 && acf.ActionSyncTime > 0 && len(acf.Actioner) > 0
}

func (acf *ActionConf) DeepEqual(other *ActionConf) bool {
	return reflect.DeepEqual(acf, other)
}

// +k8s:deepcopy-gen=true
type VAConf struct {
	Disable    bool     `yaml:"disable"`
	DownPolicy VAPolicy `yaml:"down-policy"`
	ActionConf `yaml:",inline"`
}

func (va *VAConf) Valid() bool {
	return va.ActionConf.Valid()
}

func (va *VAConf) DeepEqual(other *VAConf) bool {
	return reflect.DeepEqual(va, other)
}

// +k8s:deepcopy-gen=true
type VSConf struct {
	CheckerConf `yaml:",inline"`
	ActionConf  `yaml:",inline"`
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
		c.Method = vs.DestCheck
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
	Method       checker.Method    `yaml:"method"`
	Interval     time.Duration     `yaml:"interval"`
	DownRetry    uint              `yaml:"down-retry"`
	UpRetry      uint              `yaml:"up-retry"`
	Timeout      time.Duration     `yaml:"timeouot"`
	MethodParams map[string]string `yaml:"method-params"`
}

func (c *CheckerConf) Valid() bool {
	return c.Interval > 0 && c.Timeout > 0 && (c.Method <= checker.CheckMethodAuto && c.Method > checker.CheckMethodNone)
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
		Disable:    false,
		DownPolicy: VAPolicyAllOf,
		ActionConf: ActionConf{
			Actioner:       "KernelRouteAddDel",
			ActionTimeout:  2 * time.Second,
			ActionSyncTime: 60 * time.Second,
			ActionParams:   map[string]string{"ifname": "lo"},
		},
		/*
			ActionConf: ActionConf{
				Actioner:       "DpvsAddrKernelRouteAddDel",
				ActionTimeout:  2 * time.Second,
				ActionSyncTime: 60 * time.Second,
				ActionParams: map[string]string{
					"ifname":      "lo",
					"dpvs-ifname": "dpdk0.102",
				},
			},
			ActionConf: ActionConf{
				Actioner:       "DpvsAddrAddDel",
				ActionTimeout:  2 * time.Second,
				ActionSyncTime: 60 * time.Second,
				ActionParams:   map[string]string{"dpvs-ifname": "dpdk0.102"},
			},
			ActionConf: ActionConf{
				Actioner:       "Script",
				ActionTimeout:  2 * time.Second,
				ActionSyncTime: 60 * time.Second,
				ActionParams: map[string]string{
					"script": "./pkg/Actioner/quorum_script.sh",
					"args":   "dpdk0.102",
				},
			},
		*/
	}

	vsConfDefault VSConf = VSConf{
		CheckerConf: CheckerConf{
			Method:    checker.CheckMethodAuto,
			Interval:  3 * time.Second,
			DownRetry: 1,
			UpRetry:   1,
			Timeout:   2 * time.Second,
		},
		ActionConf: ActionConf{
			Actioner:       "BackendUpdate",
			ActionTimeout:  2 * time.Second,
			ActionSyncTime: 15 * time.Second,
		},
	}

	confDefault Conf = Conf{
		vaGlobal: vaConfDefault,
		vsGlobal: vsConfDefault,
	}
)

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

// /////////////////////// Load Config from File ///////////////////////////
type ConfFileLayoutGlobal struct {
	VAConf VAConf `yaml:"virtual-address"`
	VSConf VSConf `yaml:"virtual-server"`
}

type ConfFileLayout struct {
	Global ConfFileLayoutGlobal `yaml:"global"`
	VAs    map[VAID]VAConf      `yaml:"virtual-addresses"`
	VSs    map[VSID]VSConf      `yaml:"virtual-servers"`
}

func (fc *ConfFileLayout) Merge(defaultConf *Conf) {
	// TODO
}

func (fc *ConfFileLayout) Validate(omitEmpty bool) error {
	// TODO
	return nil
}

func (fc *ConfFileLayout) Translate() (*Conf, error) {
	// TODO
	return &confDefault, nil
}

func LoadFileConf(filename string) (*Conf, error) {
	// TODO: load config from file
	if len(filename) > 0 {
		return &confDefault, nil
	}

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var fileConf ConfFileLayout

	err = yaml.Unmarshal(data, &fileConf)
	if err != nil {
		return nil, err
	}
	fmt.Printf("FileConf:\n %v", fileConf) // TODO: DEL ME

	if err = fileConf.Validate(true); err != nil {
		return nil, fmt.Errorf("Invalid config from file: %v", err)
	}
	fileConf.Merge(&confDefault)

	return fileConf.Translate()
}
