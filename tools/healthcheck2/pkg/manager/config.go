// +k8s:deepcopy-gen=package
package manager

import (
	"errors"
	"fmt"
	"io/ioutil"
	"reflect"
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/actioner"
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

func (acf *ActionConf) Valid() error {
	if acf.ActionTimeout <= 0 {
		return fmt.Errorf("invalid action-timeout: %v", acf.ActionTimeout)
	}
	if acf.ActionSyncTime <= 0 {
		return fmt.Errorf("invalid action-sync-time: %v", acf.ActionSyncTime)
	}

	if len(acf.Actioner) == 0 {
		return errors.New("empty actioner name")
	}
	return actioner.Validate(acf.Actioner, acf.ActionParams)
}

func (acf *ActionConf) DeepEqual(other *ActionConf) bool {
	return reflect.DeepEqual(acf, other)
}

func (acf *ActionConf) MergeDefault(defaultConf *ActionConf) {
	if len(acf.Actioner) == 0 {
		acf.Actioner = defaultConf.Actioner
		acf.ActionParams = nil
		if len(defaultConf.ActionParams) > 0 {
			acf.ActionParams = make(map[string]string, len(defaultConf.ActionParams))
			for name, val := range defaultConf.ActionParams {
				acf.ActionParams[name] = val
			}
		}
	}
	if acf.ActionTimeout == 0 {
		acf.ActionTimeout = defaultConf.ActionTimeout
	}
	if acf.ActionSyncTime == 0 {
		acf.ActionSyncTime = defaultConf.ActionSyncTime
	}
	if len(acf.ActionParams) == 0 {
		// TODO: Support method-dependent default params.
	}
}

// +k8s:deepcopy-gen=true
type VAConf struct {
	Disable    bool     `yaml:"disable"`
	DownPolicy VAPolicy `yaml:"down-policy"`
	ActionConf `yaml:",inline"`
}

func (va *VAConf) Valid() error {
	if va.DownPolicy > VAPolicyAllOf || va.DownPolicy < VAPolicyOneOf {
		return fmt.Errorf("invalid down-policy: %d", va.DownPolicy)
	}
	return va.ActionConf.Valid()
}

func (va *VAConf) DeepEqual(other *VAConf) bool {
	return reflect.DeepEqual(va, other)
}

func (va *VAConf) MergeDefault(defaultConf *VAConf) {
	// VAConf::Disable default 0

	if va.DownPolicy == 0 {
		va.DownPolicy = defaultConf.DownPolicy
	}

	va.ActionConf.MergeDefault(&defaultConf.ActionConf)
}

// +k8s:deepcopy-gen=true
type VSConf struct {
	CheckerConf `yaml:",inline"`
	ActionConf  `yaml:",inline"`
}

func (vs *VSConf) Valid() error {
	if err := vs.CheckerConf.Valid(); err != nil {
		return err
	}
	if err := vs.ActionConf.Valid(); err != nil {
		return err
	}
	return nil
}

func (vs *VSConf) DeepEqual(other *VSConf) bool {
	return reflect.DeepEqual(vs, other)
}

func (vs *VSConf) MergeDefault(defaultConf *VSConf) {
	vs.CheckerConf.MergeDefault(&defaultConf.CheckerConf)
	vs.ActionConf.MergeDefault(&defaultConf.ActionConf)
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
	Timeout      time.Duration     `yaml:"timeout"`
	MethodParams map[string]string `yaml:"method-params"`
}

func (c *CheckerConf) Valid() error {
	if c.Interval <= 0 {
		return fmt.Errorf("invalid checker interval %v", c.Interval)
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("invalid checker timeout %v", c.Timeout)
	}

	return checker.Validate(c.Method, c.MethodParams)
}

func (c *CheckerConf) DeepEqual(other *CheckerConf) bool {
	return reflect.DeepEqual(c, other)
}

func (c *CheckerConf) MergeDefault(defaultConf *CheckerConf) {
	if c.Method == 0 {
		c.Method = defaultConf.Method
		c.MethodParams = nil
		if len(defaultConf.MethodParams) > 0 {
			c.MethodParams = make(map[string]string, len(defaultConf.MethodParams))
			for name, val := range defaultConf.MethodParams {
				c.MethodParams[name] = val
			}
		}
	}
	if c.Interval == 0 {
		c.Interval = defaultConf.Interval
	}
	if c.DownRetry == 0 { // FIXME: How to specify 0 value?
		c.DownRetry = defaultConf.DownRetry
	}
	if c.UpRetry == 0 { // FIXME: How to specify 0 value?
		c.UpRetry = defaultConf.UpRetry
	}
	if c.Timeout == 0 {
		c.Timeout = defaultConf.Timeout
	}

	if len(c.MethodParams) == 0 {
		// TODO: Support method-dependent default params.
	}
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
			DownRetry: 0,
			UpRetry:   0,
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
	fc.Global.VAConf.MergeDefault(&defaultConf.vaGlobal)
	fc.Global.VSConf.MergeDefault(&defaultConf.vsGlobal)
	for vaid, _ := range fc.VAs {
		conf := fc.VAs[vaid]
		if dft, ok := defaultConf.vaConf[vaid]; ok {
			conf.MergeDefault(&dft)
		} else {
			conf.MergeDefault(&defaultConf.vaGlobal)
		}
		fc.VAs[vaid] = conf
	}
	for vsid, _ := range fc.VSs {
		conf := fc.VSs[vsid]
		if dft, ok := defaultConf.vsConf[vsid]; ok {
			conf.MergeDefault(&dft)
		} else {
			conf.MergeDefault(&defaultConf.vsGlobal)
		}
		fc.VSs[vsid] = conf
	}
}

func (fc *ConfFileLayout) Validate() error {
	if err := fc.Global.VAConf.Valid(); err != nil {
		return fmt.Errorf("global/virtual-address: %v", err)
	}

	if err := fc.Global.VSConf.Valid(); err != nil {
		return fmt.Errorf("global/virtual-server: %v", err)
	}

	for vaid, va := range fc.VAs {
		if err := va.Valid(); err != nil {
			return fmt.Errorf("virtual-address/%s: %v", vaid, err)
		}
	}

	for vsid, vs := range fc.VSs {
		if err := vs.Valid(); err != nil {
			return fmt.Errorf("virtual-server/%s: %v", vsid, err)
		}
	}

	return nil
}

func (fc *ConfFileLayout) Translate() (*Conf, error) {
	// return &confDefault, nil
	return &Conf{
		vaGlobal: fc.Global.VAConf,
		vsGlobal: fc.Global.VSConf,
		vaConf:   fc.VAs,
		vsConf:   fc.VSs,
	}, nil
}

func LoadFileConf(filename string) (*Conf, error) {
	if len(filename) == 0 {
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
	// fmt.Printf("FileConf:\n %v", fileConf)

	fileConf.Merge(&confDefault)
	if err = fileConf.Validate(); err != nil {
		return nil, fmt.Errorf("Invalid config from file: %v", err)
	}
	GetAppManager().cfgFileReloader.SetRaw(&fileConf)

	return fileConf.Translate()
}
