package comm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/checker"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

// Notes:
// dpvs-agent dpvsAgentServiceListUri/dpvsAgentCheckUpdateUri always returns
// backend user-specified weight rather than healthchecker modified weight.
const (
	httpClientTimeout          = 10 * time.Second
	dpvsAgentServiceListUri    = "/v2/vs"
	dpvsAgentServiceListMethod = http.MethodGet
	dpvsAgentCheckUpdateUri    = "/v2/vs/%s/rs/health?version=%d"
	dpvsAgentCheckUpdateMethod = http.MethodPut
	dpvsAgentDeviceAddrUri     = "/v2/device/%s/addr"
)

var client *http.Client = &http.Client{Timeout: httpClientTimeout}

// svcId returns the virtual service ID used in dpvs-agent.
func svcId(vip string, vport uint16, proto utils.IPProto) string {
	return strings.ToLower(fmt.Sprintf("%s-%d-%s", vip, vport, proto))
}

func (vs *VirtualServer) Id() string {
	return svcId(vs.Addr.IP.String(), vs.Addr.Port, vs.Addr.Proto)
}

func (avs *DpvsAgentVs) Id() string {
	return svcId(avs.Addr, avs.Port, utils.IPProto(avs.Proto))
}

func (avs *DpvsAgentVs) toVs() (*VirtualServer, error) {
	version, err := strconv.ParseUint(avs.Version, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invlaid VS Version %q", avs.Version)
	}
	vip := net.ParseIP(avs.Addr)
	if vip == nil {
		return nil, fmt.Errorf("invalid VS Addr %q", avs.Addr)
	}
	vport := avs.Port
	proto := utils.IPProto(avs.Proto)
	if proto != utils.IPProtoTCP && proto != utils.IPProtoUDP {
		return nil, fmt.Errorf("not supported VS protocol type 0x%0x", avs.Proto)
	}
	method := checker.CheckMethodNone
	if len(avs.DestCheck) > 0 { // Note: Support only one check method per VS.
		method = checker.ParseMethod(avs.DestCheck[0])
	}
	ppversion := ProxyProtoVersion(avs.ProxyProto)
	quic := strings.EqualFold(avs.Quic, "true")
	vs := &VirtualServer{
		Version: version,
		Addr: utils.L3L4Addr{
			IP:    vip,
			Port:  vport,
			Proto: proto,
		},
		DestCheck:  method,
		ProxyProto: ppversion,
		Quic:       quic,
	}
	if rss, err := avs.RSs.toRsList(vs.Addr.Proto); err != nil {
		return nil, fmt.Errorf("%s: %v", avs.Id(), err)
	} else {
		vs.RSs = rss
	}
	return vs, nil
}

func (avsl *DpvsAgentVsList) toVsList() ([]VirtualServer, error) {
	if len(avsl.Items) == 0 {
		return nil, nil
	}
	vslist := make([]VirtualServer, len(avsl.Items))
	for i, avs := range avsl.Items {
		vs, err := avs.toVs()
		if err != nil {
			return nil, err
		}
		vslist[i] = *vs
	}
	return vslist, nil
}

func (arsl *DpvsAgentRsListGet) toRsList(proto utils.IPProto) ([]RealServer, error) {
	rss := make([]RealServer, len(arsl.Items))
	for i, ars := range arsl.Items {
		rip := net.ParseIP(ars.Spec.IP)
		if rip == nil {
			return nil, fmt.Errorf("invalid RS IP %q", ars.Spec.IP)
		}
		rs := &RealServer{
			Addr: utils.L3L4Addr{
				IP:    rip,
				Port:  ars.Spec.Port,
				Proto: proto,
			},
			Weight: ars.Spec.Weight,
		}
		if ars.Spec.Inhibited != nil {
			rs.Inhibited = *ars.Spec.Inhibited
		}
		rss[i] = *rs
	}
	return rss, nil
}

func GetServiceFromDPVS(svr string, ctx context.Context) ([]VirtualServer, error) {
	var req *http.Request
	var err error
	url := fmt.Sprintf("%s%s", svr, dpvsAgentServiceListUri)
	if strings.HasPrefix(url, "https://") {
		// TODO: add supports for HTTPS
		return nil, fmt.Errorf("https not supported")
	}
	if ctx != nil {
		req, err = http.NewRequestWithContext(ctx, dpvsAgentServiceListMethod, url, nil)
	} else {
		req, err = http.NewRequest(dpvsAgentServiceListMethod, url, nil)
	}
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	glog.V(9).Infof("[dpvs-agent service list API] Code: %v, Resp: %v, Err: %v",
		resp.StatusCode, string(data), err)
	var avsl DpvsAgentVsList
	if err = json.Unmarshal(data, &avsl); err != nil {
		return nil, err
	}
	vslist, err := avsl.toVsList()
	if err != nil {
		return nil, err
	}
	return vslist, nil
}

func UpdateCheckState(svr string, vs *VirtualServer, ctx context.Context) (*VirtualServer, error) {
	url := svr + dpvsAgentCheckUpdateUri
	url = fmt.Sprintf(url, vs.Id(), vs.Version)
	if strings.HasPrefix(url, "https://") {
		// TODO: add supports for HTTPS
		return nil, fmt.Errorf("https not supported")
	}
	arsl := &DpvsAgentRsListPut{}
	for _, rs := range vs.RSs {
		item := DpvsAgentRs{
			IP:        rs.Addr.IP.String(),
			Port:      rs.Addr.Port,
			Weight:    rs.Weight,
			Inhibited: &rs.Inhibited,
		}
		arsl.Items = append(arsl.Items, item)
	}
	data, err := json.Marshal(arsl)
	if err != nil {
		return nil, err
	}
	var req *http.Request
	if ctx != nil {
		req, err = http.NewRequestWithContext(ctx, dpvsAgentCheckUpdateMethod, url, bytes.NewBuffer(data))
	} else {
		req, err = http.NewRequest(dpvsAgentCheckUpdateMethod, url, bytes.NewBuffer(data))
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	glog.V(9).Infof("[dpvs-agent check update API] URL: %v, Request: %v, Code: %v", url, req, resp.Status)
	if resp.StatusCode != 200 {
		if data, err = io.ReadAll(resp.Body); err != nil {
			return nil, fmt.Errorf("http response code: %v, msg read error: %v", resp.StatusCode, err)
		}
		var vs DpvsAgentVs
		if err = json.Unmarshal(data, &vs); err != nil {
			return nil, fmt.Errorf("http response code: %v, error msg: %v", resp.StatusCode,
				strings.TrimSpace(string(data)))
		}
		ret, err := vs.toVs()
		if err != nil {
			return nil, fmt.Errorf("http response code: %v, reformatting error: %v", resp.StatusCode, err)
		}
		return ret, nil
	}
	return nil, nil
}

func AddDelDeviceAddr(isAdd bool, svr, ifname string, addr net.IP, ctx context.Context) error {
	url := svr + dpvsAgentDeviceAddrUri
	url = fmt.Sprintf(url, ifname)
	if strings.HasPrefix(url, "https://") {
		// TODO: add supports for HTTPS
		return fmt.Errorf("https not supported")
	}

	method := http.MethodPut
	if !isAdd {
		method = http.MethodDelete
	}

	data := map[string]string{
		"addr": addr.String(),
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("fail to marshal json data: %v", err)
	}

	var req *http.Request
	if ctx != nil {
		req, err = http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(jsonData))
	} else {
		req, err = http.NewRequest(method, url, bytes.NewBuffer(jsonData))
	}
	if err != nil {
		return fmt.Errorf("failed to create http request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected http status code: %v", resp.StatusCode)
	}
	return nil
}
