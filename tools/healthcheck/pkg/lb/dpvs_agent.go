// Copyright 2023 IQiYi Inc. All Rights Reserved.
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

package lb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck/pkg/utils"
)

var _ Comm = (*DpvsAgentComm)(nil)

var (
	serverDefault = "localhost:53225"
	listUri       = LbApi{"/v2/vs", http.MethodGet}
	noticeUri     = LbApi{"/v2/vs/%s/rs?healthcheck=true", http.MethodPut}

	client *http.Client = &http.Client{Timeout: httpClientTimeout}
)

const httpClientTimeout = 10 * time.Second

type DpvsAgentComm struct {
	listApi    LbApi
	noticeApis []LbApi
}

type LbApi struct {
	Url        string
	HttpMethod string // http.MethodGet, http.MethodPut, ...
}

type DpvsAgentRs struct {
	IP        string `json:"ip"`
	Port      uint16 `json:"port"`
	Weight    uint16 `json:"weight"`
	Inhibited bool   `json:"inhibited,omitempty"`
}

type DpvsAgentRsItem struct {
	Spec DpvsAgentRs
}

type DpvsAgentRsList struct {
	Items []DpvsAgentRsItem
}

type DpvsAgentRsListPut struct {
	Items []DpvsAgentRs
}

type DpvsAgentVs struct {
	Addr      string
	Port      uint16
	Proto     uint16
	DestCheck []string
	Rss       DpvsAgentRsList `json:"RSs"`
}

type DpvsAgentVsList struct {
	Items []DpvsAgentVs
}

func (avs *DpvsAgentVs) serviceId() string {
	return strings.ToLower(fmt.Sprintf("%s-%d-%s", avs.Addr, avs.Port,
		utils.IPProto(avs.Proto)))
}

func (avs *DpvsAgentVs) toVs() (*VirtualService, error) {
	vip := net.ParseIP(avs.Addr)
	if vip == nil {
		return nil, fmt.Errorf("invalid Vs Addr %q", avs.Addr)
	}
	vport := avs.Port
	proto := utils.IPProto(avs.Proto)
	if proto != utils.IPProtoTCP && proto != utils.IPProtoUDP {
		return nil, fmt.Errorf("Vs protocol type 0x%x not supported", avs.Port)
	}
	checker := CheckerNone
	for _, name := range avs.DestCheck {
		name = strings.ToLower(name)
		switch name {
		case "tcp":
			checker = CheckerTCP
		case "udp":
			checker = CheckerUDP
		case "ping":
			checker = CheckerPING
		}
	}
	vs := &VirtualService{
		Checker:  checker,
		IP:       vip,
		Port:     vport,
		Protocol: proto,
		RSs:      make([]RealServer, len(avs.Rss.Items)),
	}
	vs.Id = avs.serviceId()

	for i, ars := range avs.Rss.Items {
		rip := net.ParseIP(ars.Spec.IP)
		if rip == nil {
			return nil, fmt.Errorf("%s: invalid Rs IP %q", vs.Id, ars.Spec.IP)
		}
		rs := &RealServer{
			IP:        rip,
			Port:      ars.Spec.Port,
			Weight:    ars.Spec.Weight,
			Inhibited: ars.Spec.Inhibited,
		}
		vs.RSs[i] = *rs
	}
	return vs, nil
}

func (avslist *DpvsAgentVsList) toVsList() ([]VirtualService, error) {
	if len(avslist.Items) == 0 {
		return nil, nil
	}
	vslist := make([]VirtualService, len(avslist.Items))
	for i, avs := range avslist.Items {
		vs, err := avs.toVs()
		if err != nil {
			return nil, err
		}
		vslist[i] = *vs
	}
	return vslist, nil
}

func NewDpvsAgentComm(server string) *DpvsAgentComm {
	if len(server) == 0 {
		server = serverDefault
	}
	addr := "http://" + server
	return &DpvsAgentComm{
		listApi:    LbApi{addr + listUri.Url, listUri.HttpMethod},
		noticeApis: []LbApi{{addr + noticeUri.Url, noticeUri.HttpMethod}},
	}
}

func (comm *DpvsAgentComm) ListVirtualServices() ([]VirtualService, error) {
	req, err := http.NewRequest(comm.listApi.HttpMethod, comm.listApi.Url, nil)
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
	//fmt.Printf("Code: %v, Resp: %v, Err: %v\n", resp.StatusCode, string(data), err)
	var svcs DpvsAgentVsList
	if err = json.Unmarshal(data, &svcs); err != nil {
		return nil, err
	}
	vslist, err := svcs.toVsList()
	if err != nil {
		return nil, err
	}
	//fmt.Println(vslist)
	return vslist, nil
}

func (comm *DpvsAgentComm) UpdateByChecker(targets []VirtualService) error {
	// TODO: support batch operation
	for _, vs := range targets {
		for _, rs := range vs.RSs {
			ars := &DpvsAgentRsListPut{
				Items: []DpvsAgentRs{
					{
						IP:        rs.IP.String(),
						Port:      rs.Port,
						Weight:    rs.Weight,
						Inhibited: rs.Inhibited,
					},
				},
			}
			data, err := json.Marshal(ars)
			if err != nil {
				return err
			}
			for _, notice := range comm.noticeApis {
				url := fmt.Sprintf(notice.Url, vs.Id)
				req, err := http.NewRequest(notice.HttpMethod, url, bytes.NewBuffer(data))
				req.Header.Set("Content-Type", "application/json")
				resp, err := client.Do(req)
				if err != nil {
					return err
				}
				//fmt.Println("Code:", resp.Status)
				if resp.StatusCode != 200 {
					data, _ = io.ReadAll(resp.Body)
					return fmt.Errorf("CODE: %v, ERROR: %s", resp.StatusCode, strings.TrimSpace(string(data)))
				}
				resp.Body.Close()
			}
		}
	}
	return nil
}
