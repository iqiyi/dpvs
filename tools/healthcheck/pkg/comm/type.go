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

// +k8s:deepcopy-gen=package
package comm

import (
	"github.com/iqiyi/dpvs/tools/healthcheck/pkg/checker"
	"github.com/iqiyi/dpvs/tools/healthcheck/pkg/utils"
)

// +k8s:deepcopy-gen=true
type RealServer struct {
	Addr      utils.L3L4Addr
	Weight    uint16
	Inhibited bool
}

// +k8s:deepcopy-gen=true
type VirtualServer struct {
	Version    uint64
	Addr       utils.L3L4Addr
	DestCheck  checker.Method
	ProxyProto ProxyProtoVersion
	Quic       bool
	RSs        []RealServer
}

type ProxyProtoVersion uint8

const (
	ProxyProtoNone       ProxyProtoVersion = 0x0
	ProxyProtoV1         ProxyProtoVersion = 0x1
	ProxyProtoV2         ProxyProtoVersion = 0x2
	ProxyProtoV1Insecure ProxyProtoVersion = 0x11
	ProxyProtoV2Insecure ProxyProtoVersion = 0x12
)

type DpvsAgentRs struct {
	IP        string `json:"ip"`
	Port      uint16 `json:"port"`
	Weight    uint16 `json:"weight"`
	Inhibited *bool  `json:"inhibited,omitempty`
}

type DpvsAgentRsItem struct {
	Spec DpvsAgentRs
}

type DpvsAgentRsListGet struct {
	Items []DpvsAgentRsItem
}

type DpvsAgentRsListPut struct {
	Items []DpvsAgentRs
}

// refer to `tools/dpvs-agent/models/virtual_server_spec_expand.go: VirtualServerSpecExpand`
type DpvsAgentVs struct {
	Version    string
	Addr       string
	Port       uint16
	Proto      uint16
	DestCheck  []string
	ProxyProto uint8              `json:"ProxyProto,omitempty"`
	Quic       string             `json:"Quic,omitempty"`
	RSs        DpvsAgentRsListGet `json:"RSs"`
}

type DpvsAgentVsList struct {
	Items []DpvsAgentVs
}
