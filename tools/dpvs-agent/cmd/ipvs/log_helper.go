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

package ipvs

import (
	"fmt"
	"strings"

	"github.com/dpvs-agent/pkg/ipc/types"
)

// FormatRealServerSpecs formats a list of RealServerSpec as a human-readable string
// Format: ["IP:Port(weight=W,mode=M,inhibited=I,overloaded=O)", ...]
func FormatRealServerSpecs(rss []*types.RealServerSpec) string {
	if len(rss) == 0 {
		return "[]"
	}

	var parts []string
	for _, rs := range rss {
		parts = append(parts, formatRealServerSpec(rs))
	}
	return fmt.Sprintf("[%s]", strings.Join(parts, ", "))
}

// FormatRealServerSpec formats a single RealServerSpec (exported function)
func FormatRealServerSpec(rs *types.RealServerSpec) string {
	return formatRealServerSpec(rs)
}

// formatRealServerSpec formats a single RealServerSpec (internal function)
func formatRealServerSpec(rs *types.RealServerSpec) string {
	if rs == nil {
		return "nil"
	}

	var attrs []string

	// Basic info: IP:Port
	base := rs.ID()

	// Weight
	weight := rs.GetWeight()
	if weight > 0 {
		attrs = append(attrs, fmt.Sprintf("weight=%d", weight))
	}

	// Forwarding mode
	mode := rs.GetFwdModeString()
	if mode != "" {
		attrs = append(attrs, fmt.Sprintf("mode=%s", mode))
	}

	// Inhibited status
	if rs.GetInhibited() {
		attrs = append(attrs, "inhibited=true")
	}

	// Overloaded status
	if rs.GetOverloaded() {
		attrs = append(attrs, "overloaded=true")
	}

	// MaxConn/MinConn (if set)
	// Note: RealServerSpec doesn't have direct GetMaxConn/GetMinConn methods
	// If needed, can be obtained through reflection or by adding methods

	if len(attrs) > 0 {
		return fmt.Sprintf("%s(%s)", base, strings.Join(attrs, ","))
	}
	return base
}

// FormatRealServerSpecsSimple is a simplified version that only shows IP:Port list
// Format: ["IP:Port", "IP:Port", ...]
func FormatRealServerSpecsSimple(rss []*types.RealServerSpec) string {
	if len(rss) == 0 {
		return "[]"
	}

	var ids []string
	for _, rs := range rss {
		if rs != nil {
			ids = append(ids, rs.ID())
		}
	}
	return fmt.Sprintf("[%s]", strings.Join(ids, ", "))
}

// FormatVirtualServerSpec formats VirtualServerSpec
// Format: IP-Port-Protocol(sched=SCHEDULER,fwmark=FWMARK)
func FormatVirtualServerSpec(vs *types.VirtualServerSpec) string {
	if vs == nil {
		return "nil"
	}

	// Basic info: IP-Port-Protocol
	base := vs.ID()

	var attrs []string

	// Scheduler name
	schedName := strings.TrimRight(string(vs.GetSchedName()), "\x00")
	if schedName != "" {
		attrs = append(attrs, fmt.Sprintf("sched=%s", schedName))
	}

	// Fwmark (if set)
	if vs.GetFwmark() > 0 {
		attrs = append(attrs, fmt.Sprintf("fwmark=%d", vs.GetFwmark()))
	}

	if len(attrs) > 0 {
		return fmt.Sprintf("%s(%s)", base, strings.Join(attrs, ","))
	}
	return base
}

// FormatLocalAddrDetails formats a list of LocalAddrDetail
// Format: ["IP(device=DEVICE)", ...]
func FormatLocalAddrDetails(details []*types.LocalAddrDetail) string {
	if len(details) == 0 {
		return "[]"
	}

	var parts []string
	for _, detail := range details {
		if detail == nil {
			parts = append(parts, "nil")
			continue
		}

		addr := detail.GetAddr()
		device := detail.GetIfName()

		if device != "" {
			parts = append(parts, fmt.Sprintf("%s(device=%s)", addr, device))
		} else {
			parts = append(parts, addr)
		}
	}
	return fmt.Sprintf("[%s]", strings.Join(parts, ", "))
}

// FormatVirtualServerSpecs formats a list of VirtualServerSpec
// Format: ["IP-Port-Protocol(sched=SCHEDULER)", ...]
func FormatVirtualServerSpecs(vss []*types.VirtualServerSpec) string {
	if len(vss) == 0 {
		return "[]"
	}

	var parts []string
	for _, vs := range vss {
		parts = append(parts, FormatVirtualServerSpec(vs))
	}
	return fmt.Sprintf("[%s]", strings.Join(parts, ", "))
}
