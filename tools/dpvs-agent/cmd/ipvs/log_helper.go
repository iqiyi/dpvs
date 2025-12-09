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

// FormatRealServerSpecs 将 RealServerSpec 列表格式化为易读的字符串
// 格式: ["IP:Port(weight=W,mode=M,inhibited=I,overloaded=O)", ...]
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

// FormatRealServerSpec 格式化单个 RealServerSpec（导出函数）
func FormatRealServerSpec(rs *types.RealServerSpec) string {
	return formatRealServerSpec(rs)
}

// formatRealServerSpec 格式化单个 RealServerSpec（内部函数）
func formatRealServerSpec(rs *types.RealServerSpec) string {
	if rs == nil {
		return "nil"
	}

	var attrs []string

	// 基本信息: IP:Port
	base := rs.ID()

	// 权重
	weight := rs.GetWeight()
	if weight > 0 {
		attrs = append(attrs, fmt.Sprintf("weight=%d", weight))
	}

	// 转发模式
	mode := rs.GetFwdModeString()
	if mode != "" {
		attrs = append(attrs, fmt.Sprintf("mode=%s", mode))
	}

	// Inhibited 状态
	if rs.GetInhibited() {
		attrs = append(attrs, "inhibited=true")
	}

	// Overloaded 状态
	if rs.GetOverloaded() {
		attrs = append(attrs, "overloaded=true")
	}

	// MaxConn/MinConn (如果设置了)
	// 注意: RealServerSpec 没有直接的 GetMaxConn/GetMinConn 方法
	// 如果需要，可以通过反射或添加方法获取

	if len(attrs) > 0 {
		return fmt.Sprintf("%s(%s)", base, strings.Join(attrs, ","))
	}
	return base
}

// FormatRealServerSpecsSimple 简化版本，只显示 IP:Port 列表
// 格式: ["IP:Port", "IP:Port", ...]
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
