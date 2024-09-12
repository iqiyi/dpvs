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
	// "fmt"
	"net"
	"strings"

	// "github.com/dpvs-agent/models"
	"github.com/dpvs-agent/pkg/ipc/pool"
	"github.com/dpvs-agent/pkg/ipc/types"

	apiVs "github.com/dpvs-agent/restapi/operations/virtualserver"

	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

type putVsAllow struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewPutVsAllow(cp *pool.ConnPool, parentLogger hclog.Logger) *putVsAllow {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("PutVsVipPortAllow")
	}
	return &putVsAllow{connPool: cp, logger: logger}
}

func (h *putVsAllow) Handle(params apiVs.PutVsVipPortAllowParams) middleware.Responder {
	spec := types.NewCertificateAuthoritySpec()
	if err := spec.ParseVipPortProto(params.VipPort); err != nil {
		h.logger.Error("Convert to virtual server failed.", "VipPort", params.VipPort, "Error", err.Error())
		return apiVs.NewPutVsVipPortAllowInvalidFrontend()
	}

	failed := false
	for _, allow := range params.ACL.Items {
		spec.SetCaddr("")
		spec.SetIpset("")
		if len(allow.Ipset) > 0 {
			if !strings.HasPrefix(allow.Ipset, "ipset:") {
				h.logger.Error("Invalid allow ipset format in add.", "VipPort", params.VipPort,
					"Ipset", allow.Ipset, "expecting \"ipset:NAME\"")
				return apiVs.NewPutVsVipPortAllowInvalidFrontend()
			}
			spec.SetIpset(allow.Ipset)
		} else {
			if net.ParseIP(allow.Addr) == nil {
				h.logger.Error("Invalid ip addr add.", "VipPort", params.VipPort, "Addr", allow.Addr)
				return apiVs.NewPutVsVipPortAllowInvalidFrontend()
			}
			spec.SetCaddr(allow.Addr)
		}

		if result := spec.Add(h.connPool, false, h.logger); result != types.EDPVS_OK {
			failed = true
			h.logger.Error("Add ip addr to white list failed.", "VipPort", params.VipPort, "Addr", allow.Addr, "result", result.String())
			continue
		}
		h.logger.Info("Add entry to white list success.", "VipPort", params.VipPort, "Addr", allow.Addr, "Ipset", allow.Ipset)
	}

	if failed {
		return apiVs.NewPutVsVipPortAllowInvalidBackend()
	}

	return apiVs.NewPutVsVipPortAllowOK()
}
