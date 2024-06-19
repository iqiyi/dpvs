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

type putVsDeny struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewPutVsDeny(cp *pool.ConnPool, parentLogger hclog.Logger) *putVsDeny {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("PutVsVipPortDeny")
	}
	return &putVsDeny{connPool: cp, logger: logger}
}

func (h *putVsDeny) Handle(params apiVs.PutVsVipPortDenyParams) middleware.Responder {
	spec := types.NewCertificateAuthoritySpec()
	if err := spec.ParseVipPortProto(params.VipPort); err != nil {
		h.logger.Error("Convert to virtual server failed.", "VipPort", params.VipPort, "Error", err.Error())
		return apiVs.NewPutVsVipPortDenyInvalidFrontend()
	}

	failed := false
	for _, deny := range params.ACL.Items {
		spec.SetCaddr("")
		spec.SetIpset("")
		if len(deny.Ipset) > 0 {
			if !strings.HasPrefix(deny.Ipset, "ipset:") {
				h.logger.Error("Invalid deny ipset format in add.", "VipPort", params.VipPort,
					"Ipset", deny.Ipset, "expecting \"ipset:NAME\"")
				return apiVs.NewPutVsVipPortDenyInvalidFrontend()
			}
			spec.SetIpset(deny.Ipset)
		} else {
			if net.ParseIP(deny.Addr) == nil {
				h.logger.Error("Invalid deny ip addr in add.", "VipPort", params.VipPort, "Addr", deny.Addr)
				return apiVs.NewPutVsVipPortDenyInvalidFrontend()
			}
			spec.SetCaddr(deny.Addr)
		}

		if result := spec.Add(h.connPool, true, h.logger); result != types.EDPVS_OK {
			h.logger.Error("Add ip addr to black list failed.", "VipPort", params.VipPort, "Addr", deny.Addr, "result", result.String())
			failed = true
			continue
		}
		h.logger.Info("Add entry to black list success.", "VipPort", params.VipPort, "Addr", deny.Addr, "Ipset", deny.Ipset)
	}

	if failed {
		return apiVs.NewPutVsVipPortDenyInvalidBackend()
	}

	return apiVs.NewPutVsVipPortDenyOK()
}
