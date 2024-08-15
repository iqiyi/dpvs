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

package ipset

import (
	"github.com/dpvs-agent/pkg/ipc/pool"
	"github.com/dpvs-agent/pkg/ipc/types"
	api "github.com/dpvs-agent/restapi/operations/ipset"
	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

type ipsetGet struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewIpsetGet(cp *pool.ConnPool, parentLogger hclog.Logger) *ipsetGet {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("ipsetGet")
	}
	return &ipsetGet{connPool: cp, logger: logger}
}

func (h *ipsetGet) Handle(params api.GetParams) middleware.Responder {
	conf := &types.IPSetParam{}

	conf.SetOpcode(types.IPSET_OP_LIST)
	conf.SetName(params.Name)
	infos, err, derr := conf.Get(h.connPool, h.logger)
	if err != nil {
		h.logger.Error("Ipset Get failed.", "setName", params.Name, "Reason", err.Error())
		if derr == types.EDPVS_NOTEXIST {
			return api.NewGetNotFound().WithPayload(derr.String())
		}
		return api.NewGetFailure().WithPayload(err.Error())
	}

	h.logger.Info("Ipset Get succeed", "setName", params.Name)
	model, err := infos.Model()
	if err != nil {
		h.logger.Error("Modelling ipset Get result failed.", "setName", params.Name, "Reason", err.Error())
	}

	resp := api.NewGetOK()
	if model.Count > 0 {
		resp.SetPayload(model.Infos[0])
	}
	return resp
}
