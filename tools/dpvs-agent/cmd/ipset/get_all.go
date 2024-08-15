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

type ipsetGetAll struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewIpsetGetAll(cp *pool.ConnPool, parentLogger hclog.Logger) *ipsetGetAll {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("ipsetGetAll")
	}
	return &ipsetGetAll{connPool: cp, logger: logger}
}

func (h *ipsetGetAll) Handle(params api.GetAllParams) middleware.Responder {
	conf := &types.IPSetParam{}

	conf.SetOpcode(types.IPSET_OP_LIST)
	infos, err, _ := conf.Get(h.connPool, h.logger)
	if err != nil {
		h.logger.Error("Ipset GetAll failed.", "Reason", err.Error())
		return api.NewGetAllFailure().WithPayload(err.Error())
	}

	h.logger.Info("Ipset GetAll succeed")
	model, err := infos.Model()
	if err != nil {
		h.logger.Error("Modelling ipset GetAll result failed.", "Reason", err.Error())
	}
	return api.NewGetAllOK().WithPayload(model)
}
