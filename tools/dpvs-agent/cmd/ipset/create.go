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
	"fmt"

	"github.com/dpvs-agent/pkg/ipc/pool"
	"github.com/dpvs-agent/pkg/ipc/types"
	api "github.com/dpvs-agent/restapi/operations/ipset"
	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

type ipsetCreate struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewIpsetCreate(cp *pool.ConnPool, parentLogger hclog.Logger) *ipsetCreate {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("ipsetCreate")
	}
	return &ipsetCreate{connPool: cp, logger: logger}
}

func (h *ipsetCreate) Handle(params api.CreateParams) middleware.Responder {
	if params.IpsetParam == nil {
		return api.NewCreateBadRequest().WithPayload("missing ipset param")
	}

	if *params.IpsetParam.Name != params.Name {
		return api.NewCreateBadRequest().WithPayload("ipset name mismatch")
	}

	conf := types.IPSetParam{}
	conf.SetOpcode(types.IPSET_OP_CREATE)
	if err := conf.Build(params.IpsetParam); err != nil {
		return api.NewCreateBadRequest().WithPayload(fmt.Sprintf(
			"build create param failed: %s", err.Error()))
	}

	if err := conf.Check(); err != nil {
		return api.NewCreateBadRequest().WithPayload(fmt.Sprintf("invalid create params: %s",
			err.Error()))
	}

	err, derr := conf.CreateDestroy(h.connPool, h.logger)
	if derr == types.EDPVS_EXIST {
		return api.NewCreateOK().WithPayload(derr.String())
	}
	if err != nil {
		h.logger.Error("Ipset Create failed.", "setName", params.Name, "Reason", err.Error())
		if derr == types.EDPVS_NOTEXIST {
			return api.NewCreateNotFound().WithPayload(derr.String())
		}
		return api.NewCreateFailure().WithPayload(err.Error())
	}

	h.logger.Info("Ipset Create succeed.", "setName", params.Name)
	return api.NewCreateCreated().WithPayload(fmt.Sprintf("ipset %s created", params.Name))
}
