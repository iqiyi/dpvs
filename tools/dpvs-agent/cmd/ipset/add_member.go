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

type ipsetAddMember struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewIpsetAddMember(cp *pool.ConnPool, parentLogger hclog.Logger) *ipsetAddMember {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("ipsetAddMember")
	}
	return &ipsetAddMember{connPool: cp, logger: logger}
}

func (h *ipsetAddMember) Handle(params api.AddMemberParams) middleware.Responder {
	if params.IpsetParam == nil {
		return api.NewAddMemberBadRequest().WithPayload("missing ipset param")
	}

	if *params.IpsetParam.Name != params.Name {
		return api.NewAddMemberBadRequest().WithPayload("ipset name mismatch")
	}

	if params.IpsetParam.CreationOptions != nil {
		return api.NewAddMemberBadRequest().WithPayload("CreationOptions set in adding member")
	}

	conf := types.IPSetParamArray{}
	if err := conf.Build(types.IPSET_OP_ADD, params.IpsetParam); err != nil {
		return api.NewAddMemberBadRequest().WithPayload(fmt.Sprintf(
			"build AddMember param failed: %s", err.Error()))
	}

	if err := conf.Check(); err != nil {
		return api.NewAddMemberBadRequest().WithPayload(fmt.Sprintf(
			"AddMember params check failed: %s", err.Error()))
	}

	err, derr := conf.AddDelMember(h.connPool, h.logger)
	if derr == types.EDPVS_EXIST {
		return api.NewAddMemberOK().WithPayload(fmt.Sprintf("%s (may partially succeed)", derr.String()))
	}
	if err != nil {
		h.logger.Error("Ipset AddMember failed.", "setName", params.Name, "Reason", err.Error())
		if derr == types.EDPVS_NOTEXIST {
			return api.NewAddMemberNotFound().WithPayload(derr.String())
		}
		return api.NewAddMemberFailure().WithPayload(err.Error())
	}

	h.logger.Info("Ipset AddMember succeed.", "setName", params.Name)
	return api.NewAddMemberCreated().WithPayload(fmt.Sprintf("ipset %s add members succeed",
		params.Name))
}
