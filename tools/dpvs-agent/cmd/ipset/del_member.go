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

type ipsetDelMember struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewIpsetDelMember(cp *pool.ConnPool, parentLogger hclog.Logger) *ipsetDelMember {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("ipsetDelMember")
	}
	return &ipsetDelMember{connPool: cp, logger: logger}
}

func (h *ipsetDelMember) Handle(params api.DelMemberParams) middleware.Responder {
	if params.IpsetParam == nil {
		return api.NewDelMemberBadRequest().WithPayload("missing ipset param")
	}

	if *params.IpsetParam.Name != params.Name {
		return api.NewDelMemberBadRequest().WithPayload("ipset name mismatch")
	}

	if params.IpsetParam.CreationOptions != nil {
		return api.NewDelMemberBadRequest().WithPayload("CreationOptions set in deleting member")
	}

	conf := types.IPSetParamArray{}
	if err := conf.Build(types.IPSET_OP_DEL, params.IpsetParam); err != nil {
		return api.NewDelMemberBadRequest().WithPayload(fmt.Sprintf(
			"build DelMember param failed: %s", err.Error()))
	}

	if err := conf.Check(); err != nil {
		return api.NewDelMemberBadRequest().WithPayload(fmt.Sprintf(
			"DelMember params check failed: %s", err.Error()))
	}

	err, derr := conf.AddDelMember(h.connPool, h.logger)
	if derr == types.EDPVS_NOTEXIST {
		return api.NewDelMemberNotFound().WithPayload(fmt.Sprintf("%s(may partially deleted)",
			derr.String()))
	}
	if err != nil {
		h.logger.Error("Ipset DelMember failed.", "setName", params.Name, "Reason", err.Error())
		return api.NewDelMemberFailure().WithPayload(err.Error())
	}

	h.logger.Info("Ipset DelMember succeed.", "setName", params.Name)
	return api.NewDelMemberOK().WithPayload(fmt.Sprintf("ipset %s delete members succeed",
		params.Name))
}
