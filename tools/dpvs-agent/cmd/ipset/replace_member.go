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

type ipsetReplaceMember struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewIpsetReplaceMember(cp *pool.ConnPool, parentLogger hclog.Logger) *ipsetReplaceMember {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("ipsetReplaceMember")
	}
	return &ipsetReplaceMember{connPool: cp, logger: logger}
}

func (h *ipsetReplaceMember) Handle(params api.ReplaceMemberParams) middleware.Responder {
	if params.IpsetParam == nil {
		return api.NewReplaceMemberBadRequest().WithPayload("missing ipset param")
	}

	if *params.IpsetParam.Name != params.Name {
		return api.NewReplaceMemberBadRequest().WithPayload("ipset name mismatch")
	}

	if params.IpsetParam.CreationOptions != nil {
		return api.NewReplaceMemberBadRequest().WithPayload("CreationOptions set in replacing member")
	}

	opcode := types.IPSET_OP_FLUSH
	if len(params.IpsetParam.Entries) > 0 {
		opcode = types.IPSET_OP_ADD
	}

	conf := types.IPSetParamArray{}
	if err := conf.Build(opcode, params.IpsetParam); err != nil {
		return api.NewReplaceMemberBadRequest().WithPayload(fmt.Sprintf(
			"build ReplaceMember param failed: %s", err.Error()))
	}

	if err := conf.Check(); err != nil {
		return api.NewReplaceMemberBadRequest().WithPayload(fmt.Sprintf(
			"ReplaceMember params check failed: %s", err.Error()))
	}

	err, derr := conf.ReplaceMember(h.connPool, h.logger)
	if derr == types.EDPVS_NOTEXIST {
		return api.NewReplaceMemberNotFound().WithPayload(derr.String())
	}
	if err != nil {
		h.logger.Error("Ipset ReplaceMember failed.", "setName", params.Name, "Reason", err.Error())
		return api.NewReplaceMemberFailure().WithPayload(err.Error())
	}

	h.logger.Info("Ipset ReplaceMember succeed.", "setName", params.Name)
	return api.NewReplaceMemberOK().WithPayload(fmt.Sprintf("ipset %s replace members succeed",
		params.Name))
}
