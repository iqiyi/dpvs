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

type ipsetIsIn struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewIpsetIsIn(cp *pool.ConnPool, parentLogger hclog.Logger) *ipsetIsIn {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("ipsetIsIn")
	}
	return &ipsetIsIn{connPool: cp, logger: logger}
}

func (h *ipsetIsIn) Handle(params api.IsInParams) middleware.Responder {
	if params.IpsetCell == nil {
		return api.NewIsInBadRequest().WithPayload("missing ipset entry")
	}

	conf := types.IPSetParam{}
	conf.SetOpcode(types.IPSET_OP_TEST)
	conf.SetName(params.Name)
	conf.SetKind(string(*params.IpsetCell.Type))
	if err := conf.BuildMember(params.IpsetCell.Member); err != nil {
		return api.NewIsInBadRequest().WithPayload(fmt.Sprintf("invalid member: %s", err.Error()))
	}

	if err := conf.Check(); err != nil {
		return api.NewIsInBadRequest().WithPayload(fmt.Sprintf("invalid param: %s", err.Error()))
	}

	result, err, derr := conf.IsIn(h.connPool, h.logger)
	if err != nil {
		h.logger.Error("Ipset IsIn failed.", "setName", params.Name, "Reason", err.Error())
		if derr == types.EDPVS_NOTEXIST {
			return api.NewIsInNotFound().WithPayload(derr.String())
		}
		return api.NewIsInFailure().WithPayload(err.Error())
	}
	h.logger.Info("Ipset InIn succeed.", "setName", params.Name)

	nomatch := ""
	if params.IpsetCell.Member.Options != nil &&
		params.IpsetCell.Member.Options.NoMatch != nil &&
		*params.IpsetCell.Member.Options.NoMatch {
		nomatch = " (nomatch)"
	}

	msg := ""
	if result {
		msg = fmt.Sprintf("%s%s is IN set %s", nomatch, *params.IpsetCell.Member.Entry, params.Name)
	} else {
		msg = fmt.Sprintf("%s%s is NOT IN set %s", nomatch, *params.IpsetCell.Member.Entry, params.Name)
	}
	return api.NewIsInOK().WithPayload(&api.IsInOKBody{Result: &result, Message: msg})
}
