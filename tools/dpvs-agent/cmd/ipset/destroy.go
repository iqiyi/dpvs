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

type ipsetDestroy struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewIpsetDestroy(cp *pool.ConnPool, parentLogger hclog.Logger) *ipsetDestroy {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("ipsetDestroy")
	}
	return &ipsetDestroy{connPool: cp, logger: logger}
}

func (h *ipsetDestroy) Handle(params api.DestroyParams) middleware.Responder {
	conf := types.IPSetParam{}
	conf.SetOpcode(types.IPSET_OP_DESTROY)
	conf.SetName(params.Name)

	err, derr := conf.CreateDestroy(h.connPool, h.logger)
	if derr == types.EDPVS_NOTEXIST {
		return api.NewDestroyNotFound().WithPayload(derr.String())
	}
	if err != nil {
		h.logger.Error("Ipset Destroy failed.", "setName", params.Name, "Reason", err.Error())
		return api.NewDestroyFailure().WithPayload(err.Error())
	}

	h.logger.Info("Ipset Destroy succeed.", "setName", params.Name)
	return api.NewDestroyOK().WithPayload(fmt.Sprintf("ipset %s destroyed", params.Name))
}
