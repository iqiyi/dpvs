package ipvs

import (
	"github.com/dpvs-agent/pkg/ipc/pool"
	"github.com/dpvs-agent/pkg/ipc/types"

	apiVs "github.com/dpvs-agent/restapi/operations/virtualserver"

	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

type delVsItem struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewDelVsItem(cp *pool.ConnPool, parentLogger hclog.Logger) *delVsItem {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("DelVsVipPort")
	}
	return &delVsItem{connPool: cp, logger: logger}
}

func (h *delVsItem) Handle(params apiVs.DeleteVsVipPortParams) middleware.Responder {
	vs := types.NewVirtualServerSpec()
	if err := vs.ParseVipPortProto(params.VipPort); err != nil {
		h.logger.Error("Convert to virtual server failed.", "VipPort", params.VipPort, "Error", err.Error())
		return apiVs.NewDeleteVsVipPortFailure()
	}

	result := vs.Del(h.connPool, h.logger)
	switch result {
	case types.EDPVS_OK:
		h.logger.Info("Del virtual server success.", "VipPort", params.VipPort)
		return apiVs.NewDeleteVsVipPortOK()
	case types.EDPVS_NOTEXIST:
		h.logger.Warn("Del a not exist virtual server done.", "VipPort", params.VipPort, "result", result.String())
		return apiVs.NewDeleteVsVipPortNotFound()
	default:
		h.logger.Error("Del virtual server failed.", "VipPort", params.VipPort, "result", result.String())
	}
	return apiVs.NewDeleteVsVipPortFailure()
}
