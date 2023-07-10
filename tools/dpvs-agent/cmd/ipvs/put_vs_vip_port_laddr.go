package ipvs

import (
	"github.com/dpvs-agent/pkg/ipc/pool"
	"github.com/dpvs-agent/pkg/ipc/types"

	apiVs "github.com/dpvs-agent/restapi/operations/virtualserver"

	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

type putVsLaddr struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewPutVsLaddr(cp *pool.ConnPool, parentLogger hclog.Logger) *putVsLaddr {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("PutVsVipPortLaddr")
	}
	return &putVsLaddr{connPool: cp, logger: logger}
}

func (h *putVsLaddr) Handle(params apiVs.PutVsVipPortLaddrParams) middleware.Responder {
	laddr := types.NewLocalAddrFront()

	err := laddr.ParseVipPortProto(params.VipPort)
	if err != nil {
		h.logger.Error("Convert to virtual server failed.", "VipPort", params.VipPort, "Error", err.Error())
		return apiVs.NewPutVsVipPortLaddrInvalidFrontend()
	}

	lds := make([]*types.LocalAddrDetail, 1)

	lds[0] = types.NewLocalAddrDetail()
	lds[0].SetAf(laddr.GetAf())
	lds[0].SetAddr(params.Spec.Addr)
	lds[0].SetIfName(params.Spec.Device)

	result := laddr.Add(lds, h.connPool, h.logger)
	switch result {
	case types.EDPVS_OK:
		h.logger.Info("Set virtual server Local IP success.", "VipPort", params.VipPort, "Local Addr", params.Spec.Addr)
		return apiVs.NewPutVsVipPortLaddrOK()
	case types.EDPVS_EXIST:
		h.logger.Warn("Local IP already exist.", "VipPort", params.VipPort, "Local Addr", params.Spec.Addr, "result", result.String())
		return apiVs.NewPutVsVipPortLaddrOK()
	default:
		h.logger.Error("Set virtual server Local IP failed.", "VipPort", params.VipPort, "Local Addr", params.Spec.Addr, "result", result.String())
	}

	return apiVs.NewPutVsVipPortLaddrFailure()
}
