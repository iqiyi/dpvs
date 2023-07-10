package ipvs

import (
	// "fmt"
	"net"

	// "github.com/dpvs-agent/models"
	"github.com/dpvs-agent/pkg/ipc/pool"
	"github.com/dpvs-agent/pkg/ipc/types"

	apiVs "github.com/dpvs-agent/restapi/operations/virtualserver"

	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

type putVsAllow struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewPutVsAllow(cp *pool.ConnPool, parentLogger hclog.Logger) *putVsAllow {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("PutVsVipPortAllow")
	}
	return &putVsAllow{connPool: cp, logger: logger}
}

func (h *putVsAllow) Handle(params apiVs.PutVsVipPortAllowParams) middleware.Responder {
	spec := types.NewCertificateAuthoritySpec()
	if err := spec.ParseVipPortProto(params.VipPort); err != nil {
		h.logger.Error("Convert to virtual server failed.", "VipPort", params.VipPort, "Error", err.Error())
		return apiVs.NewPutVsVipPortAllowInvalidFrontend()
	}

	failed := false
	for _, allow := range params.ACL.Items {
		if net.ParseIP(allow.Addr) == nil {
			h.logger.Error("Invalid ip addr add.", "VipPort", params.VipPort, "Addr", allow.Addr)
			return apiVs.NewPutVsVipPortAllowInvalidFrontend()
		}
		spec.SetSrc(allow.Addr)

		if result := spec.Add(h.connPool, false, h.logger); result != types.EDPVS_OK {
			failed = true
			h.logger.Error("Add ip addr to white list failed.", "VipPort", params.VipPort, "Addr", allow.Addr, "result", result.String())
			continue
		}
		h.logger.Info("Add ip addr to white list success.", "VipPort", params.VipPort, "Addr", allow.Addr)
	}

	if failed {
		return apiVs.NewPutVsVipPortAllowInvalidBackend()
	}

	return apiVs.NewPutVsVipPortAllowOK()
}
