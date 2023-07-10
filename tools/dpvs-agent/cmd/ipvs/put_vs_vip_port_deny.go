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

type putVsDeny struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewPutVsDeny(cp *pool.ConnPool, parentLogger hclog.Logger) *putVsDeny {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("PutVsVipPortDeny")
	}
	return &putVsDeny{connPool: cp, logger: logger}
}

func (h *putVsDeny) Handle(params apiVs.PutVsVipPortDenyParams) middleware.Responder {
	spec := types.NewCertificateAuthoritySpec()
	if err := spec.ParseVipPortProto(params.VipPort); err != nil {
		h.logger.Error("Convert to virtual server failed.", "VipPort", params.VipPort, "Error", err.Error())
		return apiVs.NewPutVsVipPortDenyInvalidFrontend()
	}

	failed := false
	for _, deny := range params.ACL.Items {
		if net.ParseIP(deny.Addr) == nil {
			h.logger.Error("Invalid ip addr add.", "VipPort", params.VipPort, "Addr", deny.Addr)
			return apiVs.NewPutVsVipPortDenyInvalidFrontend()
		}
		spec.SetSrc(deny.Addr)

		if result := spec.Add(h.connPool, true, h.logger); result != types.EDPVS_OK {
			h.logger.Error("Add ip addr to black list failed.", "VipPort", params.VipPort, "Addr", deny.Addr, "result", result.String())
			failed = true
			continue
		}
		h.logger.Info("Add ip addr to black list success.", "VipPort", params.VipPort, "Addr", deny.Addr)
	}

	if failed {
		return apiVs.NewPutVsVipPortDenyInvalidBackend()
	}

	return apiVs.NewPutVsVipPortDenyOK()
}
