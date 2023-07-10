package ipvs

import (
	"net"

	"github.com/dpvs-agent/pkg/ipc/pool"
	"github.com/dpvs-agent/pkg/ipc/types"

	apiVs "github.com/dpvs-agent/restapi/operations/virtualserver"

	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

type delVsAllow struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewDelVsAllow(cp *pool.ConnPool, parentLogger hclog.Logger) *delVsAllow {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("DelVsVipPortAllow")
	}
	return &delVsAllow{connPool: cp, logger: logger}
}

func (h *delVsAllow) Handle(params apiVs.DeleteVsVipPortAllowParams) middleware.Responder {
	spec := types.NewCertificateAuthoritySpec()
	if err := spec.ParseVipPortProto(params.VipPort); err != nil {
		h.logger.Error("Convert to virtual server failed.", "VipPort", params.VipPort, "Error", err.Error())
		return apiVs.NewDeleteVsVipPortAllowInvalidFrontend()
	}

	failed := false
	for _, allow := range params.ACL.Items {
		if net.ParseIP(allow.Addr) == nil {
			h.logger.Error("Invalid ip addr del.", "VipPort", params.VipPort, "Addr", allow.Addr)
			return apiVs.NewDeleteVsVipPortAllowInvalidFrontend()
		}
		spec.SetSrc(allow.Addr)

		if result := spec.Del(h.connPool, false, h.logger); result != types.EDPVS_OK {
			failed = true
			h.logger.Error("IP Addr delete from white list failed.", "VipPort", params.VipPort, "Addr", allow.Addr, "result", result.String())
			continue
		}
		h.logger.Info("IP Addr delete from white list success.", "VipPort", params.VipPort, "Addr", allow.Addr)
	}

	if failed {
		return apiVs.NewDeleteVsVipPortAllowInvalidBackend()
	}

	return apiVs.NewDeleteVsVipPortAllowOK()
}
