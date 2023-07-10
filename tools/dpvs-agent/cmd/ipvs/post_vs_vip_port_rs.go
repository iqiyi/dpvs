package ipvs

import (
	// "github.com/dpvs-agent/models"
	"github.com/dpvs-agent/pkg/ipc/pool"
	"github.com/dpvs-agent/pkg/ipc/types"

	apiVs "github.com/dpvs-agent/restapi/operations/virtualserver"

	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

type postVsRs struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewPostVsRs(cp *pool.ConnPool, parentLogger hclog.Logger) *postVsRs {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("PostVsVipPortRs")
	}
	return &postVsRs{connPool: cp, logger: logger}
}

func (h *postVsRs) Handle(params apiVs.PostVsVipPortRsParams) middleware.Responder {
	front := types.NewRealServerFront()
	if err := front.ParseVipPortProto(params.VipPort); err != nil {
		h.logger.Error("Convert to virtual server failed.", "VipPort", params.VipPort, "Error", err.Error())
		return apiVs.NewPostVsVipPortRsInvalidFrontend()
	}

	rss := make([]*types.RealServerSpec, len(params.Rss.Items))
	for i, rs := range params.Rss.Items {
		var fwdmode types.DpvsFwdMode
		fwdmode.FromString(rs.Mode)
		rss[i] = types.NewRealServerSpec()
		rss[i].SetAf(front.GetAf())
		rss[i].SetPort(rs.Port)
		rss[i].SetWeight(uint32(rs.Weight))
		rss[i].SetProto(front.GetProto())
		rss[i].SetAddr(rs.IP)
		rss[i].SetInhibited(rs.Inhibited)
		rss[i].SetOverloaded(rs.Inhibited)
		rss[i].SetFwdMode(fwdmode)
	}

	result := front.Update(rss, h.connPool, h.logger)
	switch result {
	case types.EDPVS_EXIST, types.EDPVS_OK:
		h.logger.Info("Set real server to virtual server success.", "VipPort", params.VipPort, "rss", rss, "result", result.String())
		return apiVs.NewPostVsVipPortRsOK()
	default:
		h.logger.Error("Set real server to virtual server failed.", "VipPort", params.VipPort, "rss", rss, "result", result.String())
		return apiVs.NewPostVsVipPortRsFailure()
	}
	return apiVs.NewPostVsVipPortRsInvalidBackend()
}
