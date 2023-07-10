package device

import (
	"github.com/dpvs-agent/pkg/ipc/pool"
	"github.com/dpvs-agent/pkg/ipc/types"

	apiDevice "github.com/dpvs-agent/restapi/operations/device"

	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

type delDeviceRoute struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewDelDeviceRoute(cp *pool.ConnPool, parentLogger hclog.Logger) *delDeviceRoute {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("DelDeviceRoute")
	}
	return &delDeviceRoute{connPool: cp, logger: logger}
}

// dpip del route 192.168.88.16/32 dev dpdk0.102
func (h *delDeviceRoute) Handle(params apiDevice.DeleteDeviceNameRouteParams) middleware.Responder {

	// dest [addr], [mask] and [dev name] is useful of delete route only
	route := types.NewRouteDetail()
	route.SetDevice(params.Name)
	if params.Spec == nil {
		// FIXME: front error
		return apiDevice.NewDeleteDeviceNameRouteInternalServerError()
	}

	route.SetDst(params.Spec.Dst)
	route.SetScope(params.Spec.Scope)
	/*
		route.SetSrc(params.Spec.Src)
		route.SetGateway(params.Spec.Gateway)
		route.SetScope(params.Spec.Scope)
		route.SetMtu(params.Spec.Mtu)
		route.SetMetric(params.Spec.Metric)
	*/
	result := route.Del(h.connPool, h.logger)
	switch result {
	case types.EDPVS_OK:
		h.logger.Info("Delete route success.", "Device Name", params.Name, "route Dst", params.Spec.Dst)
		return apiDevice.NewDeleteDeviceNameRouteOK()
	case types.EDPVS_NOTEXIST:
		h.logger.Warn("Delete not exist route done.", "Device Name", params.Name, "route Dst", params.Spec.Dst, "result", result.String())
		return apiDevice.NewDeleteDeviceNameRouteOK()
	default:
		h.logger.Error("Delete route failed.", "Device Name", params.Name, "route Dst", params.Spec.Dst, "result", result.String())
	}

	return apiDevice.NewDeleteDeviceNameRouteInternalServerError()
}
