package device

import (
	"github.com/dpvs-agent/pkg/ipc/pool"
	"github.com/dpvs-agent/pkg/ipc/types"

	apiDevice "github.com/dpvs-agent/restapi/operations/device"

	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

type putDeviceAddr struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewPutDeviceAddr(cp *pool.ConnPool, parentLogger hclog.Logger) *putDeviceAddr {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("PutDeviceAddr")
	}
	return &putDeviceAddr{connPool: cp, logger: logger}
}

// dpip addr add 192.168.88.16/32 dev dpdk0.102
func (h *putDeviceAddr) Handle(params apiDevice.PutDeviceNameAddrParams) middleware.Responder {
	addr := types.NewInetAddrDetail()

	if params.Spec == nil {
		return apiDevice.NewPutDeviceNameAddrInternalServerError()
	}

	addr.SetAddr(params.Spec.Addr)
	addr.SetScope(params.Spec.Scope)
	addr.SetBCast(params.Spec.Broadcast)
	addr.SetIfName(params.Name)
	if params.Sapool != nil && *params.Sapool {
		addr.SetFlags("sapool")
	}
	// addr.SetValidLft(prarms.Spec.ValidLft)
	// addr.SetPreferedLft(prarms.Spec.ValidLft)

	result := addr.Add(h.connPool, h.logger)
	switch result {
	case types.EDPVS_OK:
		h.logger.Info("Add addr from device success.", "Device Name", params.Name, "Addr", params.Spec.Addr)
		return apiDevice.NewPutDeviceNameAddrOK()
	case types.EDPVS_EXIST:
		h.logger.Warn("Device already exist addr, add done.", "Device Name", params.Name, "Addr", params.Spec.Addr, "result", result.String())
		return apiDevice.NewPutDeviceNameAddrOK()
	default:
		h.logger.Error("Add addr from device failed.", "Device Name", params.Name, "Addr", params.Spec.Addr, "result", result.String())
	}

	return apiDevice.NewPutDeviceNameAddrInternalServerError()
}
