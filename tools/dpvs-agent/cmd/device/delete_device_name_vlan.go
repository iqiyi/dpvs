package device

import (
	// "github.com/dpvs-agent/models"
	"github.com/dpvs-agent/pkg/ipc/pool"
	"github.com/dpvs-agent/pkg/ipc/types"

	apiDevice "github.com/dpvs-agent/restapi/operations/device"

	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

type delDeviceVlan struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewDelDeviceVlan(cp *pool.ConnPool, parentLogger hclog.Logger) *delDeviceVlan {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("DelDeviceVlan")
	}
	return &delDeviceVlan{connPool: cp, logger: logger}
}

// dpip vlan del dpdk0.102
func (h *delDeviceVlan) Handle(params apiDevice.DeleteDeviceNameVlanParams) middleware.Responder {
	// vlan device delete is need device name only
	vlan := types.NewVlanDevice()
	vlan.SetIfName(params.Name)

	result := vlan.Del(h.connPool, h.logger)
	switch result {
	case types.EDPVS_OK:
		h.logger.Info("Delete dpvs vlan success.", "Vlan Name", params.Name)
		return apiDevice.NewDeleteDeviceNameVlanOK()
	case types.EDPVS_NOTEXIST:
		h.logger.Warn("Delete dpvs vlan done.", "Vlan Name", params.Name, "result", result.String())
		return apiDevice.NewDeleteDeviceNameVlanOK()
	default:
		h.logger.Error("Delete dpvs vlan failed.", "Vlan Name", params.Name, "result", result.String())
	}

	return apiDevice.NewDeleteDeviceNameVlanInternalServerError()
}
