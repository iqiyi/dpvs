package device

import (
	"fmt"
	"net"
	"strings"

	"github.com/vishvananda/netlink"

	"github.com/dpvs-agent/pkg/ipc/pool"
	apiDevice "github.com/dpvs-agent/restapi/operations/device"

	"github.com/go-openapi/runtime/middleware"
	"github.com/hashicorp/go-hclog"
)

type putDeviceNetlinkAddr struct {
	connPool *pool.ConnPool
	logger   hclog.Logger
}

func NewPutDeviceNetlinkAddr(cp *pool.ConnPool, parentLogger hclog.Logger) *putDeviceNetlinkAddr {
	logger := hclog.Default()
	if parentLogger != nil {
		logger = parentLogger.Named("PutDeviceNetlinkAddr")
	}
	return &putDeviceNetlinkAddr{connPool: cp, logger: logger}
}

// ip addr add 10.0.0.1/32 dev eth0
func (h *putDeviceNetlinkAddr) Handle(params apiDevice.PutDeviceNameNetlinkAddrParams) middleware.Responder {
	// h.logger.Info("/v2/device/", params.Name, "/netlink/addr ", params.Spec.Addr)
	var cidr string
	if strings.Count(params.Spec.Addr, "/") == 0 {
		ip := net.ParseIP(params.Spec.Addr)
		if ip == nil {
			h.logger.Info("Parse IP failed.", "Addr", params.Spec.Addr)
			return apiDevice.NewPutDeviceNameNetlinkAddrInternalServerError()
		}
		if ip.To4() != nil {
			cidr = params.Spec.Addr + "/32"
		} else {
			cidr = params.Spec.Addr + "/128"
		}
	} else {
		cidr = params.Spec.Addr
	}

	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		h.logger.Error("Parse CIDR failed.", "cidr", cidr, "Error", err.Error())
		return apiDevice.NewPutDeviceNameNetlinkAddrInternalServerError()
	}

	ipnet.IP = ip
	addr := &netlink.Addr{IPNet: ipnet}

	link, err := netlink.LinkByName(params.Name)
	if err != nil {
		h.logger.Error("netlink.LinkByName() failed.", "Device Name", params.Name, "Error", err.Error())
		return apiDevice.NewPutDeviceNameNetlinkAddrInternalServerError()
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		h.logger.Error("netlink.AddrAdd() failed.", "Error", err.Error())
		return apiDevice.NewPutDeviceNameNetlinkAddrInternalServerError()
	}

	cmd := fmt.Sprintf("ip addr add %s dev %s", cidr, params.Name)
	h.logger.Info("Device add Addr success.", "cmd", cmd)
	return apiDevice.NewPutDeviceNameNetlinkAddrOK()
}
