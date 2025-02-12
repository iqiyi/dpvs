package checker

import (
	"strings"
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

type CheckMethod interface {
	// Check executes a healthcheck procedure of the method once.
	Check(target *utils.L3L4Addr, timeout time.Duration) (types.State, error)
	// BindConfig binds method specific configs.
	BindConfig(configs map[string]string) error
}

type Method uint16

const (
	NoneChecker    Method = iota
	TCPChecker            // "tcp"
	UDPChecker            // "udp"
	PingChecker           // "ping"
	UDPPingChecker        // "udpping"
	HTTPChecker           // "http"
	// TODO: add new check methods here

	AutoChecker    Method = 10000 // "automatically inferred from protocol"
	PassiveChecker Method = 65535 // "passive", dpvs internal checker, ignore it
)

func ParseMethod(name string) Method {
	name = strings.ToLower(name)
	switch name {
	case "tcp":
		return TCPChecker
	case "udp":
		return UDPChecker
	case "ping":
		return PingChecker
	case "udpping":
		return UDPPingChecker
	case "http":
		return HTTPChecker

	case "auto":
		return AutoChecker
	}
	return NoneChecker
}

func (m *Method) String() string {
	switch *m {
	case TCPChecker:
		return "tcp"
	case UDPChecker:
		return "udp"
	case PingChecker:
		return "ping"
	case UDPPingChecker:
		return "udpping"
	case NoneChecker:
		return "none"
	case PassiveChecker:
		return "passive"
	case AutoChecker:
		return "auto"
	default:
		return "unknown"
	}
	return ""
}

func (m *Method) TranslateAuto(proto utils.IPProto) Method {
	switch proto {
	case utils.IPProtoTCP:
		return TCPChecker
	case utils.IPProtoUDP:
		return UDPPingChecker
	}
	return PingChecker
}

// Checker params that can be derived from dpvs.
const (
	ParamProxyProto = "proxy-protocol" // "", "v1", "v2"
	ParamQuic       = "quic"           // "", "true", "false"
)
