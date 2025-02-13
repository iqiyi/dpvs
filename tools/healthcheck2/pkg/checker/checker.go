package checker

import (
	"fmt"
	"strings"
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

type CheckMethod interface {
	// Check executes a healthcheck procedure of the method once.
	// The function MUST return in or immediately after `timeout` time.
	Check(target *utils.L3L4Addr, timeout time.Duration) (types.State, error)
	// create validates the given params, returns an instance of the checker
	// method, and binds params to it.
	create(params map[string]string) (CheckMethod, error)
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

var methods map[Method]CheckMethod

func registerMethod(kind Method, method CheckMethod) {
	if methods == nil {
		methods = make(map[Method]CheckMethod)
	}
	methods[kind] = method
}

func NewChecker(kind Method, target *utils.L3L4Addr, configs map[string]string) (CheckMethod, error) {
	method, ok := methods[kind]
	if !ok {
		return nil, fmt.Errorf("unsupported Action type %q", kind)
	}
	checker, err := method.create(configs)
	if err != nil {
		return nil, fmt.Errorf("checker create failed: %v", err)
	}
	return checker, nil
}

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
