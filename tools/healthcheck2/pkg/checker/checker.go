package checker

import (
	"fmt"
	"strings"
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

// Checker params that can be derived from dpvs.
const (
	ParamProxyProto = "proxy-protocol" // "", "v1", "v2"
	ParamQuic       = "quic"           // "", "true", "false"
)

var (
	proxyProtoV1LocalCmd        = "PROXY UNKNOWN\r\n"
	proxyProtoV2LocalCmd []byte = []byte{
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51,
		0x55, 0x49, 0x54, 0x0A, 0x20, 0x00, 0x00, 0x00,
	}
)

type CheckMethod interface {
	// Check executes a healthcheck procedure of the method once.
	// The function MUST return in or immediately after `timeout` time.
	Check(target *utils.L3L4Addr, timeout time.Duration) (types.State, error)
	// create validates the given params, returns an instance of the checker
	// method, and binds params to it.
	create(params map[string]string) (CheckMethod, error)
	// validate checks if the "params" given are valid for creating a checker.
	validate(params map[string]string) error
}

type Method uint16

const (
	_                  Method = iota
	CheckMethodNone           // "1, none"
	CheckMethodTCP            // "2, tcp"
	CheckMethodUDP            // "3, udp"
	CheckMethodPing           // "4, ping"
	CheckMethodUDPPing        // "5, udpping"
	CheckMethodHTTP           // "6, http"
	// TODO: add new check methods here

	CheckMethodAuto    Method = 10000 // "automatically inferred from protocol"
	CheckMethodPassive Method = 65535 // "passive", dpvs internal checker, ignore it
)

var methods map[Method]CheckMethod

func registerMethod(kind Method, method CheckMethod) {
	if methods == nil {
		methods = make(map[Method]CheckMethod)
	}
	methods[kind] = method
}

func Validate(kind Method, configs map[string]string) error {
	if kind == CheckMethodAuto {
		// auto method always uses default configs
		return nil
	}
	method, ok := methods[kind]
	if !ok {
		return fmt.Errorf("unsupported checker type: %s", kind)
	}
	return method.validate(configs)
}

func NewChecker(kind Method, target *utils.L3L4Addr, configs map[string]string) (CheckMethod, error) {
	method, ok := methods[kind]
	if !ok {
		return nil, fmt.Errorf("unsupported checker type %q", kind)
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
		return CheckMethodTCP
	case "udp":
		return CheckMethodUDP
	case "ping":
		return CheckMethodPing
	case "udpping":
		return CheckMethodUDPPing
	case "http":
		return CheckMethodHTTP
	case "none":
		return CheckMethodNone

	case "auto":
		return CheckMethodAuto
	}
	return 0
}

func (m Method) String() string {
	switch m {
	case CheckMethodTCP:
		return "tcp"
	case CheckMethodUDP:
		return "udp"
	case CheckMethodPing:
		return "ping"
	case CheckMethodUDPPing:
		return "udpping"
	case CheckMethodNone:
		return "none"
	case CheckMethodHTTP:
		return "http"
	case CheckMethodPassive:
		return "passive"
	case CheckMethodAuto:
		return "auto"
	default:
		return fmt.Sprintf("unknown(%d)", m)
	}
	return ""
}

func (m *Method) TranslateAuto(proto utils.IPProto) Method {
	switch proto {
	case utils.IPProtoTCP:
		return CheckMethodTCP
	case utils.IPProtoUDP:
		return CheckMethodUDPPing
	}
	return CheckMethodPing
}
