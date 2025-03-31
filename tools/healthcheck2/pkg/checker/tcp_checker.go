package checker

/*
TCP Checker Params:
-----------------------------------
name                value
-----------------------------------
send                non-empty string
receive             non-empty string
prxoy-protocol      v1 | v2
------------------------------------
*/

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var _ CheckMethod = (*TCPChecker)(nil)

type TCPChecker struct {
	send       string
	receive    string
	proxyProto string // "v1", "v2"
}

func init() {
	registerMethod(CheckMethodTCP, &TCPChecker{})
}

func (c *TCPChecker) Check(target *utils.L3L4Addr, timeout time.Duration) (types.State, error) {
	if timeout <= time.Duration(0) {
		return types.Unknown, fmt.Errorf("zero timeout on TCP check")
	}

	network := target.Network()
	addr := target.Addr()
	glog.V(9).Infof("Start TCP check to %s ...", addr)

	start := time.Now()
	deadline := start.Add(timeout)

	dial := net.Dialer{
		Timeout: timeout,
	}
	conn, err := dial.Dial(network, addr)
	if err != nil {
		glog.V(9).Infof("TCP check %v %v: failed to dial", addr, types.Unhealthy)
		return types.Unhealthy, nil
	}
	defer conn.Close()

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		glog.V(9).Infof("TCP check %v %v: failed to create tcp socket", addr, types.Unhealthy)
		return types.Unhealthy, nil
	}

	if len(c.send) == 0 && len(c.receive) == 0 {
		glog.V(9).Infof("TCP check %v %v: succeed", addr, types.Healthy)
		return types.Healthy, nil
	}

	err = tcpConn.SetDeadline(deadline)
	if err != nil {
		glog.V(9).Infof("TCP check %v %v: failed to set deadline", addr, types.Unhealthy)
		return types.Unhealthy, nil
	}

	if "v2" == c.proxyProto {
		if err = utils.WriteFull(tcpConn, proxyProtoV2LocalCmd); err != nil {
			glog.V(9).Infof("TCP check %v %v: failed to send proxy protocol v2 data",
				addr, types.Unhealthy)
			return types.Unhealthy, nil
		}
	} else if "v1" == c.proxyProto {
		if err = utils.WriteFull(tcpConn, []byte(proxyProtoV1LocalCmd)); err != nil {
			glog.V(9).Infof("TCP check %v %v: failed to send proxy protocol v1 data",
				addr, types.Unhealthy)
			return types.Unhealthy, nil
		}
	}

	if len(c.send) > 0 {
		if err = utils.WriteFull(tcpConn, []byte(c.send)); err != nil {
			glog.V(9).Infof("TCP check %v %v: failed to send request", addr, types.Unhealthy)
			return types.Unhealthy, nil
		}
	}

	if len(c.receive) > 0 {
		buf := make([]byte, len(c.receive))
		n, err := io.ReadFull(tcpConn, buf)
		if err != nil {
			glog.V(9).Infof("TCP check %v %v: failed to read response", addr, types.Unhealthy)
			return types.Unhealthy, nil
		}
		got := string(buf[:n])
		if got != c.receive {
			glog.V(9).Infof("TCP check %v %v: unexpected response", addr, types.Unhealthy)
			return types.Unhealthy, nil
		}
	}

	glog.V(9).Infof("TCP check %v %v: succeed", addr, types.Healthy)
	return types.Healthy, nil
}

func (c *TCPChecker) validate(params map[string]string) error {
	unsupported := make([]string, 0, len(params))
	for param, val := range params {
		switch param {
		case "send":
			if len(val) == 0 {
				return fmt.Errorf("empty tcp checker param: %s", param)
			}
		case "receive":
			if len(val) == 0 {
				return fmt.Errorf("empty tcp checker param: %s", param)
			}
		case ParamProxyProto:
			val = strings.ToLower(val)
			if val != "v1" && val != "v2" {
				return fmt.Errorf("invalid tcp checker param value: %s:%s", param, params[param])
			}
		default:
			unsupported = append(unsupported, param)
		}
	}

	if len(unsupported) > 0 {
		return fmt.Errorf("unsupported tcp checker params: %q", strings.Join(unsupported, ","))
	}
	return nil
}

func (c *TCPChecker) create(params map[string]string) (CheckMethod, error) {
	if err := c.validate(params); err != nil {
		return nil, fmt.Errorf("tcp checker param validation failed: %v", err)
	}

	checker := &TCPChecker{}

	if val, ok := params["send"]; ok {
		c.send = val
	}
	if val, ok := params["receive"]; ok {
		c.receive = val
	}
	if val, ok := params[ParamProxyProto]; ok {
		c.proxyProto = val
	}
	return checker, nil
}
