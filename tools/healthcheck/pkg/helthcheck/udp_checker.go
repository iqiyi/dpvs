// Copyright 2023 IQiYi Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// The healthcheck package refers to the framework of "github.com/google/
// seesaw/healthcheck" heavily, with only some adaption changes for DPVS.

package hc

import (
	"bytes"
	"fmt"
	"net"
	"time"
)

var _ CheckMethod = (*UDPChecker)(nil)

// UDPChecker contains configuration specific to a UDP healthcheck.
type UDPChecker struct {
	Config *CheckerConfig

	Receive    string
	Send       string
	ProxyProto int // proxy protocol: 0 - close, 2 - version 2
}

// NewUDPChecker returns an initialised UDPChecker.
func NewUDPChecker(recv, send string, proxyProto int) *UDPChecker {
	return &UDPChecker{
		Receive:    recv,
		Send:       send,
		ProxyProto: proxyProto,
	}
}

func (hc *UDPChecker) BindConfig(conf *CheckerConfig) {
	hc.Config = conf
}

// String returns the string representation of a UDP healthcheck.
func (hc *UDPChecker) String() string {
	return fmt.Sprintf("UDP checker for %v", hc.Config.Id)
}

// Check executes an UDP healthcheck.
func (hc *UDPChecker) Check(target Target, timeout time.Duration) *Result {
	msg := fmt.Sprintf("UDP check to %s", target.Addr())
	start := time.Now()
	if timeout == time.Duration(0) {
		timeout = DefaultCheckConfig.Timeout
	}
	deadline := start.Add(timeout)

	dial := net.Dialer{Timeout: timeout}
	conn, err := dial.Dial(target.Network(), target.Addr())
	if err != nil {
		msg = fmt.Sprintf("%s: failed to dail", msg)
		return NewResult(start, msg, false, err)
	}
	defer conn.Close()

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		msg = fmt.Sprintf("%s: failed to create udp socket", msg)
		return NewResult(start, msg, false, err)
	}

	err = udpConn.SetDeadline(deadline)
	if err != nil {
		msg = fmt.Sprintf("%s: failed to set deadline", msg)
		return NewResult(start, msg, false, err)
	}

	if 2 == hc.ProxyProto {
		n, err := bytes.NewReader(proxyProtoV2LocalCmd).WriteTo(udpConn)
		if err != nil || n < int64(len(proxyProtoV2LocalCmd)) {
			msg = fmt.Sprintf("%s: failed to send proxy protocol v2 data", msg)
			return NewResult(start, msg, false, err)
		}
	}

	if _, err = udpConn.Write([]byte(hc.Send)); err != nil {
		msg = fmt.Sprintf("%s: failed to send request", msg)
		return NewResult(start, msg, false, err)
	}

	buf := make([]byte, len(hc.Receive))
	n, _, err := udpConn.ReadFrom(buf)
	if err != nil {
		if hc.Send == "" && hc.Receive == "" {
			if neterr, ok := err.(net.Error); ok {
				// When hc.Send and hc.Receive is none and  i/o timeout, the dest port state
				// is undetermined. Check shall return success in the case.
				if neterr.Timeout() {
					msg = fmt.Sprintf("%s: %s, port state unkown", msg, err)
					return NewResult(start, msg, true, nil)
				}
			}
		}
		msg = fmt.Sprintf("%s: failed to read response", msg)
		return NewResult(start, msg, false, err)
	}

	got := string(buf[0:n])
	if got != hc.Receive {
		msg = fmt.Sprintf("%s: unexpected response %q", msg, got)
		return NewResult(start, msg, false, err)
	}
	msg = fmt.Sprintf("%s: succeed", msg)
	return NewResult(start, msg, true, err)
}
