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
	"io"
	"net"
	"strings"
	"time"
)

var _ CheckMethod = (*TCPChecker)(nil)

// TCPChecker contains configuration specific to a TCP healthcheck.
type TCPChecker struct {
	Config *CheckerConfig

	Receive    string
	Send       string
	ProxyProto int // proxy protocol: 0 - close, 1 - version 1, 2 - version 2
}

// NewTCPChecker returns an initialised TCPChecker.
func NewTCPChecker(recv, send string, proxyProto int) *TCPChecker {
	return &TCPChecker{
		Receive:    recv,
		Send:       send,
		ProxyProto: proxyProto,
	}
}

func (hc *TCPChecker) BindConfig(conf *CheckerConfig) {
	hc.Config = conf
}

// String returns the string representation of a TCP healthcheck.
func (hc *TCPChecker) String() string {
	return fmt.Sprintf("TCP checker for %v", hc.Config.Id)
}

// Check executes a TCP healthcheck.
func (hc *TCPChecker) Check(target Target, timeout time.Duration) *Result {
	msg := fmt.Sprintf("TCP connect to %s", target.Addr())
	start := time.Now()
	if timeout == time.Duration(0) {
		timeout = DefaultCheckConfig.Timeout
	}
	deadline := start.Add(timeout)

	dial := net.Dialer{
		Timeout: timeout,
	}
	conn, err := dial.Dial(target.Network(), target.Addr())
	if err != nil {
		msg = fmt.Sprintf("%s: failed to dail", msg)
		return NewResult(start, msg, false, err)
	}
	defer conn.Close()

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		msg = fmt.Sprintf("%s: failed to create tcp socket", msg)
		return NewResult(start, msg, false, err)
	}

	if hc.Send == "" && hc.Receive == "" {
		msg = fmt.Sprintf("%s succeed", msg)
		return NewResult(start, msg, true, err)
	}

	err = tcpConn.SetDeadline(deadline)
	if err != nil {
		msg = fmt.Sprintf("%s: failed to set deadline", msg)
		return NewResult(start, msg, false, err)
	}

	if 2 == hc.ProxyProto {
		n, err := bytes.NewReader(proxyProtoV2LocalCmd).WriteTo(tcpConn)
		if err != nil || n < int64(len(proxyProtoV2LocalCmd)) {
			msg = fmt.Sprintf("%s: failed to send proxy protocol v2 data", msg)
			return NewResult(start, msg, false, err)
		}
	} else if 1 == hc.ProxyProto {
		n, err := strings.NewReader(proxyProtoV1LocalCmd).WriteTo(tcpConn)
		if err != nil || n < int64(len(proxyProtoV1LocalCmd)) {
			msg = fmt.Sprintf("%s: failed to send proxy protocol v1 data", msg)
			return NewResult(start, msg, false, err)
		}
	}

	if hc.Send != "" {
		err = writeFull(tcpConn, []byte(hc.Send))
		if err != nil {
			msg = fmt.Sprintf("%s: failed to send request", msg)
			return NewResult(start, msg, false, err)
		}
	}

	if hc.Receive != "" {
		buf := make([]byte, len(hc.Receive))
		n, err := io.ReadFull(tcpConn, buf)
		if err != nil {
			msg = fmt.Sprintf("%s: failed to read response", msg)
			return NewResult(start, msg, false, err)
		}
		got := string(buf[0:n])
		if got != hc.Receive {
			msg = fmt.Sprintf("%s: unexpected response %q", msg, got)
			return NewResult(start, msg, false, err)
		}
	}

	msg = fmt.Sprintf("%s succeed", msg)
	return NewResult(start, msg, true, err)
}

func writeFull(conn net.Conn, b []byte) error {
	for len(b) > 0 {
		n, err := conn.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}
