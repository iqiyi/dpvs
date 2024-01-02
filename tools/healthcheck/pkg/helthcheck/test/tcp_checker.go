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

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

func Check(addr, network, send, recv string, timeout time.Duration) *Result {
	msg := fmt.Sprintf("TCP connect to %s", addr)
	start := time.Now()
	if timeout == time.Duration(0) {
		timeout = 3 * time.Second
	}
	deadline := start.Add(timeout)

	dial := net.Dialer{
		Timeout: timeout,
	}
	conn, err := dial.Dial(network, addr)
	if err != nil {
		msg = fmt.Sprintf("%s: failed to dail", msg)
		return NewResult(start, msg, false, err)
	}
	defer conn.Close()

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		msg = fmt.Sprintf("%s: not a TCP conn", msg)
		err = errors.New("failed to create tcp socket")
		return NewResult(start, msg, false, err)
	}

	if send == "" && recv == "" {
		msg = fmt.Sprintf("%s: succeed", msg)
		return NewResult(start, msg, true, err)
	}

	err = tcpConn.SetDeadline(deadline)
	if err != nil {
		msg = fmt.Sprintf("%s: failed to set deadline", msg)
		return NewResult(start, msg, false, err)
	}

	if send != "" {
		err = writeFull(tcpConn, []byte(send))
		if err != nil {
			msg = fmt.Sprintf("%s: failed to send request", msg)
			return NewResult(start, msg, false, err)
		}
	}

	if recv != "" {
		buf := make([]byte, len(recv))
		n, err := io.ReadFull(tcpConn, buf)
		if err != nil {
			msg = fmt.Sprintf("%s: failed to read response", msg)
			return NewResult(start, msg, false, err)
		}
		got := string(buf[0:n])
		if got != recv {
			msg = fmt.Sprintf("%s: unexpected response %q", msg, got)
			return NewResult(start, msg, false, err)
		}
	}

	msg = fmt.Sprintf("%s: succeed", msg)
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

type Result struct {
	Message string
	Success bool
	time.Duration
	Err error
}

func (r *Result) String() string {
	msg := fmt.Sprintf("[result: %v, duration: %v] ", r.Success, r.Duration)
	if r.Err != nil {
		return msg + r.Err.Error()
	}
	return msg + r.Message
}

func NewResult(start time.Time, msg string, success bool, err error) *Result {
	duration := time.Since(start)
	return &Result{msg, success, duration, err}
}

func main() {
	fmt.Println(Check("192.168.88.30:80", "tcp4", "", "", 10*time.Second))
	fmt.Println(Check("192.168.88.30:80", "tcp4", "1", "cds1sfdafasdfasdfafafasssssssssssssssssssssssssss", 1*time.Second))
	fmt.Println(Check("192.168.88.31:80", "tcp4", "", "", 10*time.Second))
	fmt.Println(Check("10.130.133.208:80", "tcp4", "", "", 0))
	fmt.Println(Check("1.2.1.2:12123", "tcp4", "", "", 0))
	fmt.Println(Check("[2001::30]:80", "tcp6", "", "", 0))
	fmt.Println(Check("[2001::30]:80", "tcp6", "a", "HTTP", 0))
	fmt.Println(Check("[2001::33]:81", "tcp6", "", "", 0))
}
