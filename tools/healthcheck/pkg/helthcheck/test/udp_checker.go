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
	"net"
	"os"
	"time"
)

func udpPortCheck(udpConn *net.UDPConn) (bool, error) {
	return true, nil
}

func Check(addr, network, send, recv string, timeout time.Duration) *Result {
	msg := fmt.Sprintf("UDP check to %s", addr)
	start := time.Now()
	if timeout == time.Duration(0) {
		timeout = 3
	}
	deadline := start.Add(timeout)

	dial := net.Dialer{Timeout: timeout}
	conn, err := dial.Dial(network, addr)
	if err != nil {
		msg = fmt.Sprintf("%s: failed to dail", msg)
		return NewResult(start, msg, false, err)
	}
	defer conn.Close()

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		msg = fmt.Sprintf("%s: not an UDP conn", msg)
		err = errors.New("failed to create udp socket")
		return NewResult(start, msg, false, err)
	}

	err = udpConn.SetDeadline(deadline)
	if err != nil {
		msg = fmt.Sprintf("%s: failed to set deadline", msg)
		return NewResult(start, msg, false, err)
	}

	if _, err = udpConn.Write([]byte(send)); err != nil {
		msg = fmt.Sprintf("%s: failed to send request", msg)
		return NewResult(start, msg, false, err)
	}

	buf := make([]byte, len(recv)+1)
	n, _, err := udpConn.ReadFrom(buf)
	if err != nil {
		if send == "" && recv == "" {
			if neterr, ok := err.(net.Error); ok {
				// When Send and Recv is none and  i/o timeout, the dest port state
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
	if got != recv {
		msg = fmt.Sprintf("%s: unexpected response %q", msg, got)
		return NewResult(start, msg, false, err)
	}
	msg = fmt.Sprintf("%s: succeed", msg)
	return NewResult(start, msg, true, err)
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
	if len(os.Args) != 6 {
		fmt.Printf("%s addr network send recv timeout\n", os.Args[0])
		return
	}
	timeout, _ := time.ParseDuration(os.Args[5])
	fmt.Println(Check(os.Args[1], os.Args[2], os.Args[3], os.Args[4], timeout))
}
