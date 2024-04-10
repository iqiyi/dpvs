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
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck/pkg/utils"
)

// Id provides the unique identifier of a given healthcheck. It has format
// of {vs}/{rs}, where {vs} is service id confined by the lb_interface_type,
// and {vs} is the backend id within the service of format ip:proto:port.
// Id should be created using NewId() function.
type Id string

func NewId(vs string, rs *Target) *Id {
	id := Id(fmt.Sprintf("%s/%v", vs, rs))
	return &id
}

func (id Id) Vs() string {
	strId := string(id)
	idx := strings.LastIndexByte(strId, '/')
	if idx < 0 {
		return ""
	}
	return strId[:idx]
}

func (id Id) Rs() *Target {
	strId := string(id)
	idx := strings.LastIndexByte(strId, '/')
	if idx < 0 {
		return nil
	}
	return NewTargetFromStr(strId[idx+1:])
}

// CheckMethod is the interface that must be implemented by a healthcheck.
type CheckMethod interface {
	Check(target Target, timeout time.Duration) *Result
	BindConfig(conf *CheckerConfig)
	String() string
}

// State represents the current state of a healthcheck.
type State int

const (
	StateUnknown State = iota
	StateUnhealthy
	StateHealthy
)

var stateNames = map[State]string{
	StateUnknown:   "Unknown",
	StateUnhealthy: "Unhealthy",
	StateHealthy:   "Healthy",
}

// String returns the string representation for the given healthcheck state.
func (s State) String() string {
	if name, ok := stateNames[s]; ok {
		return name
	}
	return "<unknown>"
}

// Target specifies the target for a healthcheck.
type Target struct {
	IP    net.IP // IP address of the healthcheck target.
	Port  uint16
	Proto utils.IPProto
}

// Create a Target from str of format "IPv4:Proto:Port" or "[IPv6]:Proto:Port".
func NewTargetFromStr(str string) *Target {
	idx2 := strings.LastIndexByte(str, ':')
	idx1 := strings.LastIndexByte(str[:idx2], ':')
	if idx1 < 0 || idx2 < 0 || idx1 >= idx2 {
		return nil
	}
	port, err := strconv.ParseUint(str[idx2+1:], 10, 16)
	if err != nil {
		return nil
	}
	proto := utils.IPProtoFromStr(str[idx1+1 : idx2])
	if proto == 0 {
		return nil
	}
	ip := net.ParseIP(strings.TrimRight(strings.TrimLeft(str[:idx1], "["), "]"))
	if ip == nil {
		return nil
	}
	return &Target{ip, uint16(port), proto}
}

// String returns the string representation of a healthcheck target.
func (t Target) String() string {
	if t.IP.To4() != nil {
		return fmt.Sprintf("%v:%v:%d", t.IP, t.Proto, t.Port)
	}
	return fmt.Sprintf("[%v]:%v:%d", t.IP, t.Proto, t.Port)
}

func (t *Target) Equal(t2 *Target) bool {
	if t2 == nil {
		return false
	}
	if t.Port != t2.Port || t.Proto != t2.Proto {
		return false
	}
	return t.IP.Equal(t2.IP)
}

// Addr returns the IP:Port representation of a healthcheck target
func (t Target) Addr() string {
	if t.IP.To4() != nil {
		return fmt.Sprintf("%v:%d", t.IP, t.Port)
	}
	return fmt.Sprintf("[%v]:%d", t.IP, t.Port)
}

// Network returns the network name for the healthcheck target.
func (t *Target) Network() string {
	var network string
	version := 4
	if t.IP.To4() == nil {
		version = 6
	}
	switch t.Proto {
	case utils.IPProtoICMP:
		network = "ip4:icmp"
	case utils.IPProtoICMPv6:
		network = "ip6:ipv6-icmp"
	case utils.IPProtoTCP:
		network = fmt.Sprintf("tcp%d", version)
	case utils.IPProtoUDP:
		network = fmt.Sprintf("udp%d", version)
	default:
		return "(unknown)"
	}
	return network
}

// Result stores the result of a healthcheck performed by a checker.
type Result struct {
	Message string
	Success bool
	time.Duration
	Err error
}

// String returns the string representation of a healthcheck result.
func (r *Result) String() string {
	msg := fmt.Sprintf("[result: %v, duration: %v] ", r.Success, r.Duration)
	if r.Err != nil {
		return msg + r.Err.Error()
	}
	return msg + r.Message
}

func NewResult(start time.Time, msg string, success bool, err error) *Result {
	// TODO: Make this clock skew safe.
	duration := time.Since(start)
	return &Result{msg, success, duration, err}
}

// Status represents the current status of a healthcheck instance.
type Status struct {
	Version   uint64 // the vs version
	LastCheck time.Time
	Duration  time.Duration
	Failures  uint64
	Successes uint64
	State
	Weight  uint16
	Message string
}

// Notification stores a status notification for a healthcheck.
type Notification struct {
	Id
	Target
	Status
}

// String returns the string representation for the given notification.
func (n *Notification) String() string {
	return fmt.Sprintf("ID %v, Version %d, %v, Weight %d, Fail %v, Success %v, Last check %s in %v",
		n.Id, n.Version, stateNames[n.Status.State], n.Status.Weight, n.Status.Failures,
		n.Status.Successes, n.Status.LastCheck.Format("2006-01-02 15:04:05.000"), n.Status.Duration)
}
