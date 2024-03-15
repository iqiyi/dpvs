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

// ICMP ping healthcheck implementation.

package hc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/iqiyi/dpvs/tools/healthcheck/pkg/utils"
)

var _ CheckMethod = (*PingChecker)(nil)

var nextPingCheckerID uint16

func init() {
	s := rand.NewSource(int64(os.Getpid()))
	nextPingCheckerID = uint16(s.Int63() & 0xffff)
}

// PingChecker contains configuration specific to a ping healthcheck.
type PingChecker struct {
	Config *CheckerConfig

	ID     uint16
	Seqnum uint16
}

// NewPingChecker returns an initialised PingChecker.
func NewPingChecker() *PingChecker {
	checker := PingChecker{ID: nextPingCheckerID}
	nextPingCheckerID++
	return &checker
}

func (hc *PingChecker) BindConfig(conf *CheckerConfig) {
	hc.Config = conf
}

// String returns the string representation of a Ping healthcheck.
func (hc *PingChecker) String() string {
	return fmt.Sprintf("PING checker for %s", hc.Config.Id)
}

// Check executes a ping healthcheck.
func (hc *PingChecker) Check(target Target, timeout time.Duration) *Result {
	msg := fmt.Sprintf("ICMP ping to host %v", target.IP)
	if target.IP.To4() != nil {
		target.Proto = utils.IPProtoICMP
	} else {
		target.Proto = utils.IPProtoICMPv6
	}
	seq := hc.Seqnum
	hc.Seqnum++
	echo := newICMPEchoRequest(target.Proto, hc.ID, seq, 64, []byte("Healthcheck"))
	start := time.Now()
	if timeout == time.Duration(0) {
		timeout = DefaultCheckConfig.Timeout
	}
	err := exchangeICMPEcho(target.Network(), target.IP, timeout, echo)
	success := err == nil
	if err != nil {
		err = fmt.Errorf("ping target %v, %v", target.IP, err)
	}
	return NewResult(start, msg, success, err)
}

// NB: The code below borrows heavily from pkg/net/ipraw_test.go.

type icmpMsg []byte

const (
	ICMP4_ECHO_REQUEST = 8
	ICMP4_ECHO_REPLY   = 0
	ICMP6_ECHO_REQUEST = 128
	ICMP6_ECHO_REPLY   = 129
)

func newICMPEchoRequest(proto utils.IPProto, id, seqnum, msglen uint16, filler []byte) icmpMsg {
	switch proto {
	case utils.IPProtoICMP:
		return newICMPv4EchoRequest(id, seqnum, msglen, filler)
	case utils.IPProtoICMPv6:
		return newICMPv6EchoRequest(id, seqnum, msglen, filler)
	}
	return nil
}

func newICMPv4EchoRequest(id, seqnum, msglen uint16, filler []byte) icmpMsg {
	msg := newICMPInfoMessage(id, seqnum, msglen, filler)
	msg[0] = ICMP4_ECHO_REQUEST
	cs := icmpChecksum(msg)
	// place checksum back in header; using ^= avoids the assumption that the
	// checksum bytes are zero
	cs ^= binary.BigEndian.Uint16(msg[2:4])
	binary.BigEndian.PutUint16(msg[2:4], cs)
	return msg
}

func icmpChecksum(msg icmpMsg) uint16 {
	cklen := len(msg)
	s := uint32(0)
	for i := 0; i < cklen-1; i += 2 {
		s += uint32(binary.BigEndian.Uint16(msg[i : i+2]))
	}
	if cklen&1 == 1 {
		s += uint32(msg[cklen-1]) << 8
	}
	s = (s >> 16) + (s & 0xffff)
	s += (s >> 16)
	return uint16(^s)
}

func newICMPv6EchoRequest(id, seqnum, msglen uint16, filler []byte) icmpMsg {
	msg := newICMPInfoMessage(id, seqnum, msglen, filler)
	msg[0] = ICMP6_ECHO_REQUEST
	// Note: For IPv6, the OS will compute and populate the ICMP checksum bytes.
	return msg
}

func newICMPInfoMessage(id, seqnum, msglen uint16, filler []byte) icmpMsg {
	b := make([]byte, msglen)
	copy(b[8:], bytes.Repeat(filler, (int(msglen)-8)/(len(filler)+1)))
	b[0] = 0                    // type
	b[1] = 0                    // code
	b[2] = 0                    // checksum
	b[3] = 0                    // checksum
	b[4] = uint8(id >> 8)       // identifier
	b[5] = uint8(id & 0xff)     // identifier
	b[6] = uint8(seqnum >> 8)   // sequence number
	b[7] = uint8(seqnum & 0xff) // sequence number
	return b
}

func parseICMPEchoReply(msg icmpMsg) (id, seqnum, chksum uint16) {
	id = uint16(msg[4])<<8 | uint16(msg[5])
	seqnum = uint16(msg[6])<<8 | uint16(msg[7])
	chksum = uint16(msg[2])<<8 | uint16(msg[3])
	return
}

func exchangeICMPEcho(network string, ip net.IP, timeout time.Duration, echo icmpMsg) error {
	c, err := net.ListenPacket(network, "")
	if err != nil {
		return err
	}
	defer c.Close()

	_, err = c.WriteTo(echo, &net.IPAddr{IP: ip})
	if err != nil {
		return err
	}

	c.SetDeadline(time.Now().Add(timeout))
	reply := make([]byte, 256)
	for {
		n, addr, err := c.ReadFrom(reply)
		if err != nil {
			return err
		}
		if n < 0 || n > len(reply) {
			return fmt.Errorf("Unexpect ICMP reply len %d", n)
		}
		if !ip.Equal(net.ParseIP(addr.String())) {
			continue
		}
		if reply[0] != ICMP4_ECHO_REPLY && reply[0] != ICMP6_ECHO_REPLY {
			continue
		}
		xid, xseqnum, _ := parseICMPEchoReply(echo)
		rid, rseqnum, rchksum := parseICMPEchoReply(reply)
		if rid != xid || rseqnum != xseqnum {
			continue
		}
		if reply[0] == ICMP4_ECHO_REPLY {
			cs := icmpChecksum(reply[:n])
			if cs != 0 {
				return fmt.Errorf("Bad ICMP checksum: %x, len: %d, data: %v", rchksum, n, reply[:n])
			}
		}
		// TODO(angusc): Validate checksum for IPv6
		break
	}
	return nil
}
