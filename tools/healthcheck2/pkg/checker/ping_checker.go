package checker

/*
Ping Checker Params: None
*/

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/golang/glog"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/types"
	"github.com/iqiyi/dpvs/tools/healthcheck2/pkg/utils"
)

var _ CheckMethod = (*PingChecker)(nil)

var nextPingCheckerId uint16

type PingChecker struct {
	id     uint16
	seqnum uint16
}

func init() {
	registerMethod(CheckMethodPing, &PingChecker{})

	s := rand.NewSource(int64(os.Getpid()))
	nextPingCheckerId = uint16(s.Int63() & 0xffff)
}

func (c *PingChecker) Check(target *utils.L3L4Addr, timeout time.Duration) (types.State, error) {
	if timeout <= time.Duration(0) {
		return types.Unknown, fmt.Errorf("zero timeout on Ping check")
	}

	targetCopied := target.DeepCopy()
	if targetCopied.IP.To4() != nil {
		targetCopied.Proto = utils.IPProtoICMP
	} else {
		targetCopied.Proto = utils.IPProtoICMPv6
	}
	glog.V(9).Infof("Start Ping check to %v ...", targetCopied.IP)

	c.seqnum++
	echo := newICMPEchoRequest(targetCopied.Proto, c.id, c.seqnum, 64, []byte("DPVS Healthcheck "))
	if err := exchangeICMPEcho(targetCopied.Network(), targetCopied.IP, timeout, echo); err != nil {
		glog.V(9).Infof("Ping check %v %v: failed due to %v", targetCopied.IP, types.Unhealthy, err)
		return types.Unhealthy, nil
	}

	glog.V(9).Infof("Ping check %v %v: succeed", targetCopied.IP, types.Healthy)
	return types.Healthy, nil
}

func (c *PingChecker) validate(params map[string]string) error {
	if len(params) > 0 {
		return fmt.Errorf("unsupported ping checker params: %v", params)
	}
	return nil
}

func (c *PingChecker) create(params map[string]string) (CheckMethod, error) {
	if err := c.validate(params); err != nil {
		return nil, fmt.Errorf("ping checker param validation failed: %v", err)
	}

	checker := &PingChecker{
		id:     nextPingCheckerId,
		seqnum: 0,
	}
	nextPingCheckerId++

	return checker, nil
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

	c.SetDeadline(time.Now().Add(timeout))

	_, err = c.WriteTo(echo, &net.IPAddr{IP: ip})
	if err != nil {
		return err
	}

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
