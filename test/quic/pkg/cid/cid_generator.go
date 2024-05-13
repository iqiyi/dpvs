package cid

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"

	quic "github.com/quic-go/quic-go"
)

const (
	QUIC_CID_BUF_LEN         = 20
	DPVS_QUIC_DCID_BYTES_MIN = 7
)

type DpvsQCID struct {
	cidLen  uint8
	l3len   uint8
	l4len   uint8
	svrIP   net.IP
	svrPort uint16
}

var _ quic.ConnectionIDGenerator = (*DpvsQCID)(nil)

func NewDpvsQCID(cidLen, l3len, l4len uint8,
	svrIP net.IP, svrPort uint16) *DpvsQCID {
	if cidLen < DPVS_QUIC_DCID_BYTES_MIN {
		cidLen = DPVS_QUIC_DCID_BYTES_MIN
	}
	if l3len < 1 {
		l3len = 1
	} else if l3len > 8 {
		l3len = 8
	}
	if l4len > 0 {
		l4len = 2
	}
	if svrIP == nil {
		svrIP, _ = FindLocalIP("")
	}

	return &DpvsQCID{
		cidLen:  cidLen,
		l3len:   l3len,
		l4len:   l4len,
		svrIP:   svrIP,
		svrPort: svrPort,
	}
}

func (dqcid *DpvsQCID) ConnectionIDLen() int {
	return int(dqcid.cidLen)
}

func (dqcid *DpvsQCID) GenerateConnectionID() (quic.ConnectionID, error) {
	data, err := QuicCIDGeneratorFunction(dqcid.cidLen, dqcid.l3len,
		dqcid.l4len, dqcid.svrIP, dqcid.svrPort)
	if err != nil {
		data = make([]byte, dqcid.cidLen)
		rand.Read(data[:])
	}
	return quic.ConnectionIDFromBytes(data), err
}

func QuicCIDGeneratorFunction(
	cidLen uint8, // the total length of CID to be generated, 7~20 bytes
	l3len uint8, // the length of server IP to encode into CID, 1~8 bytes
	l4len uint8, // the length of server Port to encode into CID, 0 or 2 bytes
	svrIP net.IP, // the server IP
	svrPort uint16, // the server Port
) ([]byte, error) {
	rdbuf := make([]byte, QUIC_CID_BUF_LEN)
	var i uint8
	var l3addr []byte
	var l4addr uint16

	if svrIP == nil ||
		cidLen < DPVS_QUIC_DCID_BYTES_MIN ||
		l3len > 8 || l3len < 1 ||
		(l4len != 0 && l4len != 2) ||
		cidLen < l3len+l4len+5 {
		return nil, fmt.Errorf("invalid params")
	}

	entropy := cidLen - l3len - l4len + 1
	l4flag := 0
	if l4len > 0 {
		l4flag = 1
	}

	ipbytes := svrIP.To4()
	if ipbytes != nil {
		l3addr = ipbytes[4-l3len:]
	} else {
		ipbytes = svrIP.To16()
		if ipbytes == nil {
			return nil, fmt.Errorf("invalid IP %v", svrIP)
		}
		l3addr = ipbytes[16-l3len:]
	}
	l4addr = svrPort

	if _, err := io.ReadFull(rand.Reader, rdbuf[:entropy]); err != nil {
		return nil, err
	}

	cid := make([]byte, cidLen, cidLen)
	cid[0] = rdbuf[0]
	cid[1] = uint8(((l3len-1)&0x7)<<5) | uint8((l4flag&0x1)<<4) | ((uint8(l3addr[0]) >> 4) & 0xf)
	for i = 0; i < l3len; i++ {
		if i == l3len-1 {
			cid[2+i] = ((l3addr[0] & 0xf) << 4)
		} else {
			cid[2+i] = ((l3addr[0] & 0xf) << 4) | ((l3addr[1] >> 4) & 0xf)
		}
		l3addr = l3addr[1:]
	}
	if l4len > 0 {
		cid[l3len+1] &= 0xf0
		cid[l3len+1] |= byte((l4addr >> 12) & 0xf)
		l4addr <<= 4
		cid[l3len+2] = byte((l4addr >> 8) & 0xff)
		cid[l3len+3] = byte(l4addr & 0xff)
	}
	cid[l3len+l4len+1] |= (rdbuf[1] & 0xf)
	copy(cid[l3len+l4len+2:], rdbuf[2:entropy-1])

	return cid, nil
}
