package cid

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
)

const (
	QUIC_CID_BUF_LEN         = 20
	DPVS_QUIC_DCID_BYTES_MIN = 7
)

func QuicCIDGenerator(
	cidLen uint8, // the total length of CID to be generated, 7~20 bytes
	l3len uint8, // the length of server IP to encode into CID, 1~8 bytes
	l4len uint8, // the length of server Port to encode into CID, 0 or 2 bytes
	svrIP net.IP, // the server IP
	svrPort uint16, // the server Port
) (error, []byte) {
	rdbuf := make([]byte, QUIC_CID_BUF_LEN)
	var i uint8
	var l3addr []byte
	var l4addr uint16

	if cidLen < DPVS_QUIC_DCID_BYTES_MIN || l3len > 8 || l3len < 1 ||
		(l4len != 0 && l4len != 2) ||
		cidLen < l3len+l4len+5 {
		return fmt.Errorf("invalid params"), nil
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
			return fmt.Errorf("invalid IP %v", svrIP), nil
		}
		l3addr = ipbytes[16-l3len:]
	}
	l4addr = svrPort

	if _, err := io.ReadFull(rand.Reader, rdbuf[:entropy]); err != nil {
		return err, nil
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

	return nil, cid
}
