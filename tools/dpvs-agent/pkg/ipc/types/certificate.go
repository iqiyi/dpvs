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

package types

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unsafe"

	"github.com/hashicorp/go-hclog"
	"golang.org/x/sys/unix"

	"github.com/dpvs-agent/pkg/ipc/pool"
)

type CertificateAuthoritySpec struct {
	src     [0x10]byte
	dst     [0x10]byte
	af      uint32
	fwmark  uint32
	port    uint16
	proto   uint8
	padding uint8
}

type CertificateAuthorityFront struct {
	count uint32
}

func NewCertificateAuthoritySpec() *CertificateAuthoritySpec {
	return &CertificateAuthoritySpec{}
}

func NewCertificateAuthorityFront() *CertificateAuthorityFront {
	return &CertificateAuthorityFront{}
}

func (o *CertificateAuthoritySpec) Copy(src *CertificateAuthoritySpec) bool {
	o.af = src.af
	o.fwmark = src.fwmark
	o.port = src.port
	o.proto = src.proto
	copy(o.src[:], src.src[:])
	copy(o.dst[:], src.dst[:])
	return true
}

func (o *CertificateAuthoritySpec) ParseVipPortProto(vipport string) error {
	items := strings.Split(vipport, "-")
	if len(items) != 3 {
		return errors.New("invalid vip-port-proto string")
	}

	proto := items[2]

	switch strings.ToLower(proto) {
	case "udp":
		o.proto = unix.IPPROTO_UDP
	case "tcp":
		fallthrough
	default:
		o.proto = unix.IPPROTO_TCP
	}

	// port := items[1]
	port, err := strconv.Atoi(items[1])
	if err != nil {
		return err
	}
	o.SetPort(uint16(port))

	vip := items[0]
	if net.ParseIP(vip) == nil {
		return errors.New(fmt.Sprintf("invalid ip addr: %s\n", vip))
	}

	o.SetDst(vip)

	return nil
}

func (o *CertificateAuthorityFront) Copy(src *CertificateAuthorityFront) bool {
	o.count = src.count
	return true
}

func (o *CertificateAuthoritySpec) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*o))
}

func (o *CertificateAuthorityFront) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*o))
}

func (o *CertificateAuthoritySpec) Dump(buf []byte) bool {
	if len(buf) != int(o.Sizeof()) {
		return false
	}

	var tmp *CertificateAuthoritySpec = *(**CertificateAuthoritySpec)(unsafe.Pointer(&buf))

	return o.Copy(tmp)
}

func (o *CertificateAuthorityFront) Dump(buf []byte) bool {
	if len(buf) != int(o.Sizeof()) {
		return false
	}

	var tmp *CertificateAuthorityFront = *(**CertificateAuthorityFront)(unsafe.Pointer(&buf))

	return o.Copy(tmp)
}

func (o *CertificateAuthoritySpec) Package() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, o)
	return buf.Bytes()
}

func (o *CertificateAuthorityFront) Package() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, o)
	return buf.Bytes()
}

func (o *CertificateAuthorityFront) SetCount(count uint32) {
	o.count = count
}

func (o *CertificateAuthorityFront) GetCount() uint32 {
	return o.count
}

func (o *CertificateAuthoritySpec) SetAf(af uint32) {
	o.af = af
}

func (o *CertificateAuthoritySpec) SetSrc(addr string) {
	if strings.Contains(addr, ":") {
		o.SetAf(unix.AF_INET6)
		copy(o.src[:], net.ParseIP(addr))
		return
	}
	o.SetAf(unix.AF_INET)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, net.ParseIP(addr))
	copy(o.src[:], buf.Bytes()[12:])
}

func (o *CertificateAuthoritySpec) SetDst(addr string) {
	if strings.Contains(addr, ":") {
		o.SetAf(unix.AF_INET6)
		copy(o.dst[:], net.ParseIP(addr))
		return
	}
	o.SetAf(unix.AF_INET)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, net.ParseIP(addr))
	copy(o.dst[:], buf.Bytes()[12:])
}

func (o *CertificateAuthoritySpec) SetFwmark(fwmark uint32) {
	o.fwmark = fwmark
}

func (o *CertificateAuthoritySpec) SetPort(port uint16) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(port))
	o.port = binary.BigEndian.Uint16(buf.Bytes())
}

func (o *CertificateAuthoritySpec) SetProto(proto string) {
	switch strings.ToLower(proto) {
	case "udp":
		o.proto = unix.IPPROTO_UDP
	default:
		o.proto = unix.IPPROTO_TCP
	}
}

func (o *CertificateAuthorityFront) read(conn *pool.Conn, len uint64, logger hclog.Logger) ([]*CertificateAuthorityFront, error) {
	res := len % o.Sizeof()
	cnt := len / o.Sizeof()
	if cnt <= 0 || res != 0 {
		conn.Release(int(len))
		return nil, errors.New("Wrong buffer size to read, may not convert to CertificateAuthorityFront")
	}

	fronts := make([]*CertificateAuthorityFront, cnt)

	for i := 0; i < int(cnt); i++ {
		fronts[i] = NewCertificateAuthorityFront()
		buf, err := conn.ReadN(int(o.Sizeof()))
		if err != nil {
			continue
		}
		fronts[i].Dump(buf)
	}

	return fronts, nil
}

func (o *CertificateAuthoritySpec) read(conn *pool.Conn, len uint64, logger hclog.Logger) ([]*CertificateAuthoritySpec, error) {
	res := len % o.Sizeof()
	cnt := len / o.Sizeof()
	if cnt <= 0 || res != 0 {
		conn.Release(int(len))
		return nil, errors.New("Wrong buffer size to read, may not convert to CertificateAuthoritySpec")
	}

	calst := make([]*CertificateAuthoritySpec, cnt)
	for i := 0; i < int(cnt); i++ {
		calst[i] = NewCertificateAuthoritySpec()

		buf, err := conn.ReadN(int(o.Sizeof()))
		if err != nil {
			continue
		}
		calst[i].Dump(buf)
	}

	return calst, nil
}

func (o *CertificateAuthoritySpec) write(conn *pool.Conn, logger hclog.Logger) error {
	buf := o.Package()
	_, err := conn.WriteN(buf, int(o.Sizeof()))
	if err != nil {
		return err
	}
	return nil
}

func (o *CertificateAuthoritySpec) Add(cp *pool.ConnPool, blk bool, logger hclog.Logger) DpvsErrType {
	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed:", err.Error())
		return EDPVS_IO
	}
	defer cp.Remove(ctx, conn, nil)

	var ADD uint32
	SOCKOPT_STRING := "SOCKOPT_SET_BLKLST_ADD"
	ADD = SOCKOPT_SET_BLKLST_ADD
	if !blk {
		SOCKOPT_STRING = "SOCKOPT_SET_WHTLST_ADD"
		ADD = SOCKOPT_SET_WHTLST_ADD
	}

	msg := NewSockMsg(SOCKOPT_VERSION, ADD, SOCKOPT_SET, o.Sizeof())
	err = msg.Write(conn)
	if err != nil {
		logger.Error(fmt.Sprintf("Sockopt %s Write proto header Error: %s", SOCKOPT_STRING, err.Error()))
		return EDPVS_IO
	}
	err = o.write(conn, logger)
	if err != nil {
		logger.Error(fmt.Sprintf("Sockopt %s Write specific auth user Error: %s", SOCKOPT_STRING, err.Error()))
		return EDPVS_IO
	}

	reply := NewReplySockMsg()
	err = reply.Read(conn)
	if err != nil {
		logger.Error(fmt.Sprintf("Sockopt %s reply msg Read Error: %s", SOCKOPT_STRING, err.Error()))
		return EDPVS_IO
	}

	errCode := reply.GetErrCode()
	logger.Info(fmt.Sprintf("Sockopt %s Done:%s", SOCKOPT_STRING, errCode.String()))
	return errCode
}

func (o *CertificateAuthoritySpec) Del(cp *pool.ConnPool, blk bool, logger hclog.Logger) DpvsErrType {
	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed:", err.Error())
		return EDPVS_IO
	}
	defer cp.Remove(ctx, conn, nil)

	var DEL uint32
	SOCKOPT_STRING := "SOCKOPT_SET_BLKLST_DEL"
	DEL = SOCKOPT_SET_BLKLST_DEL
	if !blk {
		SOCKOPT_STRING = "SOCKOPT_SET_WHTLST_DEL"
		DEL = SOCKOPT_SET_WHTLST_DEL
	}

	msg := NewSockMsg(SOCKOPT_VERSION, DEL, SOCKOPT_SET, o.Sizeof())
	err = msg.Write(conn)
	if err != nil {
		logger.Error(fmt.Sprintf("Sockopt %s Write proto header Error: %s", SOCKOPT_STRING, err.Error()))
		return EDPVS_IO
	}
	err = o.write(conn, logger)
	if err != nil {
		logger.Error(fmt.Sprintf("Sockopt %s Write specific auth user Error: %s", SOCKOPT_STRING, err.Error()))
		return EDPVS_IO
	}

	reply := NewReplySockMsg()
	err = reply.Read(conn)
	if err != nil {
		logger.Error(fmt.Sprintf("Sockopt %s reply msg Read Error: %s", SOCKOPT_STRING, err.Error()))
		return EDPVS_IO
	}

	errCode := reply.GetErrCode()
	logger.Info(fmt.Sprintf("Sockopt %s Done:%s", SOCKOPT_STRING, errCode.String()))
	return errCode
}

func (o *CertificateAuthoritySpec) Get(cp *pool.ConnPool, blk bool, logger hclog.Logger) ([]*CertificateAuthoritySpec, error) {
	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed:", err.Error())
		return nil, err
	}
	defer cp.Remove(ctx, conn, nil)

	var GET uint32
	SOCKOPT_STRING := "SOCKOPT_GET_BLKLST_GETALL"
	GET = SOCKOPT_GET_BLKLST_GETALL
	if !blk {
		GET = SOCKOPT_GET_WHTLST_GETALL
		SOCKOPT_STRING = "SOCKOPT_GET_WHTLST_GETALL"
	}

	msg := NewSockMsg(SOCKOPT_VERSION, GET, SOCKOPT_GET, o.Sizeof())
	if err := msg.Write(conn); err != nil {
		logger.Error(fmt.Sprintf("Sockopt %s Write proto header Error: %s", SOCKOPT_STRING, err.Error()))
		return nil, err
	}

	if err := o.write(conn, logger); err != nil {
		logger.Error(fmt.Sprintf("Sockopt %s Write specific auth user Error: %s", SOCKOPT_STRING, err.Error()))
		return nil, err
	}

	reply := NewReplySockMsg()
	if err := reply.Read(conn); err != nil {
		logger.Error(fmt.Sprintf("Sockopt %s reply msg Read Error: %s", SOCKOPT_STRING, err.Error()))
		return nil, err
	}

	if reply.GetErrCode() != EDPVS_OK {
		err = fmt.Errorf("Sockopt %s reply ErrorCode: %s", SOCKOPT_STRING, reply.GetErrStr())
		logger.Error(err.Error())
		return nil, err
	}

	front := NewCertificateAuthorityFront()
	_, err = front.read(conn, front.Sizeof(), logger)
	if err != nil {
		logger.Error(fmt.Sprintf("Sockopt %s read auth user table header Error: %s", SOCKOPT_STRING, err.Error()))
		return nil, err
	}

	return o.read(conn, uint64(reply.GetLen())-front.Sizeof(), logger)
}
