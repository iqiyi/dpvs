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

/*
derived from:
  - include/conf/blklst.h
  - include/conf/whtlst.h
*/
type CertificateAuthoritySpec struct {
	vaddr [0x10]byte
	vport uint16
	proto uint8
	af    uint8

	caddr [0x10]byte
	ipset [IPSET_MAXNAMELEN]byte
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
	copy(o.vaddr[:], src.vaddr[:])
	o.vport = src.vport
	o.proto = src.proto
	o.af = src.af
	copy(o.caddr[:], src.caddr[:])
	copy(o.ipset[:], src.ipset[:])
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

	// vport := items[1]
	vport, err := strconv.Atoi(items[1])
	if err != nil {
		return err
	}
	o.SetVport(uint16(vport))

	vaddr := items[0]
	if net.ParseIP(vaddr) == nil {
		return errors.New(fmt.Sprintf("invalid ip addr: %s\n", vaddr))
	}

	o.SetVaddr(vaddr)

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

func (o *CertificateAuthoritySpec) SetAf(af uint8) {
	o.af = af
}

func (o *CertificateAuthoritySpec) SetCaddr(addr string) {
	if len(addr) == 0 {
		var zeros [0x10]byte
		copy(o.caddr[:], zeros[:])
		return
	}
	if strings.Contains(addr, ":") {
		o.SetAf(unix.AF_INET6)
		copy(o.caddr[:], net.ParseIP(addr))
		return
	}
	o.SetAf(unix.AF_INET)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, net.ParseIP(addr))
	copy(o.caddr[:], buf.Bytes()[12:])
}

func (o *CertificateAuthoritySpec) SetVaddr(addr string) {
	if strings.Contains(addr, ":") {
		o.SetAf(unix.AF_INET6)
		copy(o.vaddr[:], net.ParseIP(addr))
		return
	}
	o.SetAf(unix.AF_INET)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, net.ParseIP(addr))
	copy(o.vaddr[:], buf.Bytes()[12:])
}

func (o *CertificateAuthoritySpec) SetIpset(ipset string) {
	if len(ipset) == 0 {
		var zeros [IPSET_MAXNAMELEN]byte
		copy(o.ipset[:], zeros[:])
		return
	}
	buf := []byte(ipset)
	copy(o.ipset[:], buf[6:])
}

func (o *CertificateAuthoritySpec) SetVport(port uint16) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(port))
	o.vport = binary.BigEndian.Uint16(buf.Bytes())
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
