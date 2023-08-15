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

type LocalAddrFront struct {
	af     uint32
	port   uint32
	proto  uint32
	fwmark uint32
	cid    uint32
	count  uint32
	addr   [0x10]byte
	match  dpvsMatch
	nop    uint32
}

func NewLocalAddrFront() *LocalAddrFront {
	return &LocalAddrFront{}
}

func (o *LocalAddrFront) ID() string {
	proto := "tcp"
	if o.proto == unix.IPPROTO_UDP {
		proto = "udp"
	}
	return fmt.Sprintf("%s-%d-%s", o.GetAddr(), o.GetPort(), proto)
}

func (o *LocalAddrFront) GetPort() uint32 {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(o.port))
	port := binary.BigEndian.Uint16(buf.Bytes())
	return uint32(port)
}

func (o *LocalAddrFront) GetAddr() string {
	var addr net.IP

	if o.af == unix.AF_INET {
		addr = net.IPv4(o.addr[0], o.addr[1], o.addr[2], o.addr[3])
		return addr.String()
	}

	addr = net.IP{o.addr[0x0], o.addr[0x1], o.addr[0x2], o.addr[0x3],
		o.addr[0x4], o.addr[0x5], o.addr[0x6], o.addr[0x7],
		o.addr[0x8], o.addr[0x9], o.addr[0xa], o.addr[0xb],
		o.addr[0xc], o.addr[0xd], o.addr[0xe], o.addr[0xf],
	}
	return addr.String()
}

func (o *LocalAddrFront) GetAf() uint32 {
	return o.af
}

func (o *LocalAddrFront) SetAf(af uint32) {
	o.af = af
}

func (o *LocalAddrFront) SetAfByAddr(addr string) {
	i := strings.Index(addr, "/")
	if i != -1 {
		i = len(addr)
	}

	if strings.Count(addr[:i], ".") == 3 {
		o.af = unix.AF_INET
	}
	if strings.Count(addr[:i], ":") >= 2 {
		o.af = unix.AF_INET6
	}
}
func (o *LocalAddrFront) SetPort(port uint32) {
	o.port = port
}
func (o *LocalAddrFront) SetProto(proto uint32) {
	o.proto = proto
}
func (o *LocalAddrFront) SetFwmark(fwmark uint32) {
	o.fwmark = fwmark
}

func (o *LocalAddrFront) ParseVipPortProto(vipport string) error {
	vip := strings.Split(vipport, "-")[0]
	port := strings.Split(vipport, "-")[1]
	proto := strings.Split(vipport, "-")[2]

	switch strings.ToLower(proto) {
	case "udp":
		o.proto = unix.IPPROTO_UDP
	default:
		o.proto = unix.IPPROTO_TCP
	}

	value, err := strconv.Atoi(port)
	if err != nil {
		return err
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(value))

	o.port = uint32(binary.BigEndian.Uint16(buf.Bytes()))
	if strings.Contains(vipport, ":") {
		o.af = unix.AF_INET6
		copy(o.addr[:], net.ParseIP(vip))
	} else {
		o.af = unix.AF_INET

		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, net.ParseIP(vip))
		copy(o.addr[:], buf.Bytes()[12:])
	}

	return nil
}

func (o *LocalAddrFront) Package() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, o)
	return buf.Bytes()
}

func (o *LocalAddrFront) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*o))
}

func (o *LocalAddrFront) Dump(buf []byte) bool {
	if len(buf) != int(o.Sizeof()) {
		return false
	}

	var tmp *LocalAddrFront = *(**LocalAddrFront)(unsafe.Pointer(&buf))

	return o.Copy(tmp)
}

func (o *LocalAddrFront) Copy(src *LocalAddrFront) bool {
	if src == nil {
		return false
	}

	o.af = src.af
	o.port = src.port
	o.proto = src.proto
	o.fwmark = src.fwmark
	o.cid = src.cid
	o.count = src.count

	copy(o.addr[:], src.addr[:])

	return o.match.Copy(&src.match)
}

func (o *LocalAddrFront) read(conn *pool.Conn, len uint64, logger hclog.Logger) ([]*LocalAddrFront, error) {
	res := len % o.Sizeof()
	cnt := len / o.Sizeof()
	if cnt <= 0 || res != 0 {
		conn.Release(int(len))
		return nil, errors.New("buffer may not convert to LocalAddrFront")
	}

	fronts := make([]*LocalAddrFront, cnt)

	for i := 0; i < int(cnt); i++ {
		buf, err := conn.ReadN(int(o.Sizeof()))
		if err != nil {
			continue
		}
		fronts[i] = NewLocalAddrFront()
		fronts[i].Dump(buf)
	}

	return fronts, nil
}

func (o *LocalAddrFront) write(conn *pool.Conn) error {
	buf := o.Package()
	_, err := conn.WriteN(buf, int(o.Sizeof()))
	if err != nil {
		return err
	}
	return nil
}

type LocalAddrDetail struct {
	af           uint32
	conns        uint32
	portConflict uint64
	addr         [0x10]byte
	ifName       [unix.IFNAMSIZ]byte
}

func NewLocalAddrDetail() *LocalAddrDetail {
	return &LocalAddrDetail{}
}

func (o *LocalAddrDetail) Package() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, o)
	return buf.Bytes()
}

func (o *LocalAddrDetail) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*o))
}

func (o *LocalAddrDetail) Dump(buf []byte) bool {
	if len(buf) != int(o.Sizeof()) {
		return false
	}

	var tmp *LocalAddrDetail = *(**LocalAddrDetail)(unsafe.Pointer(&buf))

	return o.Copy(tmp)
}

func (o *LocalAddrDetail) setAf(af uint32) {
	o.af = af
}

func (o *LocalAddrDetail) GetAf() uint32 {
	return o.af
}

func (o *LocalAddrDetail) GetConns() uint32 {
	return o.conns
}

func (o *LocalAddrDetail) GetPortConflict() uint64 {
	return o.portConflict
}

func (o *LocalAddrDetail) SetAfByAddr(addr string) {
	i := strings.Index(addr, "/")
	if i != -1 {
		i = len(addr)
	}

	if strings.Count(addr[:i], ":") >= 2 {
		o.af = unix.AF_INET6
	}
	if strings.Count(addr[:i], ".") == 3 {
		o.af = unix.AF_INET
	}
}

func (o *LocalAddrDetail) GetAddr() string {
	var addr net.IP

	if o.af == unix.AF_INET {
		addr = net.IPv4(o.addr[0], o.addr[1], o.addr[2], o.addr[3])
		return addr.String()
	}

	addr = net.IP{o.addr[0x0], o.addr[0x1], o.addr[0x2], o.addr[0x3],
		o.addr[0x4], o.addr[0x5], o.addr[0x6], o.addr[0x7],
		o.addr[0x8], o.addr[0x9], o.addr[0xa], o.addr[0xb],
		o.addr[0xc], o.addr[0xd], o.addr[0xe], o.addr[0xf],
	}
	return addr.String()
}

func (o *LocalAddrDetail) SetAddr(addr string) {
	if strings.Contains(addr, ":") {
		copy(o.addr[:], net.ParseIP(addr))
		// o.af = unix.AF_INET6
		o.setAf(unix.AF_INET6)
	} else {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, net.ParseIP(addr))
		copy(o.addr[:], buf.Bytes()[12:])
		// o.af = unix.AF_INET
		o.setAf(unix.AF_INET)
	}
}

func (o *LocalAddrDetail) GetIfName() string {
	return TrimRightZeros(string(o.ifName[:]))
}

func (o *LocalAddrDetail) SetIfName(name string) {
	copy(o.ifName[:], name[:])
}

func (o *LocalAddrDetail) Copy(src *LocalAddrDetail) bool {
	if src == nil {
		return false
	}

	o.af = src.af
	o.conns = src.conns
	o.portConflict = src.portConflict

	copy(o.addr[:], src.addr[:])
	copy(o.ifName[:], src.ifName[:])

	return true
}

func (o *LocalAddrDetail) read(conn *pool.Conn, len uint64, logger hclog.Logger) ([]*LocalAddrDetail, error) {
	res := len % o.Sizeof()
	cnt := len / o.Sizeof()
	if cnt <= 0 || res != 0 {
		conn.Release(int(len))
		return nil, errors.New("buffer may not convert to LocalAddrEntry")
	}

	details := make([]*LocalAddrDetail, cnt)

	for i := 0; i < int(cnt); i++ {
		buf, err := conn.ReadN(int(o.Sizeof()))
		if err != nil {
			continue
		}
		// logger.Info(fmt.Sprintf("fetch RAW local address from dpvs (%d): %x", o.Sizeof(), buf))
		details[i] = NewLocalAddrDetail()
		details[i].Dump(buf)
	}

	logger.Info("Get Local Addr Done", "details", details)
	return details, nil
}

func (o *LocalAddrDetail) write(conn *pool.Conn) error {
	buf := o.Package()
	_, err := conn.WriteN(buf, int(o.Sizeof()))
	if err != nil {
		return err
	}
	return nil
}

/****************
****************/
func (o *LocalAddrFront) Get(cp *pool.ConnPool, parentLogger hclog.Logger) ([]*LocalAddrDetail, error) {
	logger := hclog.Default().Named(o.ID())
	if parentLogger != nil {
		logger = parentLogger.Named(o.ID())
	}

	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed", "Error", err.Error())
		return nil, err
	}
	defer cp.Remove(ctx, conn, nil)

	msg := NewSockMsg(SOCKOPT_VERSION, DPVSAGENT_VS_GET_LADDR, SOCKOPT_GET, o.Sizeof())
	if err := msg.Write(conn); err != nil {
		logger.Error("Sockopt DPVSAGENT_VS_GET_LADDR write proto header failed", "Error", err.Error())
		return nil, err
	}

	if err := o.write(conn); err != nil {
		logger.Error("Sockopt DPVSAGENT_VS_GET_LADDR write laddr table header failed", "Error", err.Error())
		return nil, err
	}

	reply := NewReplySockMsg()
	if err := reply.Read(conn); err != nil {
		logger.Error("Sockopt DPVSAGENT_VS_GET_LADDR Read sockmsg failed", "Error", err.Error())
		return nil, err
	}

	if reply.GetErrCode() != EDPVS_OK {
		result := reply.GetErrStr()
		logger.Error("Sockopt DPVSAGENT_VS_GET_LADDR failed", "result", result)
		err = fmt.Errorf("Sockopt DPVSAGENT_VS_GET_LADDR reply ErrorCode: %s", result)
		return nil, err
	}

	_, err = o.read(conn, o.Sizeof(), logger)
	if err != nil {
		logger.Error("Sockopt DPVSAGENT_VS_GET_LADDR read table header failed", "Error", err.Error())
		return nil, err
	}

	detail := NewLocalAddrDetail()
	return detail.read(conn, uint64(reply.GetLen())-o.Sizeof(), logger)
}

func (o *LocalAddrFront) Add(details []*LocalAddrDetail, cp *pool.ConnPool, parentLogger hclog.Logger) DpvsErrType {
	logger := hclog.Default().Named(o.ID())
	if parentLogger != nil {
		logger = parentLogger.Named(o.ID())
	}

	if len(details) == 0 {
		logger.Info("There are No laddr to set, return immediately")
		return EDPVS_OK
	}
	o.count = uint32(len(details))

	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed", "Error", err.Error())
		return EDPVS_IO
	}
	defer cp.Remove(ctx, conn, nil)

	msg := NewSockMsg(SOCKOPT_VERSION, DPVSAGENT_VS_ADD_LADDR, SOCKOPT_SET, o.Sizeof()+uint64(len(details))*details[0].Sizeof())
	if err := msg.Write(conn); err != nil {
		logger.Error("Sockopt DPVSAGENT_VS_ADD_LADDR write proto header failed", "Error", err.Error())
		return EDPVS_IO
	}

	if err := o.write(conn); err != nil {
		logger.Error("Sockopt DPVSAGENT_VS_ADD_LADDR write laddr table header failed", "Error", err.Error())
		return EDPVS_IO
	}

	for _, detail := range details {
		if err := detail.write(conn); err != nil {
			logger.Error("Sockopt DPVSAGENT_VS_ADD_LADDR write spec laddr failed", "Error", err.Error())
			return EDPVS_IO
		}
	}

	reply := NewReplySockMsg()
	if err := reply.Read(conn); err != nil {
		logger.Error("Sockopt DPVSAGENT_VS_ADD_LADDR Read reply failed", "Error", err.Error())
		return EDPVS_IO
	}

	errCode := reply.GetErrCode()
	result := errCode.String()
	logger.Info("DPVSAGENT_VS_ADD_LADDR Done", "details", details, "result", result)
	return errCode
}

func (o *LocalAddrFront) Del(details []*LocalAddrDetail, cp *pool.ConnPool, parentLogger hclog.Logger) DpvsErrType {
	logger := hclog.Default().Named(o.ID())
	if parentLogger != nil {
		logger = parentLogger.Named(o.ID())
	}

	if len(details) == 0 {
		logger.Info("There are No laddr to del, return immediately")
		return EDPVS_OK
	}
	o.count = uint32(len(details))

	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed", "Error", err.Error())
		return EDPVS_IO
	}
	defer cp.Remove(ctx, conn, nil)

	msg := NewSockMsg(SOCKOPT_VERSION, DPVSAGENT_VS_DEL_LADDR, SOCKOPT_SET, o.Sizeof()+uint64(len(details))*details[0].Sizeof())
	if err := msg.Write(conn); err != nil {
		logger.Error("Sockopt DPVSAGENT_VS_DEL_LADDR Write proto header failed", "Error", err.Error())
		return EDPVS_IO
	}

	if err := o.write(conn); err != nil {
		logger.Error("Sockopt DPVSAGENT_VS_DEL_LADDR write laddr table header failed", "Error", err.Error())
		return EDPVS_IO
	}

	for _, detail := range details {
		if err := detail.write(conn); err != nil {
			logger.Error("Sockopt DPVSAGENT_VS_DEL_LADDR write spec laddr failed", "Error", err.Error())
			return EDPVS_IO
		}
	}

	reply := NewReplySockMsg()
	if err := reply.Read(conn); err != nil {
		logger.Error("Sockopt DPVSAGENT_VS_DEL_LADDR Read failed", "Error", err.Error())
		return EDPVS_IO
	}

	errCode := reply.GetErrCode()
	result := errCode.String()
	logger.Info("DPVSAGENT_VS_DEL_LADDR", "details", details, " Done", "result", result)
	return errCode
}
