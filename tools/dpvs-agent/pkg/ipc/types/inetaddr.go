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

type InetAddrFront struct {
	count uint32
}

func NewInetAddrFront() *InetAddrFront {
	return &InetAddrFront{}
}

func (o *InetAddrFront) GetCount() uint32 {
	return o.count
}

func (o *InetAddrFront) SetCount(c uint32) {
	o.count = c
}

func (o *InetAddrFront) Copy(src *InetAddrFront) bool {
	o.count = src.count
	return true
}

func (o *InetAddrFront) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*o))
}

func (o *InetAddrFront) Dump(buf []byte) bool {
	if len(buf) != int(o.Sizeof()) {
		return false
	}

	var tmp *InetAddrFront = *(**InetAddrFront)(unsafe.Pointer(&buf))

	return o.Copy(tmp)
}

func (o *InetAddrFront) Package() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, o)
	return buf.Bytes()
}

func (o *InetAddrFront) read(conn *pool.Conn, len uint64, logger hclog.Logger) ([]*InetAddrFront, error) {
	res := len % o.Sizeof()
	cnt := len / o.Sizeof()
	if cnt <= 0 || res != 0 {
		conn.Release(int(len))
		return nil, errors.New("Wrong buffer size to read, may not convert to InetAddrFront")
	}

	fronts := make([]*InetAddrFront, cnt)

	for i := 0; i < int(cnt); i++ {
		buf, err := conn.ReadN(int(o.Sizeof()))
		if err != nil {
			continue
		}
		fronts[i] = NewInetAddrFront()
		fronts[i].Dump(buf)
	}

	return fronts, nil
}

func (o *InetAddrFront) write(conn *pool.Conn, logger hclog.Logger) error {
	buf := o.Package()
	_, err := conn.WriteN(buf, int(o.Sizeof()))
	if err != nil {
		return err
	}
	return nil
}

type InetAddrStats struct {
	addr [0x10]byte
	used uint32
	free uint32
	miss uint32
}

func NewInetAddrStats() *InetAddrStats {
	return &InetAddrStats{}
}

func (o *InetAddrStats) GetUsed() uint32 {
	return o.used
}

func (o *InetAddrStats) GetFree() uint32 {
	return o.free
}

func (o *InetAddrStats) GetMiss() uint32 {
	return o.miss
}

func (o *InetAddrStats) Copy(src *InetAddrStats) bool {
	o.used = src.used
	o.free = src.free
	o.miss = src.miss
	copy(o.addr[:], src.addr[:])
	return true
}

func (o *InetAddrStats) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*o))
}

func (o *InetAddrStats) Dump(buf []byte) bool {
	if len(buf) != int(o.Sizeof()) {
		return false
	}

	var tmp *InetAddrStats = *(**InetAddrStats)(unsafe.Pointer(&buf))

	return o.Copy(tmp)
}

func (o *InetAddrStats) Package() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, o)
	return buf.Bytes()
}

func (o *InetAddrStats) read(conn *pool.Conn, len uint64, logger hclog.Logger) ([]*InetAddrStats, error) {
	res := len % o.Sizeof()
	cnt := len / o.Sizeof()
	if cnt <= 0 || res != 0 {
		conn.Release(int(len))
		return nil, errors.New("Wrong buffer size to read, may not convert to InetAddrStats")
	}

	stats := make([]*InetAddrStats, cnt)

	for i := 0; i < int(cnt); i++ {
		buf, err := conn.ReadN(int(o.Sizeof()))
		if err != nil {
			continue
		}
		stats[i] = NewInetAddrStats()
		stats[i].Dump(buf)
	}

	return stats, nil
}

func (o *InetAddrStats) write(conn *pool.Conn, logger hclog.Logger) error {
	buf := o.Package()
	_, err := conn.WriteN(buf, int(o.Sizeof()))
	if err != nil {
		return err
	}
	return nil
}

type InetAddrDetail struct {
	af          uint32
	validLft    uint32
	preferedLft uint32
	flags       uint32
	ifName      [0x10]byte
	bcast       [0x10]byte
	addr        [0x10]byte
	plen        uint8
	scope       uint8
	cid         uint8
	nop         uint8
}

func NewInetAddrDetail() *InetAddrDetail {
	return &InetAddrDetail{}
}

func (o *InetAddrDetail) Copy(src *InetAddrDetail) bool {
	o.af = src.af
	o.validLft = src.validLft
	o.preferedLft = src.preferedLft
	o.flags = src.flags
	o.plen = src.plen
	o.scope = src.scope
	o.cid = src.cid

	copy(o.ifName[:], src.ifName[:])
	copy(o.addr[:], src.addr[:])
	copy(o.bcast[:], src.bcast[:])

	return true
}

func (o *InetAddrDetail) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*o))
}

func (o *InetAddrDetail) Dump(buf []byte) bool {
	if len(buf) != int(o.Sizeof()) {
		return false
	}

	var tmp *InetAddrDetail = *(**InetAddrDetail)(unsafe.Pointer(&buf))

	return o.Copy(tmp)
}

func (o *InetAddrDetail) Package() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, o)
	return buf.Bytes()
}

func (o *InetAddrDetail) GetAddr() string {
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

func (o *InetAddrDetail) GetIfName() string {
	return TrimRightZeros(string(o.ifName[:]))
}

func (o *InetAddrDetail) SetAf(af uint32) {
	o.af = af
}

func (o *InetAddrDetail) SetValidLft(lft string) error {
	if strings.EqualFold(strings.ToLower(lft), "forever") {
		o.validLft = 0
	} else {
		i, err := strconv.Atoi(lft)
		if err != nil {
			return err
		}
		o.validLft = uint32(i)
	}
	return nil
}

func (o *InetAddrDetail) SetPreferedLft(lft string) error {
	if strings.EqualFold(strings.ToLower(lft), "forever") {
		o.preferedLft = 0
	} else {
		i, err := strconv.Atoi(lft)
		if err != nil {
			return err
		}
		o.preferedLft = uint32(i)
	}
	return nil
}

func (o *InetAddrDetail) SetPlen(len uint8) {
	o.plen = len
}

const (
	IFA_F_SAPOOL      uint32 = 0x10000
	IFA_F_OPS_VERBOSE uint32 = 0x0001
	IFA_F_OPS_STATS   uint32 = 0x0002
)

func (o *InetAddrDetail) SetFlags(flags string) {
	switch strings.ToLower(flags) {
	case "verbose":
		o.flags |= IFA_F_OPS_VERBOSE
	case "stats":
		o.flags |= IFA_F_OPS_STATS
	case "sapool":
		o.flags |= IFA_F_SAPOOL
	}
}

func (o *InetAddrDetail) SetScope(scope string) {
	value, err := strconv.ParseUint(scope, 10, 8)
	if err == nil {
		o.scope = uint8(value)
		return
	}

	switch strings.ToLower(scope) {
	case "host":
		o.scope = IFA_SCOPE_HOST
	case "link":
		o.scope = IFA_SCOPE_LINK
	case "global":
		fallthrough
	default:
		o.scope = IFA_SCOPE_GLOBAL
		// o.scope = 255
	}
}

func (o *InetAddrDetail) SetCid(cid uint8) {
	o.cid = cid
}

func (o *InetAddrDetail) SetIfName(name string) {
	copy(o.ifName[:], name[:])
}

func (o *InetAddrDetail) setAddr(addr string) {
	if strings.Contains(addr, ":") {
		copy(o.addr[:], net.ParseIP(addr))
		o.af = unix.AF_INET6
		return
	}

	o.af = unix.AF_INET
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, net.ParseIP(addr))
	copy(o.addr[:], buf.Bytes()[12:])
}

func (o *InetAddrDetail) SetAddr(addr string) {
	var plen, ip string

	if strings.Index(addr, "/") != -1 {
		plen = addr[strings.Index(addr, "/")+1:]
		ip = addr[:strings.Index(addr, "/")]
	} else {
		ip = addr
		plen = "32"

		if strings.Contains(ip, ":") {
			plen = "128"
		}
	}

	o.setAddr(ip)

	value, err := strconv.ParseUint(plen, 10, 8)
	if err == nil {
		o.SetPlen(uint8(value))
	}
}

func (o *InetAddrDetail) SetBCast(addr string) {
	if len(addr) == 0 {
		return
	}
	if strings.Contains(addr, ":") {
		copy(o.bcast[:], net.ParseIP(addr))
	} else {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, net.ParseIP(addr))
		copy(o.bcast[:], buf.Bytes()[12:])
	}
}

func (o *InetAddrDetail) read(conn *pool.Conn, len uint64, logger hclog.Logger) ([]*InetAddrDetail, error) {
	res := len % o.Sizeof()
	cnt := len / o.Sizeof()
	if cnt <= 0 || res != 0 {
		conn.Release(int(len))
		return nil, errors.New("Wrong buffer size to read, may not convert to InetAddrDetail")
	}

	details := make([]*InetAddrDetail, cnt)

	for i := 0; i < int(cnt); i++ {
		buf, err := conn.ReadN(int(o.Sizeof()))
		if err != nil {
			continue
		}
		details[i] = NewInetAddrDetail()
		details[i].Dump(buf)
	}

	return details, nil
}

func (o *InetAddrDetail) write(conn *pool.Conn, logger hclog.Logger) error {
	buf := o.Package()
	_, err := conn.WriteN(buf, int(o.Sizeof()))
	if err != nil {
		return err
	}
	return nil
}

/****************
****************/
func (o *InetAddrDetail) Get(cp *pool.ConnPool, logger hclog.Logger) ([]*InetAddrDetail, error) {
	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed", "Error", err.Error())
		return nil, err
	}
	defer cp.Remove(ctx, conn, nil)

	msg := NewSockMsg(SOCKOPT_VERSION, DPVSAGENT_IFADDR_GET_BASE, SOCKOPT_GET, o.Sizeof())
	if err := msg.Write(conn); err != nil {
		logger.Error("Sockopt DPVSAGENT_IFADDR_GET_BASE Write proto header failed", "Error", err.Error())
		return nil, err
	}

	if err := o.write(conn, logger); err != nil {
		logger.Error("Sockopt DPVSAGENT_IFADDR_GET_BASE Write specific inetaddr failed", "Error", err.Error())
		return nil, err
	}

	reply := NewReplySockMsg()
	if err := reply.Read(conn); err != nil {
		logger.Error("Sockopt DPVSAGENT_IFADDR_GET_BASE reply msg Read failed", "Error", err.Error())
		return nil, err
	}

	if reply.GetErrCode() != EDPVS_OK {
		result := reply.GetErrStr()
		logger.Error("Sockopt DPVSAGENT_IFADDR_GET_BASE failed", "result", result)
		err = fmt.Errorf("Sockopt DPVSAGENT_IFADDR_GET_BASE reply ErrorCode: %s", result)
		return nil, err
	}

	front := NewInetAddrFront()
	_, err = front.read(conn, front.Sizeof(), logger)
	if err != nil {
		logger.Error("Sockopt DPVSAGENT_IFADDR_GET_BASE read table header failed", "Error", err.Error())
		return nil, err
	}

	return o.read(conn, uint64(reply.GetLen())-front.Sizeof(), logger)
}

func (o *InetAddrDetail) Add(cp *pool.ConnPool, parentLogger hclog.Logger) DpvsErrType {
	traceName := fmt.Sprintf("dpip addr add %s dev %s", o.GetAddr(), o.GetIfName())
	logger := hclog.Default().Named(traceName)
	if parentLogger != nil {
		logger = parentLogger.Named(traceName)
	}

	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed", "Error", err.Error())
		return EDPVS_IO
	}
	defer cp.Remove(ctx, conn, nil)

	msg := NewSockMsg(SOCKOPT_VERSION, DPVSAGENT_IFADDR_ADD, SOCKOPT_SET, o.Sizeof())
	err = msg.Write(conn)
	if err != nil {
		logger.Error("Sockopt DPVSAGENT_IFADDR_ADD Write proto header failed", "Error", err.Error())
		return EDPVS_IO
	}

	err = o.write(conn, logger)
	if err != nil {
		logger.Error("Sockopt DPVSAGENT_IFADDR_ADD write inetaddr detail failed", "Error", err.Error())
		return EDPVS_IO
	}

	reply := NewReplySockMsg()
	err = reply.Read(conn)
	if err != nil {
		logger.Error("Sockopt DPVSAGENT_IFADDR_ADD reply msg Read failed", "Error", err.Error())
		return EDPVS_IO
	}

	errCode := reply.GetErrCode()
	result := errCode.String()
	addr := o.GetAddr()
	logger.Info("Sockopt DPVSAGENT_IFADDR_ADD done", "addr", addr, "result", result)
	return errCode
}

func (o *InetAddrDetail) Del(cp *pool.ConnPool, parentLogger hclog.Logger) DpvsErrType {
	traceName := fmt.Sprintf("dpip addr del %s dev %s", o.GetAddr(), o.GetIfName())
	logger := hclog.Default().Named(traceName)
	if parentLogger != nil {
		logger = parentLogger.Named(traceName)
	}
	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed", "Error", err.Error())
		return EDPVS_IO
	}
	defer cp.Remove(ctx, conn, nil)

	msg := NewSockMsg(SOCKOPT_VERSION, DPVSAGENT_IFADDR_DEL, SOCKOPT_SET, o.Sizeof())
	err = msg.Write(conn)
	if err != nil {
		logger.Error("Sockopt DPVSAGENT_IFADDR_DEL Write proto header failed", "Error", err.Error())
		return EDPVS_IO
	}

	err = o.write(conn, logger)
	if err != nil {
		logger.Error("Sockopt DPVSAGENT_IFADDR_DEL write del inetaddr detail failed", "Error", err.Error())
		return EDPVS_IO
	}

	reply := NewReplySockMsg()
	err = reply.Read(conn)
	if err != nil {
		logger.Error("Sockopt DPVSAGENT_IFADDR_DEL Read failed", "Error", err.Error())
		return EDPVS_IO
	}

	errCode := reply.GetErrCode()
	result := errCode.String()
	addr := o.GetAddr()
	logger.Info("Sockopt DPVSAGENT_IFADDR_DEL done", "addr", addr, "del", "result", result)
	return errCode
}

func (o *InetAddrStats) Get(cp *pool.ConnPool, logger hclog.Logger) ([]*InetAddrStats, error) {
	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed", "Error", err.Error())
		return nil, err
	}
	defer cp.Remove(ctx, conn, nil)

	msg := NewSockMsg(SOCKOPT_VERSION, DPVSAGENT_IFADDR_GET_STATS, SOCKOPT_GET, o.Sizeof())
	if err := msg.Write(conn); err != nil {
		logger.Error("Sockopt DPVSAGENT_IFADDR_GET_STATS Write proto header failed", "Error", err.Error())
		return nil, err
	}

	reply := NewReplySockMsg()
	if err := reply.Read(conn); err != nil {
		logger.Error("Sockopt DPVSAGENT_IFADDR_GET_STATS reply msg Read failed", "Error", err.Error())
		return nil, err
	}

	if reply.GetErrCode() != EDPVS_OK {
		result := reply.GetErrStr()
		logger.Error("Sockopt SOCKOPT_GET_KNI_LIST failed", "result", result)
		err = fmt.Errorf("Sockopt SOCKOPT_GET_KNI_LIST failed. ErrorCode: %s", reply.GetErrStr())
		return nil, err
	}

	front := NewInetAddrFront()
	_, err = front.read(conn, front.Sizeof(), logger)
	if err != nil {
		logger.Error("Sockopt SOCKOPT_GET_KNI_LIST read table header failed", "Error", err.Error())
		return nil, err
	}

	return o.read(conn, uint64(reply.GetLen())-front.Sizeof(), logger)
}
