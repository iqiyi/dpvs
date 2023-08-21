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

type RealServerSpec struct {
	af           uint32
	port         uint16
	proto        uint16
	weight       uint32
	addr         [0x10]byte
	connFlags    uint16
	flags        uint16
	fwdmode      DpvsFwdMode
	maxConn      uint32
	minConn      uint32
	actConns     uint32
	inActConns   uint32
	presistConns uint32
	stats        dpvsStats
}

func NewRealServerSpec() *RealServerSpec {
	return &RealServerSpec{}
}

func (rs *RealServerSpec) SetAf(af uint32) {
	rs.af = af
}

func (rs *RealServerSpec) SetProto(proto uint16) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(proto))
	rs.proto = binary.BigEndian.Uint16(buf.Bytes())
}

func (rs *RealServerSpec) SetPort(port uint16) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(port))
	rs.port = binary.BigEndian.Uint16(buf.Bytes())
}

func (rs *RealServerSpec) SetWeight(weight uint32) {
	rs.weight = weight
}

func (rs *RealServerSpec) GetWeight() uint32 {
	return rs.weight
}

func (rs *RealServerSpec) SetAddr(addr string) {
	if strings.Contains(addr, ":") {
		rs.af = unix.AF_INET6
		copy(rs.addr[:], net.ParseIP(addr))
	} else {
		rs.af = unix.AF_INET
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, net.ParseIP(addr))
		copy(rs.addr[:], buf.Bytes()[12:])
	}
}

func (rs *RealServerSpec) SetFlags(flags uint16) {
	rs.flags = flags
}

func (rs *RealServerSpec) setConnFlags(connFlags uint16) {
	rs.connFlags = connFlags
}

func (rs *RealServerSpec) SetFwdMode(fwdmode DpvsFwdMode) {
	rs.setConnFlags(uint16(fwdmode) & DPVS_CONN_F_FWD_MASK)
	rs.fwdmode = fwdmode
}

func (rs *RealServerSpec) SetMaxConn(conns uint32) {
	rs.maxConn = conns
}

func (rs *RealServerSpec) SetMinConn(conns uint32) {
	rs.minConn = conns
}

func (rs *RealServerSpec) SetPresistConns(conns uint32) {
	rs.presistConns = conns
}

func (rs *RealServerSpec) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*rs))
}

func (rs *RealServerSpec) Copy(src *RealServerSpec) bool {
	if src == nil {
		return false
	}

	copy(rs.addr[:], src.addr[:])

	rs.af = src.af
	rs.proto = src.proto
	rs.port = src.port
	rs.weight = src.weight
	rs.flags = src.flags
	rs.connFlags = src.connFlags
	rs.fwdmode = src.fwdmode
	rs.maxConn = src.maxConn
	rs.minConn = src.minConn
	rs.actConns = src.actConns
	rs.inActConns = src.inActConns
	rs.presistConns = src.presistConns

	return rs.stats.Copy(&src.stats)
}

func (rs *RealServerSpec) Dump(buf []byte) bool {
	if len(buf) != int(rs.Sizeof()) {
		return false
	}

	var tmp *RealServerSpec = *(**RealServerSpec)(unsafe.Pointer(&buf))

	return rs.Copy(tmp)
}

func (rs *RealServerSpec) Package() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, rs)
	return buf.Bytes()
}

func (rs *RealServerSpec) write(conn *pool.Conn) error {
	buf := rs.Package()
	_, err := conn.WriteN(buf, int(rs.Sizeof()))
	if err != nil {
		// return errors.New("real server desc write failure(", written, "/", len(buf), ")")
		return err
	}
	return nil
}

func (rs *RealServerSpec) read(conn *pool.Conn, len uint64, logger hclog.Logger) ([]*RealServerSpec, error) {
	res := len % rs.Sizeof()
	cnt := len / rs.Sizeof()
	if res != 0 {
		conn.Release(int(len))
		return nil, errors.New("Wrong buffer size to read, may not convert to RealServerSpec")
	}

	rss := make([]*RealServerSpec, cnt)

	for i := 0; i < int(cnt); i++ {
		buf, err := conn.ReadN(int(rs.Sizeof()))
		if err != nil {
			continue
		}

		rss[i] = NewRealServerSpec()
		rss[i].Dump(buf)
		spec := *rss[i]
		logger.Info("get real server success", "spec", spec)
	}

	return rss, nil
}

func (rs *RealServerSpec) GetAddr() string {
	if rs.af == unix.AF_INET {
		addr := net.IPv4(rs.addr[0], rs.addr[1], rs.addr[2], rs.addr[3])
		return addr.String()
	}
	return ""
}

func (rs *RealServerSpec) GetPort() uint16 {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(rs.port))
	return binary.BigEndian.Uint16(buf.Bytes())
}

func (rs *RealServerSpec) GetConnFlags() uint16 {
	return rs.connFlags
}

func (rs *RealServerSpec) GetOverloaded() bool {
	return rs.flags&DPVS_DEST_F_OVERLOAD != 0
}

func (rs *RealServerSpec) SetOverloaded(overloaded *bool) {
	if overloaded == nil {
		return
	}
	if *overloaded {
		rs.flags |= DPVS_DEST_F_OVERLOAD
	} else {
		rs.flags &= ^uint16(DPVS_DEST_F_OVERLOAD)
	}
}

func (rs *RealServerSpec) GetInhibited() bool {
	return rs.flags&DPVS_DEST_F_INHIBITED != 0
}

func (rs *RealServerSpec) SetInhibited(inhibited *bool) {
	if inhibited == nil {
		return
	}
	if *inhibited {
		rs.flags |= DPVS_DEST_F_INHIBITED
	} else {
		rs.flags &= ^uint16(DPVS_DEST_F_INHIBITED)
	}
}

func (rs *RealServerSpec) GetFwdModeString() string {
	return rs.fwdmode.String()
}

func (rs *RealServerSpec) ID() string {
	return fmt.Sprintf("%s:%d", rs.GetAddr(), rs.GetPort())
}

func (rs *RealServerSpec) Format(kind string) string {
	/*
	   -> RIP:RPORT\t\t\tFNAT\tWeight\tActive\tInactive
	*/
	return fmt.Sprintf("  -> %s:%d\t\t\t%s\t%d\t%d\t%d", rs.GetAddr(), rs.GetPort(), rs.GetFwdModeString(), rs.weight, rs.actConns, rs.inActConns)
}

type RealServerFront struct {
	af       uint32
	proto    uint16
	port     uint16
	fwmark   uint32
	addr     [0x10]byte
	numDests uint32
	match    dpvsMatch
	cid      uint32
	index    uint32
}

func NewRealServerFront() *RealServerFront {
	return &RealServerFront{}
}

func (rs *RealServerFront) SetNumDests(n uint32) {
	rs.numDests = n
}

func (rs *RealServerFront) ID() string {
	proto := "tcp"
	if rs.proto == unix.IPPROTO_UDP {
		proto = "udp"
	}
	return fmt.Sprintf("%s-%d-%s", rs.GetAddr(), rs.GetPort(), proto)
}

func (rs *RealServerFront) GetAddr() string {
	var addr net.IP

	if rs.af == unix.AF_INET {
		addr = net.IPv4(rs.addr[0], rs.addr[1], rs.addr[2], rs.addr[3])
		return addr.String()
	}

	addr = net.IP{rs.addr[0x0], rs.addr[0x1], rs.addr[0x2], rs.addr[0x3],
		rs.addr[0x4], rs.addr[0x5], rs.addr[0x6], rs.addr[0x7],
		rs.addr[0x8], rs.addr[0x9], rs.addr[0xa], rs.addr[0xb],
		rs.addr[0xc], rs.addr[0xd], rs.addr[0xe], rs.addr[0xf],
	}
	return addr.String()
}

func (rs *RealServerFront) GetAf() uint32 {
	return rs.af
}

func (rs *RealServerFront) GetPort() uint16 {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(rs.port))
	return binary.BigEndian.Uint16(buf.Bytes())
}

func (rs *RealServerFront) GetProto() uint16 {
	return rs.proto
}

func (rs *RealServerFront) Dump(buf []byte) bool {
	if len(buf) != int(rs.Sizeof()) {
		return false
	}

	var tmp *RealServerFront = *(**RealServerFront)(unsafe.Pointer(&buf))

	return rs.Copy(tmp)
}

func (rs *RealServerFront) Package() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, rs)
	return buf.Bytes()
}

func (rs *RealServerFront) write(conn *pool.Conn) error {
	buf := rs.Package()
	_, err := conn.WriteN(buf, int(rs.Sizeof()))
	if err != nil {
		return err
	}
	return nil
}

func (rs *RealServerFront) read(conn *pool.Conn, logger hclog.Logger) error {
	conn.SetReadBuffer(int(rs.Sizeof()))
	buf, err := conn.ReadN(int(rs.Sizeof()))
	if err != nil {
		return err
	}

	if !rs.Dump(buf) {
		return errors.New("Dump RealServerFront failed")
	}

	return nil
}

func (rs *RealServerFront) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*rs))
}

func (o *RealServerFront) ParseVipPortProto(vipport string) error {
	vip := strings.Split(vipport, "-")[0]
	port := strings.Split(vipport, "-")[1]
	proto := strings.Split(vipport, "-")[2]

	switch strings.ToLower(proto) {
	case "tcp":
		o.proto = unix.IPPROTO_TCP
	case "udp":
		o.proto = unix.IPPROTO_UDP
	default:
	}

	value, err := strconv.Atoi(port)
	if err != nil {
		return err
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(value))

	o.port = binary.BigEndian.Uint16(buf.Bytes())
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

func (rs *RealServerFront) Copy(src *RealServerFront) bool {
	if src == nil {
		return false
	}

	copy(rs.addr[:], src.addr[:])

	rs.af = src.af
	rs.proto = src.proto
	rs.port = src.port
	rs.fwmark = src.fwmark
	rs.numDests = src.numDests
	rs.cid = src.cid

	return rs.match.Copy(&src.match)
}

/*****************
******************/

func (front *RealServerFront) Get(cp *pool.ConnPool, parentLogger hclog.Logger) ([]*RealServerSpec, error) {
	logger := hclog.Default().Named(front.ID())
	if parentLogger != nil {
		logger = parentLogger.Named(front.ID())
	}

	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed", "Error", err.Error())
		return nil, err
	}
	defer cp.Remove(ctx, conn, nil)

	msg := NewSockMsg(SOCKOPT_VERSION, DPVSAGENT_VS_GET_DESTS, SOCKOPT_GET, front.Sizeof())
	if err := msg.Write(conn); err != nil {
		logger.Error("Sockopt DPVSAGENT_VS_GET_DESTs write proto header failed", "Error", err.Error())
		return nil, err
	}

	if err := front.write(conn); err != nil {
		logger.Error("Sockopt DPVSAGENT_VS_GET_DESTs write body failed", "Error", err.Error())
		return nil, err
	}

	reply := NewReplySockMsg()
	if err := reply.Read(conn); err != nil {
		logger.Error("Sockopt DPVSAGENT_VS_GET_DESTs Read sockmsg failed", "Error", err.Error())
		return nil, err
	}

	if err := front.read(conn, logger); err != nil {
		logger.Error("Sockopt DPVSAGENT_VS_GET_DESTs read table header failed", "Error", err.Error())
		return nil, err
	}

	rs := NewRealServerSpec()

	return rs.read(conn, uint64(reply.GetLen())-front.Sizeof(), logger)
}

// put
func (front *RealServerFront) Edit(existOnly bool, rss []*RealServerSpec, cp *pool.ConnPool, parentLogger hclog.Logger) DpvsErrType {
	logger := hclog.Default().Named(front.ID())
	if parentLogger != nil {
		logger = parentLogger.Named(front.ID())
	}

	if len(rss) == 0 {
		return EDPVS_OK
	}

	sEdit := "DPVSAGENT_VS_EDIT_DESTS"
	var EDIT uint32 = DPVSAGENT_VS_EDIT_DESTS

	if !existOnly {
		EDIT = DPVSAGENT_VS_ADD_DESTS
		sEdit = "DPVSAGENT_VS_ADD_DESTS"
	}

	front.numDests = uint32(len(rss))

	ctx := context.Background()
	conn, err := cp.Get(ctx)

	if err != nil {
		logger.Error("Get conn from pool failed:", err.Error())
		return EDPVS_IO
	}

	defer cp.Remove(ctx, conn, nil)

	msg := NewSockMsg(SOCKOPT_VERSION, EDIT, SOCKOPT_SET, front.Sizeof()+rss[0].Sizeof()*uint64(len(rss)))

	if err := msg.Write(conn); err != nil {
		logger.Error(fmt.Sprintf("Sockopt %s Write proto header failed Error=%s", sEdit, err.Error()))
		return EDPVS_IO
	}

	if err := front.write(conn); err != nil {
		logger.Error(fmt.Sprintf("Sockopt %s Write rss table header failed Error=%s", sEdit, err.Error()))
		return EDPVS_IO
	}

	for _, rs := range rss {
		if err := rs.write(conn); err != nil {
			logger.Error(fmt.Sprintf("Sockopt %s Write rs %v header failed Error=%s", sEdit, *rs, err.Error()))
			return EDPVS_IO
		}
	}

	reply := NewReplySockMsg()

	if err := reply.Read(conn); err != nil {
		logger.Error(fmt.Sprintf("Sockopt %s Read sockmsg failed Error=%s", sEdit, err.Error()))
		return EDPVS_IO
	}

	errCode := reply.GetErrCode()
	logger.Info(fmt.Sprintf("%s %v Done result=%s", sEdit, rss, errCode.String()))
	return errCode
}

func (front *RealServerFront) add(rss []*RealServerSpec, cp *pool.ConnPool, logger hclog.Logger) DpvsErrType {
	if len(rss) == 0 {
		return EDPVS_OK
	}

	front.numDests = uint32(len(rss))

	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed", "Error", err.Error())
		return EDPVS_IO
	}
	defer cp.Remove(ctx, conn, nil)

	msg := NewSockMsg(SOCKOPT_VERSION, DPVSAGENT_VS_ADD_DESTS, SOCKOPT_SET, front.Sizeof()+rss[0].Sizeof()*uint64(len(rss)))
	if err := msg.Write(conn); err != nil {
		logger.Error("Sockopt DPVSAGENT_VS_ADD_DESTs write proto header failed", "Error", err.Error())
		return EDPVS_IO
	}

	if err := front.write(conn); err != nil {
		logger.Error("Sockopt DPVSAGENT_VS_ADD_DESTs write rss table header failed", "Error", err.Error())
		return EDPVS_IO
	}

	for _, rs := range rss {
		if err := rs.write(conn); err != nil {
			// backend error
			logger.Error("Sockopt DPVSAGENT_VS_ADD_DESTs write spec rs failed", "Error", err.Error())
			return EDPVS_IO
		}
	}

	reply := NewReplySockMsg()
	if err := reply.Read(conn); err != nil {
		logger.Error("Sockopt DPVSAGENT_VS_ADD_DESTs Read sockmsg failed", "Error", err.Error())
		return EDPVS_IO
	}

	errCode := reply.GetErrCode()
	result := errCode.String()
	logger.Info("DPVSAGENT_VS_ADD_DESTs Done", "result", result)
	return errCode
}

func (front *RealServerFront) Del(rss []*RealServerSpec, cp *pool.ConnPool, logger hclog.Logger) DpvsErrType {
	if len(rss) == 0 {
		logger.Info("No Real server need delete, return immediately")
		return EDPVS_OK
	}

	front.numDests = uint32(len(rss))

	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed", "Error", err.Error())
		return EDPVS_IO
	}
	defer cp.Remove(ctx, conn, nil)

	msg := NewSockMsg(SOCKOPT_VERSION, DPVSAGENT_VS_DEL_DESTS, SOCKOPT_SET, front.Sizeof()+rss[0].Sizeof()*uint64(len(rss)))
	if err := msg.Write(conn); err != nil {
		logger.Error("Sockopt DPVSAGENT_VS_DEL_DESTs write proto header failed", "Error", err.Error())
		return EDPVS_IO
	}

	if err := front.write(conn); err != nil {
		logger.Error("Sockopt DPVSAGENT_VS_DEL_DESTs write rss table header failed", "Error", err.Error())
		return EDPVS_IO
	}

	for _, rs := range rss {
		if err := rs.write(conn); err != nil {
			// backend error
			logger.Error("Sockopt DPVSAGENT_VS_DEL_DESTs write spec rs failed", "Error", err.Error())
			return EDPVS_IO
		}
	}

	reply := NewReplySockMsg()
	if err := reply.Read(conn); err != nil {
		logger.Error("Sockopt DPVSAGENT_VS_DEL_DESTs Read sockmsg failed", "Error", err.Error())
		return EDPVS_IO
	}

	errCode := reply.GetErrCode()
	result := errCode.String()
	logger.Info("DPVSAGENT_VS_ADD_DESTs Done", "result", result)
	return errCode
}

// post
func (front *RealServerFront) Update(rss []*RealServerSpec, cp *pool.ConnPool, parentLogger hclog.Logger) DpvsErrType {
	logger := hclog.Default().Named(front.ID())
	if parentLogger != nil {
		logger = parentLogger.Named(front.ID())
	}

	if len(rss) == 0 {
		logger.Warn("Remove all RS ! ! !")
	}

	running, err := front.Get(cp, logger)
	if err != nil {
		logger.Error("Get realserver failed", "Error", err.Error())
		return EDPVS_IO
	}

	reserved := make(map[string]*RealServerSpec)
	for _, rs := range rss {
		reserved[rs.ID()] = rs
	}

	unreserved := make([]*RealServerSpec, 0)
	for _, expire := range running {
		if _, ok := reserved[expire.ID()]; !ok {
			unreserved = append(unreserved, expire)
		}
	}
	logger.Info("reserved", reserved, "unreserved", unreserved)

	status := front.add(rss, cp, logger)
	if status != EDPVS_OK {
		return status
	}

	errCode := front.Del(unreserved, cp, logger)
	result := errCode.String()
	logger.Info("Set real servers done", "rss", rss, "result", result)
	return errCode
}
