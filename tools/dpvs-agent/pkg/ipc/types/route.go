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

type RouteAddr struct {
	addr [0x10]byte
	plen uint32 // prefix len
}

func (o *RouteAddr) Copy(src *RouteAddr) bool {
	o.plen = src.plen
	copy(o.addr[:], src.addr[:])
	return true
}

type RouteDetail struct {
	af      uint32
	mtu     uint32
	flags   uint32
	metric  uint32
	dst     RouteAddr
	src     RouteAddr
	gateway RouteAddr
	prefSrc RouteAddr
	ifName  [0x10]byte
}

func NewRouteDetail() *RouteDetail {
	return &RouteDetail{}
}

func (o *RouteDetail) GetIfName() string {
	return TrimRightZeros(string(o.ifName[:]))
}

func (o *RouteDetail) GetSrc() string {
	var addr net.IP

	if o.af == unix.AF_INET {
		addr = net.IPv4(o.src.addr[0], o.src.addr[1], o.src.addr[2], o.src.addr[3])
		return addr.String()
	}

	addr = net.IP{o.src.addr[0x0], o.src.addr[0x1], o.src.addr[0x2], o.src.addr[0x3],
		o.src.addr[0x4], o.src.addr[0x5], o.src.addr[0x6], o.src.addr[0x7],
		o.src.addr[0x8], o.src.addr[0x9], o.src.addr[0xa], o.src.addr[0xb],
		o.src.addr[0xc], o.src.addr[0xd], o.src.addr[0xe], o.src.addr[0xf],
	}
	return addr.String()
}

func (o *RouteDetail) GetDst() string {
	var addr net.IP

	if o.af == unix.AF_INET {
		addr = net.IPv4(o.dst.addr[0], o.dst.addr[1], o.dst.addr[2], o.dst.addr[3])
		return addr.String()
	}

	addr = net.IP{o.dst.addr[0x0], o.dst.addr[0x1], o.dst.addr[0x2], o.dst.addr[0x3],
		o.dst.addr[0x4], o.dst.addr[0x5], o.dst.addr[0x6], o.dst.addr[0x7],
		o.dst.addr[0x8], o.dst.addr[0x9], o.dst.addr[0xa], o.dst.addr[0xb],
		o.dst.addr[0xc], o.dst.addr[0xd], o.dst.addr[0xe], o.dst.addr[0xf],
	}
	return addr.String()
}

func (o *RouteDetail) Copy(src *RouteDetail) bool {
	o.af = src.af
	o.mtu = src.mtu
	o.flags = src.flags
	o.metric = src.metric
	o.dst.Copy(&src.dst)
	o.src.Copy(&src.src)
	o.gateway.Copy(&src.gateway)
	o.prefSrc.Copy(&src.prefSrc)
	copy(o.ifName[:], src.ifName[:])
	return true
}

func (o *RouteDetail) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*o))
}

func (o *RouteDetail) Dump(buf []byte) bool {
	if len(buf) != int(o.Sizeof()) {
		return false
	}

	var tmp *RouteDetail = *(**RouteDetail)(unsafe.Pointer(&buf))

	return o.Copy(tmp)
}

func (o *RouteDetail) Package() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, o)
	return buf.Bytes()
}

func (o *RouteDetail) SetAf(af uint32) {
	o.af = af
}

func (o *RouteDetail) SetMtu(mtu uint32) {
	o.mtu = mtu
}

func (o *RouteDetail) SetFlags(flags uint32) {
	// FIXME o.flags ^= o.flags first ???
	o.flags |= flags
}

func (o *RouteDetail) SetMetric(metric uint32) {
	o.metric = metric
}

func (o *RouteDetail) SetScope(scope string) {
	switch strings.ToLower(scope) {
	case "host":
		o.SetFlags(RTF_LOCALIN)
	case "kni_host":
		o.SetFlags(RTF_KNI)
	default:
		/*case "global":*/
		/*case "link":*/
		o.SetFlags(RTF_FORWARD)
	}
}

func (o *RouteDetail) SetDst(dst string) {
	addr := dst
	plen := "32"
	if strings.Index(dst, "/") != -1 {
		addr = dst[:strings.Index(dst, "/")]
		plen = dst[strings.Index(dst, "/")+1:]
	}

	if strings.Contains(addr, ":") {
		o.SetAf(unix.AF_INET6)
		copy(o.dst.addr[:], net.ParseIP(addr))
	} else {
		o.SetAf(unix.AF_INET)
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, net.ParseIP(addr))
		copy(o.dst.addr[:], buf.Bytes()[12:])
	}

	mask, err := strconv.Atoi(plen)
	if err != nil {
		o.dst.plen = 32
	}
	o.dst.plen = uint32(mask)
}

func (o *RouteDetail) SetSrc(src string) bool {
	if len(src) == 0 {
		return false
	}

	if strings.Contains(src, ":") {
		o.SetAf(unix.AF_INET6)
		copy(o.src.addr[:], net.ParseIP(src))
	} else {
		o.SetAf(unix.AF_INET)
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, net.ParseIP(src))
		copy(o.src.addr[:], buf.Bytes()[12:])
	}

	return true
}

func (o *RouteDetail) SetGateway(gw string) bool {
	if len(gw) == 0 {
		return false
	}

	if strings.Contains(gw, ":") {
		o.SetAf(unix.AF_INET6)
		copy(o.gateway.addr[:], net.ParseIP(gw))
	} else {
		o.SetAf(unix.AF_INET)
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, net.ParseIP(gw))
		copy(o.gateway.addr[:], buf.Bytes()[12:])
	}
	return true
}

func (o *RouteDetail) SetPrefSrc(pref string) {
	if len(pref) == 0 {
		return
	}

	if strings.Contains(pref, ":") {
		o.SetAf(unix.AF_INET6)
		copy(o.prefSrc.addr[:], net.ParseIP(pref))
	} else {
		o.SetAf(unix.AF_INET)
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, net.ParseIP(pref))
		copy(o.prefSrc.addr[:], buf.Bytes()[12:])
	}
}

func (o *RouteDetail) SetDevice(name string) {
	copy(o.ifName[:], name[:])
}

func (o *RouteDetail) Read(conn *pool.Conn, len uint64) ([]*RouteDetail, error) {
	res := len % o.Sizeof()
	cnt := len / o.Sizeof()
	if cnt <= 0 || res != 0 {
		conn.Release(int(len))
		return nil, errors.New("Wrong buffer size to read, may not convert to RouteDetail")
	}

	details := make([]*RouteDetail, cnt)
	for i := 0; i < int(cnt); i++ {
		buf, err := conn.ReadN(int(o.Sizeof()))
		if err != nil {
			continue
		}
		details[i] = NewRouteDetail()
		details[i].Dump(buf)
	}

	return details, nil
}

func (o *RouteDetail) Write(conn *pool.Conn) error {
	buf := o.Package()
	_, err := conn.WriteN(buf, int(o.Sizeof()))
	if err != nil {
		return err
	}
	return nil
}

type RouteFront struct {
	count uint32
}

func NewRouteFront() *RouteFront {
	return &RouteFront{}
}

func (o *RouteFront) Copy(src *RouteFront) bool {
	o.count = src.count
	return true
}

func (o *RouteFront) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*o))
}

func (o *RouteFront) Dump(buf []byte) bool {
	if len(buf) != int(o.Sizeof()) {
		return false
	}

	var tmp *RouteFront = *(**RouteFront)(unsafe.Pointer(&buf))

	return o.Copy(tmp)
}

func (o *RouteFront) Package() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, o)
	return buf.Bytes()
}

func (o *RouteFront) SetCount(c uint32) {
	o.count = c
}

func (o *RouteFront) GetCount() uint32 {
	return o.count
}

func (o *RouteFront) Read(conn *pool.Conn, len uint64) ([]*RouteFront, error) {
	res := len % o.Sizeof()
	cnt := len / o.Sizeof()
	if cnt <= 0 || res != 0 {
		conn.Release(int(len))
		return nil, errors.New("Wrong buffer size to read, may not convert to RouteFront")
	}

	fronts := make([]*RouteFront, cnt)

	for i := 0; i < int(cnt); i++ {
		buf, err := conn.ReadN(int(o.Sizeof()))
		if err != nil {
			continue
		}
		fronts[i] = NewRouteFront()
		fronts[i].Dump(buf)
	}

	return fronts, nil
}

func (o *RouteFront) Write(conn *pool.Conn) error {
	buf := o.Package()
	_, err := conn.WriteN(buf, int(o.Sizeof()))
	if err != nil {
		return err
	}
	return nil
}

/****************
****************/
func (o *RouteDetail) Get(cp *pool.ConnPool, parentLogger hclog.Logger) ([]*RouteDetail, error) {
	traceName := o.GetIfName()
	logger := hclog.Default().Named(traceName)
	if parentLogger != nil {
		logger = parentLogger.Named(traceName)
	}

	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed", "Error", err.Error())
		return nil, err
	}
	defer cp.Remove(ctx, conn, nil)

	var GET uint32
	GET = DPVSAGENT_ROUTE_GET
	if o.af == unix.AF_INET6 {
		GET = DPVSAGENT_ROUTE6_GET
	}

	msg := NewSockMsg(SOCKOPT_VERSION, GET, SOCKOPT_GET, o.Sizeof())
	if err := msg.Write(conn); err != nil {
		logger.Error("Sockopt ", GET, "Write proto header failed", "Error", err.Error())
		return nil, err
	}

	if err := o.Write(conn); err != nil {
		logger.Error("Sockopt ", GET, "Write proto body failed", "Error", err.Error())
		return nil, err
	}

	reply := NewReplySockMsg()
	if err := reply.Read(conn); err != nil {
		logger.Error("Sockopt ", GET, "Read proto header failed", "Error", err.Error())
		return nil, err
	}

	if reply.GetErrCode() != EDPVS_OK {
		result := reply.GetErrStr()
		logger.Error("Sockopt ", GET, " failed", "result", result)
		err := fmt.Errorf("Sockopt %s reply ErrorCode: %s", GET, result)
		return nil, err
	}

	front := NewRouteFront()
	_, err = front.Read(conn, front.Sizeof())
	if err != nil {
		logger.Error("Sockopt ", GET, "read list header failed", "Error", err.Error())
		return nil, err
	}

	return o.Read(conn, uint64(reply.GetLen())-front.Sizeof())
}

func (o *RouteDetail) Add(cp *pool.ConnPool, parentLogger hclog.Logger) DpvsErrType {
	traceName := fmt.Sprintf("add %s via %s dev %s", o.GetSrc(), o.GetDst(), o.GetIfName())
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

	var ADD uint32
	ADD = DPVSAGENT_ROUTE_ADD
	if o.af == unix.AF_INET6 {
		ADD = DPVSAGENT_ROUTE6_ADD
	}

	msg := NewSockMsg(SOCKOPT_VERSION, ADD, SOCKOPT_SET, o.Sizeof())
	err = msg.Write(conn)
	if err != nil {
		logger.Error("Sockopt ", ADD, "Write proto header failed", "Error", err.Error())
		return EDPVS_IO
	}
	err = o.Write(conn)
	if err != nil {
		logger.Error("Sockopt ", ADD, "Write proto body failed", "Error", err.Error())
		return EDPVS_IO
	}

	reply := NewReplySockMsg()
	err = reply.Read(conn)
	if err != nil {
		logger.Error("Sockopt ", ADD, "reply failed", "Error", err.Error())
		return EDPVS_IO
	}

	return reply.GetErrCode()
}

func (o *RouteDetail) Del(cp *pool.ConnPool, parentLogger hclog.Logger) DpvsErrType {
	traceName := fmt.Sprintf("del %s via %s dev %s", o.GetSrc(), o.GetDst(), o.GetIfName())
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

	var DEL uint32
	DEL = DPVSAGENT_ROUTE_DEL
	if o.af == unix.AF_INET6 {
		DEL = DPVSAGENT_ROUTE6_DEL
	}

	msg := NewSockMsg(SOCKOPT_VERSION, DEL, SOCKOPT_SET, o.Sizeof())
	err = msg.Write(conn)
	if err != nil {
		logger.Error("Sockopt ", DEL, "Write proto header failed", "Error", err.Error())
		return EDPVS_IO
	}

	err = o.Write(conn)
	if err != nil {
		logger.Error("Sockopt ", DEL, "Write proto body failed", "Error", err.Error())
		return EDPVS_IO
	}

	reply := NewReplySockMsg()
	err = reply.Read(conn)
	if err != nil {
		logger.Error("Sockopt ", DEL, "reply failed", "Error", err.Error())
		return EDPVS_IO
	}

	return reply.GetErrCode()
}
