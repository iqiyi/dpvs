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

	"github.com/dpvs-agent/models"
	"github.com/dpvs-agent/pkg/ipc/pool"
)

type VirtualServerFront struct {
	cid     uint8
	index   uint8
	count   uint16
	padding uint32
}

func NewVirtualServerFront() *VirtualServerFront {
	return &VirtualServerFront{}
}

func (o *VirtualServerFront) Copy(src *VirtualServerFront) bool {
	if src == nil {
		return false
	}

	o.cid = src.cid
	o.index = src.index
	o.count = src.count

	return true
}

func (o *VirtualServerFront) Dump(buf []byte) bool {
	if len(buf) != int(o.Sizeof()) {
		return false
	}

	var tmp *VirtualServerFront = *(**VirtualServerFront)(unsafe.Pointer(&buf))
	return o.Copy(tmp)
}

func (o *VirtualServerFront) SetCid(cid uint8) {
	o.cid = cid
}

func (o *VirtualServerFront) SetIndex(index uint8) {
	o.index = index
}

func (o *VirtualServerFront) SetCount(count uint16) {
	o.count = count
}

func (o *VirtualServerFront) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*o))
}

func (o *VirtualServerFront) Package() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, o)
	return buf.Bytes()
}

func (o *VirtualServerFront) read(conn *pool.Conn, logger hclog.Logger) error {
	conn.SetReadBuffer(int(o.Sizeof()))
	buf, err := conn.ReadN(int(o.Sizeof()))
	if err != nil {
		return err
	}

	if !o.Dump(buf) {
		return errors.New("dump reply virtual server front failed")
	}
	logger.Info("Get Virtual Server Count success", "count", o.count)

	return nil
}
func (o *VirtualServerFront) Write(conn *pool.Conn) error {
	buf := o.Package()

	_, err := conn.WriteN(buf, int(o.Sizeof()))
	if err != nil {
		return err
	}

	return nil
}

type dpvsDestCheck struct {
	types   uint8
	padding [7]byte
}

type VirtualServerSpec struct {
	af              uint32
	proto           uint8
	proxyProto      uint8
	port            uint16
	fwmark          uint32
	flags           uint32
	timeout         uint32
	connTimeout     uint32
	netmask         uint32
	bps             uint32
	limitProportion uint32
	addr            [0x10]byte
	schedName       [0x10]byte
	match           dpvsMatch
	numDests        uint32
	numLaddrs       uint32
	cid             uint64
	stats           dpvsStats
	hc              dpvsDestCheck
}

func NewVirtualServerSpec() *VirtualServerSpec {
	return &VirtualServerSpec{}
}

func (vs *VirtualServerSpec) Convert2NewRsFront() *RealServerFront {
	front := NewRealServerFront()

	front.af = vs.af
	front.port = vs.port
	front.proto = uint16(vs.proto)
	front.fwmark = vs.fwmark
	front.numDests = vs.numDests
	front.cid = uint32(vs.cid)

	front.match.Copy(&vs.match)
	copy(front.addr[:], vs.addr[:])

	return front
}

func (vs *VirtualServerSpec) Copy(src *VirtualServerSpec) bool {
	if src == nil {
		return false
	}

	vs.af = src.af
	vs.proto = src.proto
	vs.port = src.port
	vs.fwmark = src.fwmark
	vs.flags = src.flags
	vs.timeout = src.timeout
	vs.connTimeout = src.connTimeout
	vs.netmask = src.netmask
	vs.bps = src.bps
	vs.limitProportion = src.limitProportion
	vs.numDests = src.numDests
	vs.numLaddrs = src.numLaddrs
	vs.cid = src.cid
	vs.hc = src.hc

	copy(vs.addr[:], src.addr[:])
	copy(vs.schedName[:], src.schedName[:])

	if !vs.match.Copy(&src.match) {
		return false
	}
	if !vs.stats.Copy(&src.stats) {
		return false
	}
	return true
}

func (vs *VirtualServerSpec) ID() string {
	proto := "tcp"
	if vs.proto == unix.IPPROTO_UDP {
		proto = "udp"
	}
	return fmt.Sprintf("%s-%d-%s", vs.GetAddr(), vs.GetPort(), proto)
}

func (vs *VirtualServerSpec) Format(kind string) string {
	/*
	   TCP VIP:PORT sched
	   -> RIP:RPORT Fnat weight actConn inActConn
	   -> RIP:RPORT Fnat weight actConn inActConn
	   ...
	*/

	var vipport string
	vip := vs.GetAddr()
	if vip == "" {
		return ""
	}
	port := vs.GetPort()

	vipport = fmt.Sprintf("%s:%d", vip, port)
	if vs.proto == unix.IPPROTO_TCP {
		vsHeader := fmt.Sprintf("TCP %s %s\r\n", vipport, string(vs.schedName[:]))
		return vsHeader
	}

	return ""
}

func (vs *VirtualServerSpec) Dump(buf []byte) bool {
	if len(buf) != int(vs.Sizeof()) {
		return false
	}

	var tmp *VirtualServerSpec = *(**VirtualServerSpec)(unsafe.Pointer(&buf))

	return vs.Copy(tmp)
}

func (vs *VirtualServerSpec) SetAf(af uint32) {
	vs.af = af
}
func (vs *VirtualServerSpec) GetAf() uint32 {
	return vs.af
}

func (vs *VirtualServerSpec) SetProto(proto uint8) {
	vs.proto = proto
}

func (vs *VirtualServerSpec) SetProxyProto(version string) {
	switch version {
	case models.VirtualServerSpecTinyProxyProtocolV2:
		vs.proxyProto = 2
	case models.VirtualServerSpecTinyProxyProtocolV1:
		vs.proxyProto = 1
	case models.VirtualServerSpecTinyProxyProtocolV2DashInsecure:
		vs.proxyProto = 18
	case models.VirtualServerSpecTinyProxyProtocolV1DashInsecure:
		vs.proxyProto = 17
	default:
		vs.proxyProto = 0
	}
}

func (vs *VirtualServerSpec) SetPort(port uint16) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(port))
	vs.port = binary.BigEndian.Uint16(buf.Bytes())
}

func (vs *VirtualServerSpec) GetPort() uint16 {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(vs.port))
	return binary.BigEndian.Uint16(buf.Bytes())
}

func (vs *VirtualServerSpec) GetProto() uint8 {
	return vs.proto
}

func (vs *VirtualServerSpec) SetFwmark(fwmark uint32) {
	vs.fwmark = fwmark
}
func (vs *VirtualServerSpec) GetFwmark() uint32 {
	return vs.fwmark
}

func (vs *VirtualServerSpec) SetFlagsSynProxy() {
	vs.setFlags(DPVS_SVC_F_SYNPROXY)
}

func (vs *VirtualServerSpec) SetFlagsExpireQuiescent() {
	vs.setFlags(DPVS_SVC_F_EXPIRE_QUIESCENT)
}

func (vs *VirtualServerSpec) SetFlagsQuic() {
	vs.setFlags(DPVS_SVC_F_QUIC)
}

func (vs *VirtualServerSpec) SetFlagsPersistent() {
	vs.setFlags(DPVS_SVC_F_PERSISTENT)
}

func (vs *VirtualServerSpec) SetFlagsHashSrcIP() {
	vs.flags &= ^DPVS_SVC_F_QID_HASH
	vs.flags &= ^DPVS_SVC_F_SIP_HASH

	vs.setFlags(DPVS_SVC_F_SIP_HASH)
}

func (vs *VirtualServerSpec) SetFlagsHashQuicID() {
	vs.flags &= ^DPVS_SVC_F_QID_HASH
	vs.flags &= ^DPVS_SVC_F_SIP_HASH

	vs.setFlags(DPVS_SVC_F_QID_HASH)
}

func (vs *VirtualServerSpec) setFlags(flags uint32) {
	vs.flags |= flags
}

func (vs *VirtualServerSpec) GetFlags() uint32 {
	return vs.flags
}

func (vs *VirtualServerSpec) SetTimeout(t uint32) {
	vs.timeout = t
}
func (vs *VirtualServerSpec) GetTimeout() uint32 {
	return vs.timeout
}

func (vs *VirtualServerSpec) SetConnTimeout(ct uint32) {
	vs.connTimeout = ct
}

func (vs *VirtualServerSpec) GetConnTimeout() uint32 {
	return vs.connTimeout
}

func (vs *VirtualServerSpec) SetNetMask(mask uint32) {
	vs.netmask = mask
}

func (vs *VirtualServerSpec) GetNetMask() uint32 {
	return vs.netmask
}

func (vs *VirtualServerSpec) SetBps(bps uint32) {
	vs.bps = bps
}

func (vs *VirtualServerSpec) GetBps() uint32 {
	return vs.bps
}

func (vs *VirtualServerSpec) SetLimitProportion(limit uint32) {
	vs.limitProportion = limit
}

func (vs *VirtualServerSpec) GetLimitProportion() uint32 {
	return vs.limitProportion
}

func (vs *VirtualServerSpec) SetNumDests(num uint32) {
	vs.numDests = num
}

func (vs *VirtualServerSpec) GetNumDests() uint32 {
	return vs.numDests
}

func (vs *VirtualServerSpec) SetNumLaddrs(num uint32) {
	vs.numLaddrs = num
}

func (vs *VirtualServerSpec) SetCid(cid uint64) {
	vs.cid = cid
}

func (vs *VirtualServerSpec) setNetmask(mask uint32) {
	vs.netmask = mask
}

func (vs *VirtualServerSpec) SetAddr(addr string) {
	if strings.Contains(addr, ":") {
		copy(vs.addr[:], net.ParseIP(addr))
		vs.af = unix.AF_INET6
		vs.setNetmask(128)
		return
	}

	vs.af = unix.AF_INET
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, net.ParseIP(addr))
	copy(vs.addr[:], buf.Bytes()[12:])
	vs.setNetmask(0xFFFFFFFF)
}

func (vs *VirtualServerSpec) GetAddr() string {
	var addr net.IP

	if vs.af == unix.AF_INET {
		addr = net.IPv4(vs.addr[0], vs.addr[1], vs.addr[2], vs.addr[3])
		return addr.String()
	}

	addr = net.IP{vs.addr[0x0], vs.addr[0x1], vs.addr[0x2], vs.addr[0x3],
		vs.addr[0x4], vs.addr[0x5], vs.addr[0x6], vs.addr[0x7],
		vs.addr[0x8], vs.addr[0x9], vs.addr[0xa], vs.addr[0xb],
		vs.addr[0xc], vs.addr[0xd], vs.addr[0xe], vs.addr[0xf],
	}
	return addr.String()
}

func (vs *VirtualServerSpec) GetSchedName() string {
	return TrimRightZeros(string(vs.schedName[:]))
}

func (vs *VirtualServerSpec) GetDestCheck() []models.DestCheckSpec {
	var res []models.DestCheckSpec
	if vs.hc.types&DPVS_DEST_HC_PASSIVE != 0 {
		res = append(res, models.DestCheckSpecPassive)
	}
	if vs.hc.types&DPVS_DEST_HC_TCP != 0 {
		res = append(res, models.DestCheckSpecTCP)
	}
	if vs.hc.types&DPVS_DEST_HC_UDP != 0 {
		res = append(res, models.DestCheckSpecUDP)
	}
	if vs.hc.types&DPVS_DEST_HC_PING != 0 {
		res = append(res, models.DestCheckSpecPing)
	}
	return res
}

func (vs *VirtualServerSpec) SetSchedName(name string) {
	sched := strings.ToLower(name)

	switch strings.ToLower(name) {
	case "rr":
	case "wlc":
	case "conhash":
	case "fo":
	case "mh":
	default:
		sched = "wrr"
	}
	copy(vs.schedName[:], []byte(sched))
}

func (vs *VirtualServerSpec) SetMatch(m *dpvsMatch) {
	vs.match.Copy(m)
}

func (vs *VirtualServerSpec) SetStats(s *dpvsStats) {
	vs.stats.Copy(s)
}

func (vs *VirtualServerSpec) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*vs))
}

func (vs *VirtualServerSpec) ParseVipPortProto(vipport string) error {
	items := strings.Split(vipport, "-")
	if len(items) != 3 {
		return errors.New("invalid vip-port-proto string")
	}

	proto := items[2]

	switch strings.ToLower(proto) {
	case "udp":
		vs.proto = unix.IPPROTO_UDP
	case "tcp":
		fallthrough
	default:
		vs.proto = unix.IPPROTO_TCP
	}

	// port := items[1]
	port, err := strconv.Atoi(items[1])
	if err != nil {
		return err
	}
	vs.SetPort(uint16(port))

	vip := items[0]
	if net.ParseIP(vip) == nil {
		return errors.New(fmt.Sprintf("invalid ip addr: %s\n", vip))
	}
	vs.SetAddr(vip)

	return nil
}

func (vs *VirtualServerSpec) read(conn *pool.Conn, len uint64, logger hclog.Logger) ([]*VirtualServerSpec, error) {
	res := len % vs.Sizeof()
	cnt := len / vs.Sizeof()
	if cnt <= 0 || res != 0 {
		conn.Release(int(len))
		err := errors.New("the buffer may not convert to VirtualServerSpec")
		logger.Error("Read failed", "Error", err.Error())
		return nil, err
	}

	vss := make([]*VirtualServerSpec, cnt)

	for i := 0; i < int(cnt); i++ {
		buf, err := conn.ReadN(int(vs.Sizeof()))
		if err != nil {
			logger.Error("Read VirtualServerSpec() failed", "Error", err.Error())
			return nil, err
		}

		vss[i] = NewVirtualServerSpec()
		if !vss[i].Dump(buf) {
			logger.Error("Dump byte as VirtualServerSpec failed")
			return nil, errors.New("dump reply virtual server failed")
		}
		spec := *vss[i]
		logger.Info("get virtual server success", "spec", spec)
	}

	return vss, nil
}

func (vs *VirtualServerSpec) Write(conn *pool.Conn) error {
	buf := vs.Package()

	_, err := conn.WriteN(buf, int(vs.Sizeof()))
	if err != nil {
		return err
	}

	return nil
}

func (vs *VirtualServerSpec) Package() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, vs)
	return buf.Bytes()
}

/*****************
******************/

func (front *VirtualServerFront) Get(cp *pool.ConnPool, logger hclog.Logger) ([]*VirtualServerSpec, error) {
	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed", "Error", err.Error())
		return nil, err
	}
	defer cp.Remove(ctx, conn, nil)

	msg := NewSockMsg(SOCKOPT_VERSION, DPVSAGENT_SO_GET_SERVICES, SOCKOPT_GET, front.Sizeof())
	err = msg.Write(conn)
	if err != nil {
		logger.Error("Sockopt DPVSAGENT_SO_GET_SERVICEs Write proto header failed", "Error", err.Error())
		return nil, err
	}

	err = front.Write(conn)
	if err != nil {
		logger.Error("Sockopt DPVSAGENT_SO_GET_SERVICEs Write proto bodyfailed", "Error", err.Error())
		return nil, err
	}

	reply := NewReplySockMsg()
	if err := reply.Read(conn); err != nil {
		logger.Error("Sockopt DPVSAGENT_SO_GET_SERVICEs Read proto header failed", "Error", err.Error())
		return nil, err
	}

	if err := front.read(conn, logger); err != nil {
		logger.Error("Sockopt DPVSAGENT_SO_GET_SERVICEs Read vss table header failed", "Error", err.Error())
		return nil, err
	}

	vs := NewVirtualServerSpec()
	return vs.read(conn, uint64(reply.GetLen())-front.Sizeof(), logger)
}

func (vs *VirtualServerSpec) Get(cp *pool.ConnPool, parentLogger hclog.Logger) ([]*VirtualServerSpec, error) {
	logger := hclog.Default().Named(vs.ID())
	if parentLogger != nil {
		logger = parentLogger.Named(vs.ID())
	}

	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed", "Error", err.Error())
		return nil, err
	}
	defer cp.Remove(ctx, conn, nil)
	msg := NewSockMsg(SOCKOPT_VERSION, DPVS_SO_GET_SERVICE, SOCKOPT_GET, vs.Sizeof())
	err = msg.Write(conn)
	if err != nil {
		logger.Error("Sockopt DPVS_SO_GET_SERVICE Write proto header failed", "Error", err.Error())
		return nil, err
	}

	err = vs.Write(conn)
	if err != nil {
		logger.Error("Sockopt DPVS_SO_GET_SERVICE Write proto body failed", "Error", err.Error())
		return nil, err
	}

	reply := NewReplySockMsg()
	if err := reply.Read(conn); err != nil {
		logger.Error("Sockopt DPVS_SO_GET_SERVICE Read failed", "Error", err.Error())
		return nil, err
	}

	return vs.read(conn, uint64(reply.GetLen()), logger)
}

func (vs *VirtualServerSpec) Update(cp *pool.ConnPool, parentLogger hclog.Logger) DpvsErrType {
	logger := hclog.Default().Named(vs.ID())
	if parentLogger != nil {
		logger = parentLogger.Named(vs.ID())
	}

	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed", "Error", err.Error())
		return EDPVS_IO
	}
	defer cp.Remove(ctx, conn, nil)

	msg := NewSockMsg(SOCKOPT_VERSION, DPVS_SO_SET_EDIT, SOCKOPT_SET, vs.Sizeof())

	err = msg.Write(conn)
	if err != nil {
		logger.Error("Sockopt DPVS_SO_SET_EDIT Write proto header failed", "Error", err.Error())
		return EDPVS_IO
	}

	err = vs.Write(conn)
	if err != nil {
		logger.Error("Sockopt DPVS_SO_SET_EDIT Write proto body failed", "Error", err.Error())
		return EDPVS_IO
	}

	reply := NewReplySockMsg()
	err = reply.Read(conn)
	if err != nil {
		logger.Error("Sockopt DPVS_SO_SET_EDIT Read failed", "Error", err.Error())
		return EDPVS_IO
	}
	errCode := reply.GetErrCode()
	result := errCode.String()
	logger.Info("DPVS_SO_SET_EDIT Done", "result", result)
	return errCode
}

func (vs *VirtualServerSpec) Add(cp *pool.ConnPool, parentLogger hclog.Logger) DpvsErrType {
	logger := hclog.Default().Named(vs.ID())
	if parentLogger != nil {
		logger = parentLogger.Named(vs.ID())
	}

	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed", "Error", err.Error())
		return EDPVS_IO
	}
	defer cp.Remove(ctx, conn, nil)

	msg := NewSockMsg(SOCKOPT_VERSION, DPVS_SO_SET_ADD, SOCKOPT_SET, vs.Sizeof())
	err = msg.Write(conn)
	if err != nil {
		logger.Error("Sockopt DPVS_SO_SET_ADD Write proto header failed", "Error", err.Error())
		return EDPVS_IO
	}

	err = vs.Write(conn)
	if err != nil {
		logger.Error("Sockopt DPVS_SO_SET_ADD Write proto body failed", "Error", err.Error())
		return EDPVS_IO
	}

	reply := NewReplySockMsg()
	err = reply.Read(conn)
	if err != nil {
		logger.Error("Sockopt DPVS_SO_SET_ADD Read failed", "Error", err.Error())
		return EDPVS_IO
	}
	errCode := reply.GetErrCode()
	result := errCode.String()

	logger.Info("DPVS_SO_SET_ADD Done", "result", result)
	return errCode
}

func (vs *VirtualServerSpec) Del(cp *pool.ConnPool, logger hclog.Logger) DpvsErrType {
	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed", "Error", err.Error())
		return EDPVS_IO
	}
	defer cp.Remove(ctx, conn, nil)

	msg := NewSockMsg(SOCKOPT_VERSION, DPVS_SO_SET_DEL, SOCKOPT_SET, vs.Sizeof())
	if err := msg.Write(conn); err != nil {
		logger.Error("Sockopt DPVS_SO_SET_DEL write proto header failed", "Error", err.Error())
		return EDPVS_IO
	}

	if err := vs.Write(conn); err != nil {
		logger.Error("Sockopt DPVS_SO_SET_DEL Write body failed", "Error", err.Error())
		return EDPVS_IO
	}

	reply := NewReplySockMsg()
	if err := reply.Read(conn); err != nil {
		logger.Error("Sockopt DPVS_SO_SET_DEL Read reply failed", "Error", err.Error())
		return EDPVS_IO
	}

	errCode := reply.GetErrCode()
	result := errCode.String()

	logger.Info("DPVS_SO_SET_DEL Done", "result", result)
	return errCode
}
