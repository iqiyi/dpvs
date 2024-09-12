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
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"github.com/dpvs-agent/pkg/ipc/pool"
	"github.com/hashicorp/go-hclog"
	"golang.org/x/sys/unix"
)

// The consts mirrors const macros defined in conf/ipset.h
const (
	IPSET_MAXNAMELEN = 32
	IPSET_MAXCOMLEN  = 32

	IPSET_F_FORCE = 0x0001
)

// The consts mirrors `enum ipset_op` defined in conf/ipset.h
const (
	_ uint16 = iota
	IPSET_OP_ADD
	IPSET_OP_DEL
	IPSET_OP_TEST
	IPSET_OP_CREATE
	IPSET_OP_DESTROY
	IPSET_OP_FLUSH
	IPSET_OP_LIST
	IPSET_OP_MAX
)

// InetAddrRange mirrors `struct inet_addr_range` defined in conf/inet.h
type InetAddrRange struct {
	minAddr [16]byte
	maxAddr [16]byte
	minPort uint16
	maxPort uint16
}

func (o *InetAddrRange) SetMinAddr(ip net.IP) {
	if ip == nil {
		return
	}
	if ip4 := ip.To4(); ip4 != nil {
		copy(o.minAddr[:4], ip4[:4])
	} else {
		copy(o.minAddr[:], ip[:])
	}
}

func (o *InetAddrRange) SetMaxAddr(ip net.IP) {
	if ip == nil {
		return
	}
	if ip4 := ip.To4(); ip4 != nil {
		copy(o.maxAddr[:4], ip4[:4])
	} else {
		copy(o.maxAddr[:], ip[:])
	}
}

func (o *InetAddrRange) SetMinPort(port uint16) {
	o.minPort = port
}

func (o *InetAddrRange) SetMaxPort(port uint16) {
	o.maxPort = port
}

func (o *InetAddrRange) Decode(af uint8) (net.IP, net.IP, uint16, uint16) {
	if af == syscall.AF_INET6 {
		minAddr := make(net.IP, net.IPv6len)
		maxAddr := make(net.IP, net.IPv6len)
		copy(minAddr[:], o.minAddr[:16])
		copy(maxAddr[:], o.maxAddr[:16])
		return minAddr, maxAddr, o.minPort, o.maxPort
	} else {
		minAddr := net.IPv4(o.minAddr[0], o.minAddr[1], o.minAddr[2], o.minAddr[3])
		maxAddr := net.IPv4(o.maxAddr[0], o.maxAddr[1], o.maxAddr[2], o.maxAddr[3])
		return minAddr, maxAddr, o.minPort, o.maxPort
	}
	return nil, nil, 0, 0 // never hit
}

func (o *InetAddrRange) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*o))
}

func (o *InetAddrRange) Copy(from *InetAddrRange) bool {
	if from == nil {
		return false
	}
	copy(o.minAddr[:], from.minAddr[:])
	copy(o.maxAddr[:], from.maxAddr[:])
	o.minPort = from.minPort
	o.maxPort = from.maxPort
	return true
}

// IPSetParam mirrors `struct ipset_param` defined in conf/ipset.h
type IPSetParam struct {
	kind    [IPSET_MAXNAMELEN]byte
	name    [IPSET_MAXNAMELEN]byte
	comment [IPSET_MAXCOMLEN]byte
	opcode  uint16
	flag    uint16

	// flat reflection of `struct ipset_option`:
	// ops create: af(8), comment(8), hashSize(4), maxElem(4)
	// ops add: af(8), nomatch(8)
	hashSize         uint32
	maxElem          uint32
	commentOrNomatch uint8
	af               uint8

	proto     uint8
	cidr      uint8
	addrRange InetAddrRange
	iface     [unix.IFNAMSIZ]byte
	macAddr   [6]byte

	// for ipset types with 2 nets
	_          uint8
	cidr2      uint8
	addrRange2 InetAddrRange
}

func (o *IPSetParam) getKind() string {
	return string(bytes.TrimRight(o.kind[:], "\x00"))
}

func (o *IPSetParam) SetKind(kind string) {
	if len(kind) > 0 {
		copy(o.kind[:], kind)
	}
}

func (o *IPSetParam) SetName(name string) {
	if len(name) > 0 {
		copy(o.name[:], name)
	}
}

func (o *IPSetParam) SetComment(comment string) {
	if len(comment) > 0 {
		copy(o.comment[:], comment)
	}
}

func (o *IPSetParam) SetOpcode(opcode uint16) {
	o.opcode = opcode
}

func (o *IPSetParam) SetFlag(flag uint16) {
	o.flag = flag
}

func (o *IPSetParam) AddFlag(flag uint16) {
	o.flag |= flag
}

func (o *IPSetParam) DelFlag(flag uint16) {
	o.flag &= ^flag
}

func (o *IPSetParam) SetAf(af uint8) {
	o.af = af
}

func (o *IPSetParam) SetCommentFlag(enable bool) {
	num := 0
	if enable {
		num = 1
	}
	o.commentOrNomatch = uint8(num)
}

func (o *IPSetParam) SetNomatch(enable bool) {
	num := 0
	if enable {
		num = 1
	}
	o.commentOrNomatch = uint8(num)
}

func (o *IPSetParam) SetHashSize(hashSize uint32) {
	o.hashSize = hashSize
}

func (o *IPSetParam) SetMaxElem(maxElem uint32) {
	o.maxElem = maxElem
}

func (o *IPSetParam) SetProto(proto uint8) {
	o.proto = proto
}

func (o *IPSetParam) SetCidr(cidr uint8) {
	o.cidr = cidr
}

func (o *IPSetParam) GetAddrRange() *InetAddrRange {
	return &o.addrRange
}

func (o *IPSetParam) SetIface(iface string) {
	if len(iface) > 0 {
		copy(o.iface[:], iface)
	}
}

func (o *IPSetParam) SetMacAddr(macAddr string) error {
	n, err := fmt.Sscanf(macAddr, "%02x:%02x:%02x:%02x:%02x:%02x",
		&o.macAddr[0], &o.macAddr[1], &o.macAddr[2],
		&o.macAddr[3], &o.macAddr[4], &o.macAddr[5])
	if err != nil {
		return err
	}
	if n != 6 {
		return fmt.Errorf("string macAddr parsed to %d parts, expected 6", n)
	}
	return nil
}

func (o *IPSetParam) SetCidr2(cidr uint8) {
	o.cidr2 = cidr
}

func (o *IPSetParam) GetAddrRange2() *InetAddrRange {
	return &o.addrRange2
}

func (o *IPSetParam) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*o))
}

func (o *IPSetParam) Copy(from *IPSetParam) bool {
	if from == nil {
		return false
	}
	copy(o.kind[:], from.kind[:])
	copy(o.name[:], from.name[:])
	copy(o.comment[:], from.comment[:])
	o.opcode = from.opcode
	o.flag = from.flag

	o.af = from.af
	o.commentOrNomatch = from.commentOrNomatch
	o.hashSize = from.hashSize
	o.maxElem = from.maxElem

	o.proto = from.proto
	o.cidr = from.cidr
	o.addrRange.Copy(&from.addrRange)
	o.iface = from.iface
	o.macAddr = from.macAddr

	o.cidr2 = from.cidr2
	o.addrRange2.Copy(&from.addrRange2)

	return true
}

func (o *IPSetParam) Dump(buf []byte) bool {
	var to *IPSetParam
	if len(buf) < int(o.Sizeof()) {
		return false
	}
	to = *(**IPSetParam)(unsafe.Pointer(&buf))
	return o.Copy(to)
}

func (o *IPSetParam) Package() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, o)
	return buf.Bytes()
}

func (o *IPSetParam) write(conn *pool.Conn) error {
	buf := o.Package()
	n, err := conn.WriteN(buf, int(o.Sizeof()))
	if err != nil {
		return fmt.Errorf("IPSetParam write error: %v, %d of %d written\n",
			err, n, o.Sizeof())
	}
	return nil
}

type IPSetParamArray []IPSetParam

// IPSetMember mirrors `struct ipset_meber` defined in conf/ipset.h
type IPSetMember struct {
	comment [IPSET_MAXCOMLEN]byte

	addr    [16]byte
	cidr    uint8
	proto   uint8
	port    uint16
	iface   [unix.IFNAMSIZ]byte
	macAddr [6]byte
	nomatch uint8

	// for ipset types with 2 nets
	cidr2 uint8
	port2 uint16
	_     [2]uint8
	addr2 [16]byte
}

func (o *IPSetMember) GetComment() string {
	return string(bytes.TrimRight(o.comment[:], "\x00"))
}

func (o *IPSetMember) GetAddr(af uint8) net.IP {
	if af == syscall.AF_INET6 {
		res := make(net.IP, net.IPv6len)
		copy(res, o.addr[:])
		return res
	}
	return net.IPv4(o.addr[0], o.addr[1], o.addr[2], o.addr[3])
}

func (o *IPSetMember) GetCidr() uint8 {
	return o.cidr
}

func (o *IPSetMember) GetProto() uint8 {
	return o.proto
}

func (o *IPSetMember) GetPort() uint16 {
	return o.port
}

func (o *IPSetMember) GetIface() string {
	return string(bytes.TrimRight(o.iface[:], "\x00"))
}

func (o *IPSetMember) GetMacAddr() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		o.macAddr[0], o.macAddr[1], o.macAddr[2],
		o.macAddr[3], o.macAddr[4], o.macAddr[5])
}

func (o *IPSetMember) GetNoMatch() bool {
	if o.nomatch > 0 {
		return true
	}
	return false
}

func (o *IPSetMember) GetCidr2() uint8 {
	return o.cidr2
}

func (o *IPSetMember) GetPort2() uint16 {
	return o.port2
}

func (o *IPSetMember) GetAddr2(af uint8) net.IP {
	if af == syscall.AF_INET6 {
		res := make(net.IP, net.IPv6len)
		copy(res, o.addr2[:])
		return res
	}
	return net.IPv4(o.addr2[0], o.addr2[1], o.addr2[2], o.addr2[3])
}

func (o *IPSetMember) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*o))
}

func (o *IPSetMember) Copy(from *IPSetMember) bool {
	if from == nil {
		return false
	}

	copy(o.comment[:], from.comment[:])

	copy(o.addr[:], from.addr[:])
	o.cidr = from.cidr
	o.proto = from.proto
	o.port = from.port
	copy(o.iface[:], from.iface[:])
	copy(o.macAddr[:], from.macAddr[:])
	o.nomatch = from.nomatch

	o.cidr2 = from.cidr2
	o.port2 = from.port2
	copy(o.addr2[:], from.addr2[:])

	return true
}

// IPSetInfo mirrors `struct ipset_info` defined in conf/ipset.h
type IPSetInfo struct {
	name    [IPSET_MAXNAMELEN]byte
	kind    [IPSET_MAXNAMELEN]byte
	comment uint8

	af uint8
	_  [2]uint8

	// kind bitmap: cidr(8), addrRange(20)
	// kind hash: hashSize(4), hashMaxElem(4)
	cidr                uint8
	_                   [3]uint8
	hashSizeOrAddrRange uint32
	hashMaxElem         uint32
	__reserved          [28]uint8

	size       uint32
	entries    uint32
	references uint32

	membersPtr uintptr
	members    []IPSetMember
}

func (o *IPSetInfo) GetName() string {
	return string(bytes.TrimRight(o.name[:], "\x00"))
}

func (o *IPSetInfo) GetKind() string {
	return string(bytes.TrimRight(o.kind[:], "\x00"))
}

func (o *IPSetInfo) GetComment() bool {
	if o.comment > 0 {
		return true
	}
	return false
}

func (o *IPSetInfo) GetAf() uint8 {
	return o.af
}

func (o *IPSetInfo) GetCidr() uint8 {
	return o.cidr
}

func (o *IPSetInfo) GetAddrRange() (net.IP, net.IP, uint16, uint16) {
	iaRange := (*InetAddrRange)(unsafe.Pointer(uintptr(unsafe.Pointer(&o.hashSizeOrAddrRange))))
	return iaRange.Decode(o.af)
}

func (o *IPSetInfo) GetHashSize() uint32 {
	return o.hashSizeOrAddrRange
}

func (o *IPSetInfo) GetSize() uint32 {
	return o.size
}

func (o *IPSetInfo) GetEntries() uint32 {
	return o.entries
}

func (o *IPSetInfo) GetReferences() uint32 {
	return o.references
}

func (o *IPSetInfo) GetHashMaxElem() uint32 {
	return o.hashMaxElem
}

func (o *IPSetInfo) GetMembers() []IPSetMember {
	return o.members
}

func (o *IPSetInfo) Sizeof() uint64 {
	return uint64(unsafe.Offsetof(o.members))
}

func (o *IPSetInfo) Copy(from *IPSetInfo) bool {
	if from == nil {
		return false
	}

	copy(o.name[:], from.name[:])
	copy(o.kind[:], from.kind[:])
	o.comment = from.comment

	o.af = from.af

	o.cidr = from.cidr
	o.hashSizeOrAddrRange = from.hashSizeOrAddrRange
	o.hashMaxElem = from.hashMaxElem
	copy(o.__reserved[:], from.__reserved[:])

	o.size = from.size
	o.entries = from.entries
	o.references = from.references

	//// Note:
	////   Do NOT copy members! They are not in C struct.
	//	o.members = make([]IPSetMember, len(from.members))
	//	for i, _ := range from.members {
	//		o.members[i].Copy(&from.members[i])
	//	}

	return true
}

// IPSetInfoArray interprets `struct ipset_info_array` defined in conf/ipset.h
type IPSetInfoArray struct {
	infos []IPSetInfo
}

func (o *IPSetInfoArray) GetIPSetInfos() []IPSetInfo {
	return o.infos
}

func (o *IPSetInfoArray) read(conn *pool.Conn, logger hclog.Logger) error {
	var info *IPSetInfo
	var member *IPSetMember
	var i, j, nipset uint32
	var offset uint64

	dataLen := uint64(unsafe.Sizeof(nipset))
	buf, err := conn.ReadN(int(dataLen))
	if err != nil {
		return fmt.Errorf("Read IPSetInfo number failed: %v", err)
	}
	nipset = binary.LittleEndian.Uint32(buf[:dataLen])
	if nipset == 0 {
		return nil
	}

	// read IPSetInfo data
	dataLen = (uint64(nipset)) * info.Sizeof()
	buf, err = conn.ReadN(int(dataLen))
	if err != nil {
		return fmt.Errorf("Read IPSetInfo data failed: %v", err)
	}

	dataLen = 0
	offset = 0
	o.infos = make([]IPSetInfo, nipset)
	for i = 0; i < nipset; i++ {
		info = (*IPSetInfo)(unsafe.Pointer(uintptr(unsafe.Pointer(&buf[offset]))))
		o.infos[i].Copy(info)
		offset += info.Sizeof()
		dataLen += uint64(info.entries) * member.Sizeof()
	}
	if dataLen == 0 {
		return nil
	}

	// read IPSetMember data
	buf, err = conn.ReadN(int(dataLen))
	if err != nil {
		return fmt.Errorf("Read IPSetMember data failed: %v", err)
	}
	offset = 0
	for i = 0; i < nipset; i++ {
		o.infos[i].members = make([]IPSetMember, o.infos[i].entries)
		for j = 0; j < o.infos[i].entries; j++ {
			member = (*IPSetMember)(unsafe.Pointer(uintptr(unsafe.Pointer(&buf[offset]))))
			o.infos[i].members[j].Copy(member)
			offset += member.Sizeof()
		}
	}

	return nil
}

type CheckResult int32

func (o *CheckResult) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*o))
}

func (o *CheckResult) Dump(buf []byte) bool {
	if len(buf) != int(o.Sizeof()) {
		return false
	}
	reader := bytes.NewReader(buf)
	if err := binary.Read(reader, binary.LittleEndian, o); err != nil {
		return false
	}
	return true
}

func (o *CheckResult) read(conn *pool.Conn, logger hclog.Logger) error {
	buf, err := conn.ReadN(int(o.Sizeof()))
	if err != nil {
		return fmt.Errorf("Read ipset check result failed: %v", err)
	}
	if o.Dump(buf) != true {
		return fmt.Errorf("Dump ipset check result failed")
	}
	return nil
}

func getLogger(name string, parent hclog.Logger) hclog.Logger {
	if parent != nil {
		return parent.Named(name)
	}
	return hclog.Default().Named(name)
}

func (o *IPSetParam) Get(cp *pool.ConnPool, parentLogger hclog.Logger) (*IPSetInfoArray, error, DpvsErrType) {
	logger := getLogger("ipset:get", parentLogger)

	if o.opcode != IPSET_OP_LIST {
		logger.Error("Invalid ipset opcode for Get", "opcode", o.opcode)
		return nil, fmt.Errorf("invalid ipset opcode %d for get", o.opcode), 0
	}

	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed", "Error", err.Error())
		return nil, err, 0
	}
	defer cp.Remove(ctx, conn, nil)

	msg := NewSockMsg(SOCKOPT_VERSION, SOCKOPT_GET_IPSET_LIST, SOCKOPT_GET, o.Sizeof())
	if err = msg.Write(conn); err != nil {
		logger.Error("SOCKOPT_GET_IPSET_LIST write proto header failed", "Error", err.Error())
		return nil, err, 0
	}

	if err = o.write(conn); err != nil {
		logger.Error("SOCKOPT_GET_IPSET_LIST write ipset param failed", "Error", err.Error())
		return nil, err, 0
	}

	reply := NewReplySockMsg()
	if err = reply.Read(conn); err != nil {
		logger.Error("SOCKOPT_GET_IPSET_LIST read reply header failed", "Error", err.Error())
		return nil, err, 0
	}
	if reply.GetErrCode() != EDPVS_OK {
		errStr := reply.GetErrStr()
		logger.Error("SOCKOPT_GET_IPSET_LIST replied error", "DPVS.Error", errStr)
		return nil, fmt.Errorf("DPVS Response Error: %s", errStr), reply.GetErrCode()
	}

	output := &IPSetInfoArray{}
	if reply.GetLen() > 0 {
		err = output.read(conn, logger)
		if err != nil {
			logger.Error("SOCKOPT_GET_IPSET_LIST read reply data failed", "Error", err.Error())
			return nil, err, 0
		}
	}
	return output, nil, 0
}

func (o *IPSetParam) CreateDestroy(cp *pool.ConnPool, parentLogger hclog.Logger) (error, DpvsErrType) {
	if o.opcode != IPSET_OP_CREATE && o.opcode != IPSET_OP_DESTROY {
		return fmt.Errorf("invalid ipset opcode %d for Create/Destroy", o.opcode), 0
	}
	logName := "ipset:create"
	if o.opcode == IPSET_OP_DESTROY {
		logName = "ipset:destroy"
	}
	logger := getLogger(logName, parentLogger)

	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed", "Error", err.Error())
		return err, 0
	}
	defer cp.Remove(ctx, conn, nil)

	msg := NewSockMsg(SOCKOPT_VERSION, SOCKOPT_SET_IPSET, SOCKOPT_SET, o.Sizeof())
	if err = msg.Write(conn); err != nil {
		logger.Error("SOCKOPT_SET_IPSET write proto header failed", "Error", err.Error())
		return err, 0
	}

	if err = o.write(conn); err != nil {
		logger.Error("SOCKOPT_SET_IPSET write ipset param failed", "Error", err.Error())
		return err, 0
	}

	reply := NewReplySockMsg()
	if err = reply.Read(conn); err != nil {
		logger.Error("SOCKOPT_SET_IPSET read reply header failed", "Error", err.Error())
		return err, 0
	}
	dpvsErrCode := reply.GetErrCode()
	if dpvsErrCode != EDPVS_OK {
		/*
			if !(dpvsErrCode == EDPVS_EXIST && o.opcode == IPSET_OP_CREATE ||
				dpvsErrCode == EDPVS_NOTEXIST && o.opcode == IPSET_OP_DESTROY) {
				errStr := reply.GetErrStr()
				logger.Error("SOCKOPT_SET_IPSET replied error", "DPVS.Error", errStr)
				return fmt.Errorf("DPVS Response Error: %s", errStr), reply.GetErrCode()
			}
		*/
		errStr := reply.GetErrStr()
		logger.Error("SOCKOPT_SET_IPSET replied error", "DPVS.Error", errStr)
		return fmt.Errorf("DPVS Response Error: %s", errStr), reply.GetErrCode()
	}
	return nil, 0
}

func (o *IPSetParam) IsIn(cp *pool.ConnPool, parentLogger hclog.Logger) (bool, error, DpvsErrType) {
	logger := getLogger("ipset:isin", parentLogger)

	result := false
	if o.opcode != IPSET_OP_TEST {
		logger.Error("Invalid ipset opcode for TEST", "opcode", o.opcode)
		return result, fmt.Errorf("invalid ipset opcode %d for TEST", o.opcode), 0
	}

	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed", "Error", err.Error())
		return result, err, 0
	}
	defer cp.Remove(ctx, conn, nil)

	msg := NewSockMsg(SOCKOPT_VERSION, SOCKOPT_GET_IPSET_TEST, SOCKOPT_GET, o.Sizeof())
	if err = msg.Write(conn); err != nil {
		logger.Error("SOCKOPT_GET_IPSET_TEST write proto header failed", "Error", err.Error())
		return result, err, 0
	}

	if err = o.write(conn); err != nil {
		logger.Error("SOCKOPT_GET_IPSET_TEST write ipset param failed", "Error", err.Error())
		return result, err, 0
	}

	reply := NewReplySockMsg()
	if err = reply.Read(conn); err != nil {
		logger.Error("SOCKOPT_GET_IPSET_TEST read reply header failed", "Error", err.Error())
		return result, err, 0
	}
	if reply.GetErrCode() != EDPVS_OK {
		errStr := reply.GetErrStr()
		logger.Error("SOCKOPT_GET_IPSET_TEST replied error", "DPVS.Error", errStr)
		return result, fmt.Errorf("DPVS Response Error: %s", errStr), reply.GetErrCode()
	}

	var output CheckResult
	err = output.read(conn, logger)
	if err != nil {
		logger.Error("SOCKOPT_GET_IPSET_LIST read reply data failed", "Error", err.Error())
		return result, err, 0
	}
	if output > 0 {
		result = true
	}
	return result, nil, 0
}

func (o *IPSetParamArray) AddDelMember(cp *pool.ConnPool, parentLogger hclog.Logger) (error, DpvsErrType) {
	if len(*o) == 0 {
		return nil, 0
	}
	opcode := (*o)[0].opcode
	if opcode != IPSET_OP_ADD && opcode != IPSET_OP_DEL {
		return fmt.Errorf("invalid ipset opcode %d for Add/Del", opcode), 0
	}
	name := (*o)[0].name
	for _, param := range *o {
		if opcode != param.opcode {
			return fmt.Errorf("ipset opcode in param array did not match for Add/Del"), 0
		}
		if !bytes.Equal(name[:], param.name[:]) {
			return fmt.Errorf("ipset name in param array did not match for Add/Del"), 0
		}
	}

	logName := "ipset:add"
	if opcode == IPSET_OP_DEL {
		logName = "ipset:del"
	}
	logger := getLogger(logName, parentLogger)

	for _, param := range *o {
		ctx := context.Background()
		conn, err := cp.Get(ctx)
		if err != nil {
			logger.Error("Get conn from pool failed", "Error", err.Error())
			return err, 0
		}

		msg := NewSockMsg(SOCKOPT_VERSION, SOCKOPT_SET_IPSET, SOCKOPT_SET, param.Sizeof())
		if err = msg.Write(conn); err != nil {
			logger.Error("SOCKOPT_SET_IPSET write proto header failed", "Error", err.Error())
			cp.Remove(ctx, conn, nil)
			return err, 0
		}

		if err = param.write(conn); err != nil {
			logger.Error("SOCKOPT_SET_IPSET write ipset param failed", "Error", err.Error())
			cp.Remove(ctx, conn, nil)
			return err, 0
		}

		reply := NewReplySockMsg()
		if err = reply.Read(conn); err != nil {
			logger.Error("SOCKOPT_SET_IPSET read reply header failed", "Error", err.Error())
			cp.Remove(ctx, conn, nil)
			return err, 0
		}
		cp.Remove(ctx, conn, nil)

		dpvsErrCode := reply.GetErrCode()
		if dpvsErrCode != EDPVS_OK {
			/*
				if dpvsErrCode == EDPVS_EXIST && opcode == IPSET_OP_ADD ||
					dpvsErrCode == EDPVS_NOTEXIST && opcode == IPSET_OP_DEL {
					continue
				}
			*/
			errStr := reply.GetErrStr()
			logger.Error("SOCKOPT_SET_IPSET replied error", "DPVS.Error", errStr)
			return fmt.Errorf("DPVS Response Error: %s", errStr), reply.GetErrCode()
		}
	}
	return nil, 0
}

func (o *IPSetParamArray) ReplaceMember(cp *pool.ConnPool, parentLogger hclog.Logger) (error, DpvsErrType) {
	if len(*o) == 0 {
		return nil, 0
	}
	opcode := (*o)[0].opcode
	if opcode != IPSET_OP_ADD && opcode != IPSET_OP_FLUSH {
		return fmt.Errorf("invalid ipset opcode %d for Replace", opcode), 0
	}
	name := (*o)[0].name
	for i, param := range *o {
		if i == 0 {
			continue
		}
		if opcode != param.opcode {
			return fmt.Errorf("ipset opcode in param array did not match for Replace"), 0
		}
		if !bytes.Equal(name[:], param.name[:]) {
			return fmt.Errorf("ipset name in param array did not match for Repalce"), 0
		}
	}

	logger := getLogger("replace", parentLogger)

	// Flush the whole ipset
	param := &IPSetParam{}
	param.Copy(&(*o)[0])
	param.opcode = IPSET_OP_FLUSH

	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed", "Error", err.Error())
		return err, 0
	}

	msg := NewSockMsg(SOCKOPT_VERSION, SOCKOPT_SET_IPSET, SOCKOPT_SET, param.Sizeof())
	if err = msg.Write(conn); err != nil {
		logger.Error("SOCKOPT_SET_IPSET write proto header failed", "Error", err.Error())
		cp.Remove(ctx, conn, nil)
		return err, 0
	}

	if err = param.write(conn); err != nil {
		logger.Error("SOCKOPT_SET_IPSET write ipset param failed", "Error", err.Error())
		cp.Remove(ctx, conn, nil)
		return err, 0
	}

	reply := NewReplySockMsg()
	if err = reply.Read(conn); err != nil {
		logger.Error("SOCKOPT_SET_IPSET read reply header failed", "Error", err.Error())
		cp.Remove(ctx, conn, nil)
		return err, 0
	}
	cp.Remove(ctx, conn, nil)

	if reply.GetErrCode() != EDPVS_OK {
		errStr := reply.GetErrStr()
		logger.Error("SOCKOPT_SET_IPSET replied error", "DPVS.Error", errStr)
		return fmt.Errorf("DPVS Response Error: %s", errStr), reply.GetErrCode()
	}

	if opcode != IPSET_OP_ADD {
		return nil, 0
	}

	// Add members into ipset
	for _, param := range *o {
		ctx := context.Background()
		conn, err := cp.Get(ctx)
		if err != nil {
			logger.Error("Get conn from pool failed", "Error", err.Error())
			return err, 0
		}

		msg := NewSockMsg(SOCKOPT_VERSION, SOCKOPT_SET_IPSET, SOCKOPT_SET, param.Sizeof())
		if err = msg.Write(conn); err != nil {
			logger.Error("SOCKOPT_SET_IPSET write proto header failed", "Error", err.Error())
			cp.Remove(ctx, conn, nil)
			return err, 0
		}

		if err = param.write(conn); err != nil {
			logger.Error("SOCKOPT_SET_IPSET write ipset param failed", "Error", err.Error())
			cp.Remove(ctx, conn, nil)
			return err, 0
		}

		reply := NewReplySockMsg()
		if err = reply.Read(conn); err != nil {
			logger.Error("SOCKOPT_SET_IPSET read reply header failed", "Error", err.Error())
			cp.Remove(ctx, conn, nil)
			return err, 0
		}
		cp.Remove(ctx, conn, nil)

		dpvsErrCode := reply.GetErrCode()
		if dpvsErrCode != EDPVS_OK {
			errStr := reply.GetErrStr()
			logger.Error("SOCKOPT_SET_IPSET replied error", "DPVS.Error", errStr)
			return fmt.Errorf("DPVS Response Error: %s", errStr), reply.GetErrCode()
		}
	}
	return nil, 0
}
