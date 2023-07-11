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
	// "errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/hashicorp/go-hclog"

	"github.com/dpvs-agent/pkg/ipc/pool"
)

type NetifNicDesc struct {
	name  [0x20]byte
	mac   [0x12]byte
	flags uint16
}

func NewNetifNicDesc() *NetifNicDesc {
	return &NetifNicDesc{}
}

func (o *NetifNicDesc) Copy(src *NetifNicDesc) bool {
	o.flags = src.flags
	copy(o.name[:], src.name[:])
	copy(o.mac[:], src.mac[:])
	return true
}

func (o *NetifNicDesc) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*o))
}

func (o *NetifNicDesc) Dump(buf []byte) bool {
	if len(buf) != int(o.Sizeof()) {
		return false
	}

	var tmp *NetifNicDesc = *(**NetifNicDesc)(unsafe.Pointer(&buf))

	return o.Copy(tmp)
}

func (o *NetifNicDesc) Package() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, o)
	return buf.Bytes()
}

func (o *NetifNicDesc) SetName(device string) {
	copy(o.name[:], device[:])
}

func (o *NetifNicDesc) SetMac(mac string) {
	// not set in user plane
}

func (o *NetifNicDesc) SetPromisc(device, flags string) bool {
	o.SetName(device)
	switch strings.ToLower(flags) {
	case "on", "up", "true":
		o.setFlags("promisc_on")
		return true
	case "off", "down", "false":
		o.setFlags("promisc_off")
		return true
	case "unset":
		return false
	default:
		return false
	}
	return false
}

func (o *NetifNicDesc) SetLink(device, flags string) bool {
	o.SetName(device)
	switch strings.ToLower(flags) {
	case "on", "up", "true":
		o.setFlags("link_status_up")
		return true
	case "off", "down", "false":
		o.setFlags("link_status_down")
		return true
	case "unset":
		return false
	default:
		return false
	}
	return false
}

func (o *NetifNicDesc) SetFwd2Kni(device, flags string) bool {
	o.SetName(device)
	switch strings.ToLower(flags) {
	case "on", "up", "true":
		o.setFlags("forward2kni_on")
		return true
	case "off", "down", "false":
		o.setFlags("forward2kni_off")
		return true
	case "unset":
		return false
	default:
		return false
	}
	return false
}

func (o *NetifNicDesc) SetTcEgress(device, flags string) bool {
	o.SetName(device)
	switch strings.ToLower(flags) {
	case "on", "up", "true":
		o.setFlags("tc_egress_on")
		return true
	case "off", "down", "false":
		o.setFlags("tc_egress_off")
		return true
	case "unset":
		return false
	default:
		return false
	}
	return false
}

func (o *NetifNicDesc) SetTcIngress(device, flags string) bool {
	o.SetName(device)
	switch strings.ToLower(flags) {
	case "on", "up", "true":
		o.setFlags("tc_ingress_on")
		return true
	case "off", "down", "false":
		o.setFlags("tc_ingress_off")
		return true
	case "unset":
		return false
	default:
		return false
	}
	return false
}

func (o *NetifNicDesc) setFlags(flags string) {
	bak := o.flags

	o.flags = o.flags ^ o.flags

	switch strings.ToLower(flags) {
	case "promisc_on":
		o.flags |= NETIF_NIC_PROMISC_ON
	case "promisc_off":
		o.flags |= NETIF_NIC_PROMISC_OFF
	case "link_status_up":
		o.flags |= NETIF_NIC_LINK_UP
	case "link_status_down":
		o.flags |= NETIF_NIC_LINK_DOWN
	case "forward2kni_on":
		o.flags |= NETIF_NIC_FWD2KNI_ON
	case "forward2kni_off":
		o.flags |= NETIF_NIC_FWD2KNI_OFF
	case "tc_egress_on":
		o.flags |= NETIF_NIC_TC_EGRESS_ON
	case "tc_egress_off":
		o.flags |= NETIF_NIC_TC_EGRESS_OFF
	case "tc_ingress_on":
		o.flags |= NETIF_NIC_TC_INGRESS_ON
	case "tc_ingress_off":
		o.flags |= NETIF_NIC_TC_INGRESS_OFF
	default:
		o.flags |= bak
	}
}

func (o *NetifNicDesc) write(conn *pool.Conn, logger hclog.Logger) error {
	buf := o.Package()
	_, err := conn.WriteN(buf, int(o.Sizeof()))
	if err != nil {
		return err
	}
	return nil
}

func (o *NetifNicDesc) Set(cp *pool.ConnPool, logger hclog.Logger) DpvsErrType {
	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed:", err.Error())
		return EDPVS_IO
	}
	defer cp.Remove(ctx, conn, nil)

	var SET uint32
	SET = SOCKOPT_NETIF_SET_PORT

	msg := NewSockMsg(SOCKOPT_VERSION, SET, SOCKOPT_SET, o.Sizeof())
	err = msg.Write(conn)
	if err != nil {
		logger.Error("Sockopt SOCKOPT_NETIF_SET_PORT Write proto header failed", "Error", err.Error())
		return EDPVS_IO
	}
	err = o.write(conn, logger)
	if err != nil {
		logger.Error("Sockopt SOCKOPT_NETIF_SET_PORT write specific port failed", "Error", err.Error())
		return EDPVS_IO
	}

	reply := NewReplySockMsg()
	err = reply.Read(conn)
	if err != nil {
		logger.Error("Sockopt SOCKOPT_NETIF_SET_PORT reply msg Read failed", "Error", err.Error())
		return EDPVS_IO
	}

	errCode := reply.GetErrCode()
	result := errCode.String()
	logger.Info("Sockopt SOCKOPT_NETIF_SET_PORT Done", "result", result)
	return errCode
}

type NetifNicEntryFront struct {
	count    uint16
	phyBase  uint16
	phyEnd   uint16
	bondBase uint16
	bondEnd  uint16
}

func NewNetifNicEntryFront() *NetifNicEntryFront {
	return &NetifNicEntryFront{}
}

func (o *NetifNicEntryFront) Copy(src *NetifNicEntryFront) bool {
	o.count = src.count
	o.phyBase = src.phyBase
	o.phyEnd = src.phyEnd
	o.bondBase = src.bondBase
	o.bondEnd = src.bondEnd
	return true
}

func (o *NetifNicEntryFront) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*o))
}

func (o *NetifNicEntryFront) Dump(buf []byte) bool {
	if len(buf) != int(o.Sizeof()) {
		return false
	}

	var tmp *NetifNicEntryFront = *(**NetifNicEntryFront)(unsafe.Pointer(&buf))

	return o.Copy(tmp)
}

func (o *NetifNicEntryFront) Package() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, o)
	return buf.Bytes()
}

func (o *NetifNicEntryFront) read(conn *pool.Conn, logger hclog.Logger) error {
	buf, err := conn.ReadN(int(o.Sizeof()))
	if err != nil {
		return err
	}

	o.Dump(buf)

	return nil
}

type NetifNicEntry struct {
	id   uint16
	name [0x10]byte
}

func (o *NetifNicEntry) GetID() uint16 {
	return o.id
}

func (o *NetifNicEntry) GetName() string {
	return TrimRightZeros(string(o.name[:]))
}

func NewNetifNicEntry() *NetifNicEntry {
	return &NetifNicEntry{}
}

func (o *NetifNicEntry) Copy(src *NetifNicEntry) bool {
	copy(o.name[:], src.name[:])
	o.id = src.id
	return true
}

func (o *NetifNicEntry) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*o))
}

func (o *NetifNicEntry) Dump(buf []byte) bool {
	if len(buf) != int(o.Sizeof()) {
		return false
	}

	var tmp *NetifNicEntry = *(**NetifNicEntry)(unsafe.Pointer(&buf))

	return o.Copy(tmp)
}

func (o *NetifNicEntry) Package() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, o)
	return buf.Bytes()
}

func (o *NetifNicEntry) read(conn *pool.Conn, logger hclog.Logger) error {
	buf, err := conn.ReadN(int(o.Sizeof()))
	if err != nil {
		return err
	}

	o.Dump(buf)

	return nil
}

type NetifNicEntries struct {
	Front   *NetifNicEntryFront
	Entries []*NetifNicEntry
}

func NewNetifNicEntries() *NetifNicEntries {
	return &NetifNicEntries{Front: NewNetifNicEntryFront()}
}

func (o *NetifNicDesc) GetPortList(cp *pool.ConnPool, logger hclog.Logger) (*NetifNicEntries, DpvsErrType) {
	var GET uint32
	GET = SOCKOPT_NETIF_GET_PORT_LIST

	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed", "Error", err.Error())
		return nil, EDPVS_IO
	}
	defer cp.Remove(ctx, conn, nil)

	msg := NewSockMsg(SOCKOPT_VERSION, GET, SOCKOPT_GET, o.Sizeof())
	if err := msg.Write(conn); err != nil {
		logger.Error("Sockopt SOCKOPT_NETIF_GET_PORT_LIST Write proto header failed", "Error", err.Error())
		return nil, EDPVS_IO
	}

	if err := o.write(conn, logger); err != nil {
		logger.Error("Sockopt SOCKOPT_NETIF_GET_PORT_LIST write specific port failed", "Error", err.Error())
		return nil, EDPVS_IO
	}

	reply := NewReplySockMsg()
	if err := reply.Read(conn); err != nil {
		logger.Error("Sockopt SOCKOPT_NETIF_GET_PORT_LIST reply msg Read failed", "Error", err.Error())
		return nil, EDPVS_IO
	}

	if reply.GetErrCode() != EDPVS_OK {
		logger.Error("Sockopt SOCKOPT_NETIF_GET_PORT_LIST failed.", "reply", reply.GetErrStr())
		return nil, reply.GetErrCode()
	}

	nic := NewNetifNicEntries()

	err = nic.Front.read(conn, logger)
	if err != nil {
		logger.Error("Sockopt SOCKOPT_NETIF_GET_PORT_LIST table header read failed", "Error", err.Error())
		return nil, EDPVS_IO
	}

	if nic.Front.count <= 0 {
		return nic, EDPVS_OK
	}

	entry := NewNetifNicEntry()
	resLen := int(reply.GetLen()) - int(nic.Front.Sizeof())
	if resLen != int(entry.Sizeof())*int(nic.Front.count) {
		conn.Release(resLen)
		logger.Error(fmt.Sprintf("buffer may not convert to %d count NetifNicEntry", nic.Front.count))
		return nil, EDPVS_IO
	}

	nic.Entries = make([]*NetifNicEntry, nic.Front.count)

	for i := 0; i < int(nic.Front.count); i++ {
		nic.Entries[i] = NewNetifNicEntry()
		nic.Entries[i].read(conn, logger)
	}
	return nic, EDPVS_OK
}

type NetifNicDetail struct {
	name     [0x20]byte
	addr     [0x20]byte
	status   [0x10]byte
	duplex   [0x10]byte
	autoneg  [0x10]byte
	speed    uint32
	nrxq     uint8
	ntxq     uint8
	padding  [0x3]uint8
	socketId uint8
	id       uint16
	mtu      uint16
	flags    uint16
}

func NewNetifNicDetail() *NetifNicDetail {
	return &NetifNicDetail{}
}

func (o *NetifNicDetail) Copy(src *NetifNicDetail) bool {
	o.speed = src.speed
	o.nrxq = src.nrxq
	o.ntxq = src.ntxq
	o.socketId = src.socketId
	o.id = src.id
	o.mtu = src.mtu
	o.flags = src.flags
	copy(o.name[:], src.name[:])
	copy(o.addr[:], src.addr[:])
	copy(o.status[:], src.status[:])
	copy(o.duplex[:], src.duplex[:])
	copy(o.autoneg[:], src.autoneg[:])
	return true
}

func (o *NetifNicDetail) GetSpeed() uint32 {
	return o.speed
}

func (o *NetifNicDetail) GetSocketID() uint8 {
	return o.socketId
}

func (o *NetifNicDetail) GetTxQueueCount() uint8 {
	return o.ntxq
}

func (o *NetifNicDetail) GetRxQueueCount() uint8 {
	return o.nrxq
}

func (o *NetifNicDetail) GetStatus() string {
	return TrimRightZeros(string(o.status[:]))
}

func (o *NetifNicDetail) GetName() string {
	return TrimRightZeros(string(o.name[:]))
}

func (o *NetifNicDetail) GetLinkDuplex() string {
	return TrimRightZeros(string(o.duplex[:]))
}

func (o *NetifNicDetail) GetLinkAutoNeg() string {
	return TrimRightZeros(string(o.autoneg[:]))
}

func (o *NetifNicDetail) GetAddr() string {
	return TrimRightZeros(string(o.addr[:]))
}

func (o *NetifNicDetail) GetMTU() uint16 {
	return o.mtu
}

func (o *NetifNicDetail) GetID() uint16 {
	return o.id
}

func (o *NetifNicDetail) GetFlags() uint16 {
	return o.flags
}

func (o *NetifNicDetail) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*o))
}

func (o *NetifNicDetail) Dump(buf []byte) bool {
	if len(buf) != int(o.Sizeof()) {
		return false
	}

	var tmp *NetifNicDetail = *(**NetifNicDetail)(unsafe.Pointer(&buf))

	return o.Copy(tmp)
}

func (o *NetifNicDetail) read(conn *pool.Conn, logger hclog.Logger) error {
	buf, err := conn.ReadN(int(o.Sizeof()))
	if err != nil {
		return err
	}

	o.Dump(buf)

	return nil
}

func (o *NetifNicDesc) GetPortBasic(cp *pool.ConnPool, logger hclog.Logger) (*NetifNicDetail, DpvsErrType) {
	var GET uint32
	GET = SOCKOPT_NETIF_GET_PORT_BASIC

	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed:", err.Error())
		return nil, EDPVS_IO
	}
	defer cp.Remove(ctx, conn, nil)

	msg := NewSockMsg(SOCKOPT_VERSION, GET, SOCKOPT_GET, o.Sizeof())
	if err := msg.Write(conn); err != nil {
		logger.Error("Sockopt SOCKOPT_NETIF_GET_PORT_BASIC Write proto header failed", "Error", err.Error())
		return nil, EDPVS_IO
	}

	if err := o.write(conn, logger); err != nil {
		logger.Error("Sockopt SOCKOPT_NETIF_GET_PORT_BASIC write specific port failed", "Error", err.Error())
		return nil, EDPVS_IO
	}

	reply := NewReplySockMsg()
	if err := reply.Read(conn); err != nil {
		logger.Error("Sockopt SOCKOPT_NETIF_GET_PORT_BASIC reply msg Read failed", "Error", err.Error())
		return nil, EDPVS_IO
	}

	if reply.GetErrCode() != EDPVS_OK {
		logger.Error(fmt.Sprintf("Sockopt SOCKOPT_NETIF_GET_PORT_BASIC reply ErrorCode: %s", reply.GetErrStr()))
		return nil, reply.GetErrCode()
	}

	detail := NewNetifNicDetail()
	if err := detail.read(conn, logger); err != nil {
		logger.Error("Sockopt SOCKOPT_NETIF_GET_PORT_BASIC spec port read failed", "Error", err.Error())
		return nil, EDPVS_IO
	}

	logger.Info("Sockopt SOCKOPT_NETIF_GET_PORT_BASIC read Done")
	return detail, EDPVS_OK
}

type NetifNicQueue struct {
	queue [0x10]uint64
}

func (o *NetifNicQueue) Copy(src *NetifNicQueue) bool {
	if src == nil {
		return false
	}

	for i := 0; i < len(o.queue); i++ {
		o.queue[i] = src.queue[i]
	}

	return true
}

type NetifNicStats struct {
	mBufAvail uint32
	mBufInuse uint32
	inPkts    uint64
	outPkts   uint64
	inBytes   uint64
	outBytes  uint64
	inMissed  uint64
	inErrors  uint64
	outErrors uint64
	rxNoMbuf  uint64
	inPktsQ   NetifNicQueue
	outPktsQ  NetifNicQueue
	inBytesQ  NetifNicQueue
	outBytesQ NetifNicQueue
	errorQ    NetifNicQueue
	padding   [0x3]uint16
	id        uint16
}

func NewNetifNicStats() *NetifNicStats {
	return &NetifNicStats{}
}

func (o *NetifNicStats) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*o))
}

func (o *NetifNicStats) Dump(buf []byte) bool {
	if len(buf) != int(o.Sizeof()) {
		return false
	}

	var tmp *NetifNicStats = *(**NetifNicStats)(unsafe.Pointer(&buf))

	return o.Copy(tmp)
}

func (o *NetifNicStats) Copy(src *NetifNicStats) bool {
	o.id = src.id
	o.mBufAvail = src.mBufAvail
	o.mBufInuse = src.mBufInuse
	o.inPkts = src.inPkts
	o.outPkts = src.outPkts
	o.inBytes = src.inBytes
	o.outBytes = src.outBytes
	o.inMissed = src.inMissed
	o.inErrors = src.inErrors
	o.outErrors = src.outErrors
	o.rxNoMbuf = src.rxNoMbuf
	o.inPktsQ.Copy(&src.inPktsQ)
	o.outPktsQ.Copy(&src.outPktsQ)
	o.inBytesQ.Copy(&src.inBytesQ)
	o.outBytesQ.Copy(&src.outBytesQ)
	o.errorQ.Copy(&src.errorQ)
	return true
}

func (o *NetifNicStats) GetID() uint16 {
	return o.id
}

func (o *NetifNicStats) GetRxNoMbuf() uint64 {
	return o.rxNoMbuf
}

func (o *NetifNicStats) GetOutErrors() uint64 {
	return o.outErrors
}

func (o *NetifNicStats) GetInErrors() uint64 {
	return o.inErrors
}

func (o *NetifNicStats) GetInMissed() uint64 {
	return o.inMissed
}

func (o *NetifNicStats) GetOutBytes() uint64 {
	return o.outBytes
}

func (o *NetifNicStats) GetInBytes() uint64 {
	return o.inBytes
}

func (o *NetifNicStats) GetOutPkts() uint64 {
	return o.outPkts
}

func (o *NetifNicStats) GetInPkts() uint64 {
	return o.inPkts
}

func (o *NetifNicStats) GetMBufInuse() uint32 {
	return o.mBufInuse
}

func (o *NetifNicStats) GetMBufAvail() uint32 {
	return o.mBufAvail
}

func (o *NetifNicStats) read(conn *pool.Conn, logger hclog.Logger) error {
	buf, err := conn.ReadN(int(o.Sizeof()))
	if err != nil {
		return err
	}

	o.Dump(buf)

	return nil
}

func (o *NetifNicDesc) GetPortStats(cp *pool.ConnPool, logger hclog.Logger) (*NetifNicStats, DpvsErrType) {
	var GET uint32
	GET = SOCKOPT_NETIF_GET_PORT_STATS

	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed", "Error", err.Error())
		return nil, EDPVS_IO
	}
	defer cp.Remove(ctx, conn, nil)

	msg := NewSockMsg(SOCKOPT_VERSION, GET, SOCKOPT_GET, o.Sizeof())
	if err := msg.Write(conn); err != nil {
		logger.Error("Sockopt SOCKOPT_NETIF_GET_PORT_STATS Write proto header failed", "Error", err.Error())
		return nil, EDPVS_IO
	}

	if err := o.write(conn, logger); err != nil {
		logger.Error("Sockopt SOCKOPT_NETIF_GET_PORT_STATS Write specific port failed", "Error", err.Error())
		return nil, EDPVS_IO
	}

	reply := NewReplySockMsg()
	if err := reply.Read(conn); err != nil {
		logger.Error("Sockopt SOCKOPT_NETIF_GET_PORT_STATS reply msg Read failed", "Error", err.Error())
		return nil, EDPVS_IO
	}

	stats := NewNetifNicStats()
	if err := stats.read(conn, logger); err != nil {
		logger.Error("Sockopt SOCKOPT_NETIF_GET_PORT_STATS read port stats failed", "Error", err.Error())
		return nil, EDPVS_IO
	}

	logger.Info("Sockopt SOCKOPT_NETIF_GET_PORT_STATS read Done")
	return stats, EDPVS_OK
}

/*
func (o *NetifNicDesc) GetPortExtra(cp *pool.ConnPool) DpvsErrType {
	var GET uint32
	GET = SOCKOPT_NETIF_GET_PORT_EXT_INFO
}
*/
