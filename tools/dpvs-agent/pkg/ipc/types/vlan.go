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
	"strings"
	"unsafe"

	"github.com/hashicorp/go-hclog"
	"golang.org/x/sys/unix"

	"github.com/dpvs-agent/pkg/ipc/pool"
)

type VlanFront struct {
	count uint32
}

func NewVlanFront() *VlanFront {
	return &VlanFront{}
}

func (o *VlanFront) GetCount() uint32 {
	return o.count
}

func (o *VlanFront) SetCount(c uint32) {
	o.count = c
}

func (o *VlanFront) Copy(src *VlanFront) bool {
	o.count = src.count
	return true
}

func (o *VlanFront) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*o))
}

func (o *VlanFront) Dump(buf []byte) bool {
	if len(buf) != int(o.Sizeof()) {
		return false
	}

	var tmp *VlanFront = *(**VlanFront)(unsafe.Pointer(&buf))

	return o.Copy(tmp)
}

func (o *VlanFront) Package() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, o)
	return buf.Bytes()
}

func (o *VlanFront) read(conn *pool.Conn, len uint64, logger hclog.Logger) ([]*VlanFront, error) {
	res := len % o.Sizeof()
	cnt := len / o.Sizeof()
	if cnt <= 0 || res != 0 {
		conn.Release(int(len))
		return nil, errors.New("Wrong buffer size to read, may not convert to VlanFront")
	}

	fronts := make([]*VlanFront, cnt)

	for i := 0; i < int(cnt); i++ {
		buf, err := conn.ReadN(int(o.Sizeof()))
		if err != nil {
			continue
		}
		fronts[i] = NewVlanFront()
		fronts[i].Dump(buf)
	}

	return fronts, nil
}

func (o *VlanFront) write(conn *pool.Conn, logger hclog.Logger) error {
	buf := o.Package()
	_, err := conn.WriteN(buf, int(o.Sizeof()))
	if err != nil {
		return err
	}
	return nil
}

type VlanDevice struct {
	realDev [0x10]byte
	ifName  [0x10]byte
	proto   uint16
	id      uint16
}

func NewVlanDevice() *VlanDevice {
	return &VlanDevice{proto: unix.ETH_P_8021Q}
}

func (o *VlanDevice) Copy(src *VlanDevice) bool {
	copy(o.realDev[:], src.realDev[:])
	copy(o.ifName[:], src.ifName[:])
	o.proto = src.proto
	o.id = src.id
	return true
}

func (o *VlanDevice) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*o))
}

func (o *VlanDevice) Dump(buf []byte) bool {
	if len(buf) != int(o.Sizeof()) {
		return false
	}

	var tmp *VlanDevice = *(**VlanDevice)(unsafe.Pointer(&buf))

	return o.Copy(tmp)
}

func (o *VlanDevice) Package() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, o)
	return buf.Bytes()
}

func (o *VlanDevice) SetRealDev(name string) {
	copy(o.realDev[:], name[:])
}

func (o *VlanDevice) SetId(id uint16) {
	o.id = id
}

func (o *VlanDevice) SetIfName(name string) {
	copy(o.ifName[:], name[:])
}

func (o *VlanDevice) SetProto(proto string) {
	p := strings.ToLower(proto)
	switch p {
	case "vlan":
		fallthrough
	case "802.1q":
		o.proto = unix.ETH_P_8021Q
	case "qinq":
		fallthrough
	case "802.1ad":
		o.proto = unix.ETH_P_8021AD
	default:
	}
}

func (o *VlanDevice) ValidProto(proto string) bool {
	// p := strings.ToLower(proto)
	switch strings.ToLower(proto) {
	case "vlan":
		return true
	case "802.1q":
		return true
	case "qinq":
		return true
	case "802.1ad":
		return true
	default:
		return false
	}
	return false
}

func (o *VlanDevice) read(conn *pool.Conn, len uint64, logger hclog.Logger) ([]*VlanDevice, error) {
	res := len % o.Sizeof()
	cnt := len / o.Sizeof()
	if cnt <= 0 || res != 0 {
		conn.Release(int(len))
		return nil, errors.New("Wrong buffer size to read, may not convert to VlanDevice")
	}

	devices := make([]*VlanDevice, cnt)
	for i := 0; i < int(cnt); i++ {
		buf, err := conn.ReadN(int(o.Sizeof()))
		if err != nil {
			continue
		}
		devices[i] = NewVlanDevice()
		devices[i].Dump(buf)
	}

	return devices, nil
}

func (o *VlanDevice) write(conn *pool.Conn, logger hclog.Logger) error {
	buf := o.Package()
	_, err := conn.WriteN(buf, int(o.Sizeof()))
	if err != nil {
		return err
	}
	return nil
}

/****************
****************/
func (o *VlanDevice) Get(cp *pool.ConnPool, logger hclog.Logger) ([]*VlanDevice, error) {
	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed:", err.Error())
		return nil, err
	}
	defer cp.Remove(ctx, conn, nil)

	msg := NewSockMsg(SOCKOPT_VERSION, SOCKOPT_GET_VLAN_SHOW, SOCKOPT_GET, o.Sizeof())
	if err := msg.Write(conn); err != nil {
		logger.Error("Sockopt SOCKOPT_GET_VLAN_SHOW Write proto header Error:", err.Error())
		return nil, err
	}

	if err := o.write(conn, logger); err != nil {
		logger.Error("Sockopt SOCKOPT_GET_VLAN_SHOW write specific vlan Error:", err.Error())
		return nil, err
	}

	reply := NewReplySockMsg()
	if err := reply.Read(conn); err != nil {
		logger.Error("Sockopt SOCKOPT_GET_VLAN_SHOW reply msg Read failed:", err.Error())
		return nil, err
	}

	if reply.GetErrCode() != EDPVS_OK {
		err = fmt.Errorf("Sockopt SOCKOPT_GET_VLAN_SHOW reply ErrorCode: %s", reply.GetErrStr())
		logger.Error(err.Error())
		return nil, err
	}

	front := VlanFront{}
	_, err = front.read(conn, front.Sizeof(), logger)
	if err != nil {
		logger.Error("Sockopt SOCKOPT_GET_VLAN_SHOW read table header failed:", err.Error())
		return nil, err
	}

	return o.read(conn, uint64(reply.GetLen())-front.Sizeof(), logger)
}

func (o *VlanDevice) Add(cp *pool.ConnPool, logger hclog.Logger) DpvsErrType {
	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed", "Error", err.Error())
		return EDPVS_IO
	}
	defer cp.Remove(ctx, conn, nil)

	msg := NewSockMsg(SOCKOPT_VERSION, SOCKOPT_SET_VLAN_ADD, SOCKOPT_SET, o.Sizeof())
	err = msg.Write(conn)
	if err != nil {
		logger.Error("Sockopt SOCKOPT_SET_VLAN_ADD Write proto header Error failed", "Error", err.Error())
		return EDPVS_IO
	}

	err = o.write(conn, logger)
	if err != nil {
		logger.Error("Sockopt SOCKOPT_SET_VLAN_ADD write specific vlan Error failed", "Error", err.Error())
		return EDPVS_IO
	}

	reply := NewReplySockMsg()
	err = reply.Read(conn)
	if err != nil {
		logger.Error("Sockopt SOCKOPT_SET_VLAN_ADD reply msg Read failed", "Error", err.Error())
		return EDPVS_IO
	}

	errCode := reply.GetErrCode()
	result := errCode.String()
	logger.Info("Sockopt SOCKOPT_SET_VLAN_ADD Done", "result", result)
	return errCode
}

func (o *VlanDevice) Del(cp *pool.ConnPool, logger hclog.Logger) DpvsErrType {
	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed:", err.Error())
		return EDPVS_IO
	}
	defer cp.Remove(ctx, conn, nil)

	msg := NewSockMsg(SOCKOPT_VERSION, SOCKOPT_SET_VLAN_DEL, SOCKOPT_SET, o.Sizeof())
	err = msg.Write(conn)
	if err != nil {
		logger.Error("Sockopt SOCKOPT_SET_VLAN_DEL Write proto header Error:", err.Error())
		return EDPVS_IO
	}

	err = o.write(conn, logger)
	if err != nil {
		logger.Error("Sockopt SOCKOPT_SET_VLAN_DEL write specific vlan Error:", err.Error())
		return EDPVS_IO
	}

	reply := NewReplySockMsg()
	err = reply.Read(conn)
	if err != nil {
		logger.Error("Sockopt SOCKOPT_SET_VLAN_DEL reply msg Read failed:", err.Error())
		return EDPVS_IO
	}

	return reply.GetErrCode()
}
