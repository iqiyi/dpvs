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
	"strings"
	"unsafe"

	"github.com/hashicorp/go-hclog"
	"golang.org/x/sys/unix"

	"github.com/dpvs-agent/pkg/ipc/pool"
)

type KniAddrFlowFront struct {
	count uint32
}

type KniAddrFlowEntry struct {
	af   uint32
	addr [0x10]byte
}

type KniAddrFlowSpec struct {
	flags  uint32
	ifName [0x10]byte
	entry  KniAddrFlowEntry
}

func NewKniAddrFlowFront() *KniAddrFlowFront {
	return &KniAddrFlowFront{}
}

func NewKniAddrFlowSpec() *KniAddrFlowSpec {
	return &KniAddrFlowSpec{flags: 1}
}

func NewKniAddrFlowEntry() *KniAddrFlowEntry {
	return &KniAddrFlowEntry{}
}

func (o *KniAddrFlowSpec) Copy(src *KniAddrFlowSpec) bool {
	o.flags = src.flags
	copy(o.ifName[:], src.ifName[:])
	return o.entry.Copy(&src.entry)
}

func (o *KniAddrFlowEntry) Copy(src *KniAddrFlowEntry) bool {
	o.af = src.af
	copy(o.addr[:], src.addr[:])
	return true
}

func (o *KniAddrFlowFront) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*o))
}

func (o *KniAddrFlowSpec) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*o))
}

func (o *KniAddrFlowEntry) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*o))
}

func (o *KniAddrFlowFront) Copy(src *KniAddrFlowFront) bool {
	o.count = src.count
	return true
}

func (o *KniAddrFlowFront) Dump(buf []byte) bool {
	if len(buf) != int(o.Sizeof()) {
		return false
	}

	var tmp *KniAddrFlowFront = *(**KniAddrFlowFront)(unsafe.Pointer(&buf))

	return o.Copy(tmp)
}

func (o *KniAddrFlowSpec) Dump(buf []byte) bool {
	if len(buf) != int(o.Sizeof()) {
		return false
	}

	var tmp *KniAddrFlowSpec = *(**KniAddrFlowSpec)(unsafe.Pointer(&buf))

	return o.Copy(tmp)
}

func (o *KniAddrFlowEntry) Dump(buf []byte) bool {
	if len(buf) != int(o.Sizeof()) {
		return false
	}

	var tmp *KniAddrFlowEntry = *(**KniAddrFlowEntry)(unsafe.Pointer(&buf))

	return o.Copy(tmp)
}

func (o *KniAddrFlowFront) Package() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, o)
	return buf.Bytes()
}

func (o *KniAddrFlowSpec) Package() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, o)
	return buf.Bytes()
}

func (o *KniAddrFlowEntry) Package() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, o)
	return buf.Bytes()
}

func (o *KniAddrFlowSpec) SetFlags(flags uint32) {
	o.flags = 1 // must be 1
}

func (o *KniAddrFlowSpec) SetDevice(name string) {
	copy(o.ifName[:], name[:])
}

func (o *KniAddrFlowEntry) SetAf(af uint32) {
	o.af = af
}

func (o *KniAddrFlowEntry) SetAddr(addr string) {
	if strings.Contains(addr, ":") {
		o.SetAf(unix.AF_INET6)
		copy(o.addr[:], net.ParseIP(addr))
		return
	}

	o.SetAf(unix.AF_INET)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, net.ParseIP(addr))
	copy(o.addr[:], buf.Bytes()[12:])
}

func (o *KniAddrFlowFront) read(conn *pool.Conn, len uint64, logger hclog.Logger) ([]*KniAddrFlowFront, error) {
	res := len % o.Sizeof()
	cnt := len / o.Sizeof()
	if cnt <= 0 || res != 0 {
		conn.Release(int(len))
		return nil, errors.New("buffer may not convert to KniAddrFlowFront")
	}

	fronts := make([]*KniAddrFlowFront, cnt)
	for i := 0; i < int(cnt); i++ {
		fronts[i] = NewKniAddrFlowFront()
		buf, err := conn.ReadN(int(o.Sizeof()))
		if err != nil {
			continue
		}
		fronts[i].Dump(buf)
	}

	return fronts, nil
}

func (o *KniAddrFlowSpec) write(conn *pool.Conn) error {
	buf := o.Package()
	_, err := conn.WriteN(buf, int(o.Sizeof()))
	if err != nil {
		return err
	}
	return nil
}

func (o *KniAddrFlowEntry) read(conn *pool.Conn, len uint64, logger hclog.Logger) ([]*KniAddrFlowEntry, error) {
	res := len % o.Sizeof()
	cnt := len / o.Sizeof()
	if cnt <= 0 || res != 0 {
		conn.Release(int(len))
		return nil, errors.New("buffer may not convert to KniAddrFlowEntry")
	}

	entries := make([]*KniAddrFlowEntry, cnt)
	for i := 0; i < int(cnt); i++ {
		entries[i] = NewKniAddrFlowEntry()
		err := conn.Read(entries[i])
		if err != nil {
			continue
		}
	}

	logger.Info("Get Kni Addr success", "entries", entries)
	return entries, nil
}

func (o *KniAddrFlowSpec) Get(cp *pool.ConnPool, logger hclog.Logger) ([]*KniAddrFlowEntry, error) {
	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed", "Error", err.Error())
		return nil, err
	}
	defer cp.Remove(ctx, conn, nil)

	msg := NewSockMsg(SOCKOPT_VERSION, SOCKOPT_GET_KNI_LIST, SOCKOPT_GET, o.Sizeof())
	if err := msg.Write(conn); err != nil {
		logger.Error("Sockopt SOCKOPT_GET_KNI_LIST Write proto header failed", "Error", err.Error())
		return nil, err
	}

	if err := o.write(conn); err != nil {
		logger.Error("Sockopt SOCKOPT_GET_KNI_LIST write spec kni failed", "Error", err.Error())
		return nil, err
	}

	reply := NewReplySockMsg()
	if err := reply.Read(conn); err != nil {
		logger.Error("Sockopt SOCKOPT_GET_KNI_LIST Read reply failed", "Error", err.Error())
		return nil, err
	}

	if reply.GetErrCode() != EDPVS_OK {
		result := reply.GetErrStr()
		logger.Error("Sockopt SOCKOPT_GET_KNI_LIST failed", "result", result)
		err = fmt.Errorf("Sockopt SOCKOPT_GET_KNI_LIST reply ErrorCode: %s", reply.GetErrStr())
		return nil, err
	}

	front := NewKniAddrFlowFront()
	_, err = front.read(conn, front.Sizeof(), logger)
	if err != nil {
		logger.Error("Sockopt SOCKOPT_GET_KNI_LIST read table header failed", "Error", err.Error())
		return nil, err
	}

	entry := NewKniAddrFlowEntry()
	return entry.read(conn, uint64(reply.GetLen())-front.Sizeof(), logger)
}

func (o *KniAddrFlowSpec) Add(cp *pool.ConnPool, logger hclog.Logger) DpvsErrType {
	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Get conn from pool failed", "Error", err.Error())
		return EDPVS_IO
	}
	defer cp.Remove(ctx, conn, nil)

	var ADD uint32
	ADD = SOCKOPT_SET_KNI_ADD

	msg := NewSockMsg(SOCKOPT_VERSION, ADD, SOCKOPT_SET, o.Sizeof())
	err = msg.Write(conn)
	if err != nil {
		logger.Error("Sockopt SOCKOPT_SET_KNI_ADD Write proto header failed", "Error", err.Error())
		return EDPVS_IO
	}
	err = o.write(conn)
	if err != nil {
		logger.Error("Sockopt SOCKOPT_SET_KNI_ADD write spec kni failed", "Error", err.Error())
		return EDPVS_IO
	}

	reply := NewReplySockMsg()
	err = reply.Read(conn)
	if err != nil {
		logger.Error("Sockopt SOCKOPT_SET_KNI_ADD Read reply failed", "Error", err.Error())
		return EDPVS_IO
	}

	errCode := reply.GetErrCode()
	logger.Info("Sockopt SOCKOPT_SET_KNI_ADD Done:", errCode.String())
	return errCode
}

func (o *KniAddrFlowSpec) Del(cp *pool.ConnPool, logger hclog.Logger) DpvsErrType {
	ctx := context.Background()
	conn, err := cp.Get(ctx)
	if err != nil {
		logger.Error("Sockopt SOCKOPT_SET_KNI_DEL Write proto header failed", "Error", err.Error())
		return EDPVS_IO
	}
	defer cp.Remove(ctx, conn, nil)

	var DEL uint32
	DEL = SOCKOPT_SET_KNI_DEL

	msg := NewSockMsg(SOCKOPT_VERSION, DEL, SOCKOPT_SET, o.Sizeof())
	err = msg.Write(conn)
	if err != nil {
		logger.Error("Sockopt SOCKOPT_SET_KNI_DEL Write spec kni failed", "Error", err.Error())
		return EDPVS_IO
	}
	err = o.write(conn)
	if err != nil {
		logger.Error("Sockopt SOCKOPT_SET_KNI_DEL write spec kni failed", "Error", err.Error())
		return EDPVS_IO
	}

	reply := NewReplySockMsg()
	err = reply.Read(conn)
	if err != nil {
		logger.Error("Sockopt SOCKOPT_SET_KNI_DEL Read reply failed", "Error", err.Error())
		return EDPVS_IO
	}

	errCode := reply.GetErrCode()
	result := errCode.String()
	logger.Info("Sockopt SOCKOPT_SET_KNI_DEL Done", "result", result)
	return errCode
}
