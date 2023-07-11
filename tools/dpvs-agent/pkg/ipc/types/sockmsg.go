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
	"encoding/binary"
	"errors"
	"unsafe"

	"github.com/dpvs-agent/pkg/ipc/pool"
)

type SockMsg struct {
	version uint32
	id      uint32
	sockopt SockoptType
	nop     uint32
	len     uint64
}

type ReplySockMsg struct {
	version uint32
	id      uint32
	sockopt SockoptType
	errCode DpvsErrType
	errStr  [0x40]byte
	len     uint32
	nop     uint32
}

func NewSockMsg(version, id uint32, sockopt SockoptType, len uint64) *SockMsg {
	return &SockMsg{version: version, id: id, sockopt: sockopt, len: len}
}

func (msg *SockMsg) GetLen() uint64 {
	return msg.len
}

func NewReplySockMsg() *ReplySockMsg {
	return &ReplySockMsg{}
}

func (msg *ReplySockMsg) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*msg))
}

func (msg *ReplySockMsg) Dump(buf []byte) bool {
	if len(buf) != int(msg.Sizeof()) {
		return false
	}

	var tmp *ReplySockMsg = *(**ReplySockMsg)(unsafe.Pointer(&buf))
	msg.version = tmp.version
	msg.id = tmp.id
	msg.sockopt = tmp.sockopt
	msg.errCode = tmp.errCode
	msg.len = tmp.len
	copy(msg.errStr[:], tmp.errStr[:])
	msg.ZeroPadding()

	return true
}

func (msg *ReplySockMsg) SetVersion(version uint32) {
	msg.version = version
}

func (msg *ReplySockMsg) SetID(id uint32) {
	msg.id = id
}

func (msg *ReplySockMsg) SetSockopt(opt SockoptType) {
	msg.sockopt = opt
}

func (msg *ReplySockMsg) SetErrCode(code DpvsErrType) {
	msg.errCode = code
}

func (msg *ReplySockMsg) SetErrStr(err []byte) {
	copy(msg.errStr[:], err)
}

func (msg *ReplySockMsg) SetLen(len uint32) {
	msg.len = len
}

func (msg *ReplySockMsg) ZeroPadding() {
	msg.nop = 0
}

func (msg *ReplySockMsg) GetErrCode() DpvsErrType {
	return msg.errCode
}

func (msg *ReplySockMsg) GetErrStr() string {
	return TrimRightZeros(string(msg.errStr[:]))
}

func (msg *ReplySockMsg) GetLen() uint32 {
	return msg.len
}

func (msg *SockMsg) Package() []byte {
	hdr := new(bytes.Buffer)
	binary.Write(hdr, binary.LittleEndian, msg)
	return hdr.Bytes()
}

func (msg *SockMsg) Sizeof() uint64 {
	return uint64(unsafe.Sizeof(*msg))
}

func (msg *SockMsg) Write(conn *pool.Conn) error {
	buf := msg.Package()
	_, err := conn.WriteN(buf, len(buf))
	if err != nil {
		return err
	}
	return nil
}

func (msg *ReplySockMsg) Read(conn *pool.Conn) error {
	buf, err := conn.ReadN(int(msg.Sizeof()))
	if err != nil {
		return err
	}

	if !msg.Dump(buf) {
		return errors.New("dump reply msg failed")
	}
	return nil
}
