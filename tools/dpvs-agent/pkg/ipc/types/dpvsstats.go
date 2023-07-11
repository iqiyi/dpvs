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

type dpvsStats struct {
	conns    uint64
	inPkts   uint64
	inBytes  uint64
	outPkts  uint64
	outBytes uint64

	cps    uint32
	inPps  uint32
	inBps  uint32
	outPps uint32
	outBps uint32
	nop    uint32
}

func (s *dpvsStats) Copy(src *dpvsStats) bool {
	if src == nil {
		return false
	}
	s.conns = src.conns
	s.inPkts = src.inPkts
	s.inBytes = src.inBytes
	s.outPkts = src.outPkts
	s.outBytes = src.outBytes

	s.cps = src.cps
	s.inPps = src.inPps
	s.inBps = src.inBps
	s.outPps = src.outPps
	s.outBps = src.outBps
	return true
}

func (s *dpvsStats) SetConns(c uint64) {
	s.conns = c
}

func (s *dpvsStats) SetInPkts(p uint64) {
	s.inPkts = p
}

func (s *dpvsStats) SetInBytes(b uint64) {
	s.inBytes = b
}

func (s *dpvsStats) SetOutPkts(p uint64) {
	s.outPkts = p
}

func (s *dpvsStats) SetOutBytes(b uint64) {
	s.outBytes = b
}

func (s *dpvsStats) SetCps(c uint32) {
	s.cps = c
}

func (s *dpvsStats) SetInPps(p uint32) {
	s.inPps = p
}

func (s *dpvsStats) SetInBps(b uint32) {
	s.inBps = b
}

func (s *dpvsStats) SetOutPps(p uint32) {
	s.outPps = p
}

func (s *dpvsStats) SetOutBps(b uint32) {
	s.outBps = b
}

func (s *dpvsStats) GetConns() uint64 {
	return s.conns
}

func (s *dpvsStats) GetInPkts() uint64 {
	return s.inPkts
}

func (s *dpvsStats) GetInBytes() uint64 {
	return s.inBytes
}

func (s *dpvsStats) GetOutPkts() uint64 {
	return s.outPkts
}

func (s *dpvsStats) GetOutBytes() uint64 {
	return s.outBytes
}

func (s *dpvsStats) GetCps() uint32 {
	return s.cps
}

func (s *dpvsStats) GetInPps() uint32 {
	return s.inPps
}

func (s *dpvsStats) GetInBps() uint32 {
	return s.inBps
}

func (s *dpvsStats) GetOutPps() uint32 {
	return s.outPps
}

func (s *dpvsStats) GetOutBps() uint32 {
	return s.outBps
}
