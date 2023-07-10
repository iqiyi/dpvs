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
