package types

type ipRange struct {
	minAddr [0x10]byte
	maxAddr [0x10]byte
	minPort uint16
	maxPort uint16
}

func (r *ipRange) Copy(src *ipRange) bool {
	if src == nil {
		return false
	}
	copy(r.minAddr[:], src.minAddr[:])
	copy(r.maxAddr[:], src.maxAddr[:])
	r.minPort = src.minPort
	r.maxPort = src.maxPort
	return true
}

func (r *ipRange) SetMinAddr(addr []byte) {
	copy(r.minAddr[:], addr)
}

func (r *ipRange) SetMaxAddr(addr []byte) {
	copy(r.maxAddr[:], addr)
}

func (r *ipRange) GetMinAddr() string {
	return TrimRightZeros(string(r.minAddr[:]))
}

func (r *ipRange) GetMaxAddr() string {
	return TrimRightZeros(string(r.maxAddr[:]))
}

func (r *ipRange) SetMinPort(port uint16) {
	r.minPort = port
}

func (r *ipRange) SetMaxPort(port uint16) {
	r.maxPort = port
}
