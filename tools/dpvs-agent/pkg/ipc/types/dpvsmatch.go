package types

type dpvsMatch struct {
	af      uint32
	srange  ipRange
	drange  ipRange
	iIfName [0x10]byte
	oIfName [0x10]byte
}

func (m *dpvsMatch) Copy(src *dpvsMatch) bool {
	if src == nil {
		return false
	}

	m.af = src.af

	copy(m.iIfName[:], src.iIfName[:])
	copy(m.oIfName[:], src.oIfName[:])

	if !m.srange.Copy(&src.srange) {
		return false
	}
	if !m.drange.Copy(&src.drange) {
		return false
	}
	return true
}

func (m *dpvsMatch) SetAf(af uint32) {
	m.af = af
}

func (m *dpvsMatch) SetSrange(r *ipRange) {
	m.srange.Copy(r)
}

func (m *dpvsMatch) SetDrange(r *ipRange) {
	m.drange.Copy(r)
}

func (m *dpvsMatch) SetIifName(name []byte) {
	copy(m.iIfName[:], name)
}

func (m *dpvsMatch) SetOifName(name []byte) {
	copy(m.oIfName[:], name)
}

func (m *dpvsMatch) GetIifName() string {
	return TrimRightZeros(string(m.iIfName[:]))
}

func (m *dpvsMatch) GetOifName() string {
	return TrimRightZeros(string(m.oIfName[:]))
}
