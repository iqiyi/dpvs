package pool

import (
	"bytes"
	"encoding/binary"
)

func Package(o ConnWriteIf) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, o)
	return buf.Bytes()
}
