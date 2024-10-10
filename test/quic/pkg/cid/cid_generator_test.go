package cid

import (
	"net"
	"reflect"
	"testing"
)

func TestQuicCIDGenerator_IPv4(t *testing.T) {
	cid, err := QuicCIDGeneratorFunction(10, 3, 2, net.ParseIP("192.168.111.222"), 8029)
	if err != nil {
		t.Errorf("QuicCIDGenerator error return: %v", err)
	}
	if len(cid) != 10 {
		t.Errorf("invalid CID length")
	}
	result := make([]byte, 6)
	copy(result, cid[1:7])
	result[len(result)-1] &= 0xf0
	expected := []byte{0x5a, 0x86, 0xfd, 0xe1, 0xf5, 0xd0}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("mismatched CID:\nresult: %x\nexpect: %x\n", result, expected)
	} else {
		t.Logf("%x\n", cid)
	}
}

func TestQuicCIDGenerator_IPv6(t *testing.T) {
	cid, err := QuicCIDGeneratorFunction(16, 6, 2,
		net.ParseIP("2001::123:4567:89ab:cdef"), 51321)
	if err != nil {
		t.Errorf("QuicCIDGenerator error return: %v", err)
	}
	if len(cid) != 16 {
		t.Errorf("invalid CID length")
	}
	result := make([]byte, 9)
	copy(result, cid[1:10])
	result[len(result)-1] &= 0xf0
	expected := []byte{0xb4, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xfc, 0x87, 0x90}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("mismatched CID:\nresult: %x\nexpect: %x\n", result, expected)
	} else {
		t.Logf("%x\n", cid)
	}
}
