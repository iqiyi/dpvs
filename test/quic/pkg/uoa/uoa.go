package uoa

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	IPOPT_CONTROL     = 0
	IPOPT_UOA         = 31 | IPOPT_CONTROL
	UOA_SO_GET_LOOKUP = 2048

	AF_INET  = 2
	AF_INET6 = 10
)

type uoaParamMap struct {
	// input
	af    uint16
	saddr [16]byte
	daddr [16]byte
	sport uint16
	dport uint16

	// output
	realAf    uint16
	realSaddr [16]byte
	realSport uint16
}

func AddrToIPnPort(addr net.Addr) (net.IP, uint16, error) {
	switch t := addr.(type) {
	case *net.TCPAddr:
		return t.IP, uint16(t.Port), nil
	case *net.UDPAddr:
		return t.IP, uint16(t.Port), nil
	default:
		return nil, 0, fmt.Errorf("unsupported address type %T for %s", t, addr)
	}
}

func IPnPortToAddr(af uint16, l4Proto string, addr [16]byte, port uint16) (net.Addr, error) {
	// fmt.Println("uoa address", af, l4Proto, addr, port)
	switch l4Proto {
	case "tcp":
		res := &net.TCPAddr{}
		if af == AF_INET {
			res.IP = net.IPv4(addr[0], addr[1], addr[2], addr[3])
		} else {
			res.IP = make(net.IP, net.IPv6len)
			copy(res.IP, addr[:])
		}
		res.Port = int(port)
		return res, nil
	case "udp":
		res := &net.UDPAddr{}
		if af == AF_INET {
			res.IP = net.IPv4(addr[0], addr[1], addr[2], addr[3])
		} else {
			res.IP = make(net.IP, net.IPv6len)
			copy(res.IP, addr[:])
		}
		res.Port = int(port)
		return res, nil
	default:
		return nil, fmt.Errorf("unsupported network type %q", l4Proto)
	}
}

func htons(le uint16) uint16 {
	bytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(bytes, le)
	return binary.BigEndian.Uint16(bytes)
}

func ntohs(be uint16) uint16 {
	bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bytes, be)
	return binary.LittleEndian.Uint16(bytes)
}

func GetUoaAddr(fd uintptr, saddr, daddr net.Addr) (net.Addr, error) {
	sip, sport, err := AddrToIPnPort(saddr)
	if err != nil {
		return nil, err
	}
	_, dport, err := AddrToIPnPort(daddr) // server ip doesn't matter
	if err != nil {
		return nil, err
	}
	uoaParam := uoaParamMap{}
	if sip.To4() != nil {
		uoaParam.af = AF_INET
		copy(uoaParam.saddr[:], sip.To4())
		//copy(uoaParam.daddr[:], dip.To4())
	} else {
		uoaParam.af = AF_INET6
		copy(uoaParam.saddr[:], sip.To16())
		//copy(uoaParam.daddr[:], dip.To16())
	}
	uoaParam.sport = htons(sport)
	uoaParam.dport = htons(dport)
	paramLen := uint32(unsafe.Sizeof(uoaParam))
	//fmt.Println(fd, uoaParam, paramLen)
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.IPPROTO_IP, UOA_SO_GET_LOOKUP, uintptr(unsafe.Pointer(&uoaParam)), uintptr(unsafe.Pointer(&paramLen)), 0)
	if errno != 0 {
		return nil, fmt.Errorf("syscall failed with errno %d", errno)
	}

	res, err := IPnPortToAddr(uoaParam.realAf, "udp", uoaParam.realSaddr, ntohs(uoaParam.realSport))
	if err != nil {
		return nil, err
	}

	return res, nil
}
