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

package utils

import (
	"fmt"
	"net"
	"syscall"
)

// AF represents a network address family.
type AF int

const (
	IPv4 AF = syscall.AF_INET
	IPv6 AF = syscall.AF_INET6
)

// String returns the string representation of an AF.
func (af AF) String() string {
	switch af {
	case IPv4:
		return "IPv4"
	case IPv6:
		return "IPv6"
	}
	return "(unknown)"
}

// AFs returns the supported address families.
func AFs() []AF {
	return []AF{IPv4, IPv6}
}

// IP specifies an IP address.
type IP [net.IPv6len]byte

// NewIP returns a seesaw IP initialised from a net.IP address.
func NewIP(nip net.IP) IP {
	var ip IP
	copy(ip[:], nip.To16())
	return ip
}

// ParseIP parses the given string and returns a healthcheck IP initialised
// with the resulting IP address.
func ParseIP(ip string) IP {
	return NewIP(net.ParseIP(ip))
}

// Equal returns true of the given IP addresses are equal, as determined by
// net.IP.Equal().
func (ip IP) Equal(eip IP) bool {
	return ip.IP().Equal(eip.IP())
}

// IP returns the net.IP representation of a healthcheck IP address.
func (ip IP) IP() net.IP {
	return net.IP(ip[:])
}

// AF returns the address family of a healthcheck IP address.
func (ip IP) AF() AF {
	if ip.IP().To4() != nil {
		return IPv4
	}
	return IPv6
}

// String returns the string representation of an IP address.
func (ip IP) String() string {
	return fmt.Sprintf("%v", ip.IP())
}

// IPProto specifies an IP protocol.
type IPProto uint16

const (
	IPProtoICMP   IPProto = syscall.IPPROTO_ICMP
	IPProtoICMPv6 IPProto = syscall.IPPROTO_ICMPV6
	IPProtoTCP    IPProto = syscall.IPPROTO_TCP
	IPProtoUDP    IPProto = syscall.IPPROTO_UDP
)

// String returns the name for the given protocol value.
func (proto IPProto) String() string {
	switch proto {
	case IPProtoICMP:
		return "ICMP"
	case IPProtoICMPv6:
		return "ICMPv6"
	case IPProtoTCP:
		return "TCP"
	case IPProtoUDP:
		return "UDP"
	}
	return fmt.Sprintf("IP(%d)", proto)
}

func IPProtoFromStr(str string) IPProto {
	switch str {
	case "TCP":
		return IPProtoTCP
	case "UDP":
		return IPProtoUDP
	case "ICMP":
		return IPProtoICMP
	case "ICMPv6":
		return IPProtoICMPv6
	}
	return 0
}
