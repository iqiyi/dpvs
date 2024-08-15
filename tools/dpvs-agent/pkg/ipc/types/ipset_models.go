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
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"unicode"

	"github.com/dpvs-agent/models"
)

var (
	_ IPSetType = (*IPSetBitmapIP)(nil)
	_ IPSetType = (*IPSetBitmapIPMac)(nil)
	_ IPSetType = (*IPSetBitmapPort)(nil)
	_ IPSetType = (*IPSetHashIP)(nil)
	_ IPSetType = (*IPSetHashNet)(nil)
	_ IPSetType = (*IPSetHashIPPort)(nil)
	_ IPSetType = (*IPSetHashNetPort)(nil)
	_ IPSetType = (*IPSetHashNetPortIface)(nil)
	_ IPSetType = (*IPSetHashIPPortIP)(nil)
	_ IPSetType = (*IPSetHashIPPortNet)(nil)
	_ IPSetType = (*IPSetHashNetPortNet)(nil)
	_ IPSetType = (*IPSetHashNetPortNetPort)(nil)
)

type IPSetType interface {
	// Update IPSetParam with parsed fields from models.IpsetMember.Entry
	ParseEntry(string, *IPSetParam) error
	// Create a models.IpsetMember with Entry field filled
	ModelEntry(uint8, *IPSetMember) (*models.IpsetMember, error)
	// Check if IPSetParam is valid
	CheckParam(*IPSetParam) error
}

type IPSetBitmapIP struct{}
type IPSetBitmapIPMac struct{}
type IPSetBitmapPort struct{}
type IPSetHashIP struct{}
type IPSetHashNet struct{}
type IPSetHashIPPort struct{}
type IPSetHashNetPort struct{}
type IPSetHashNetPortIface struct{}
type IPSetHashIPPortIP struct{}
type IPSetHashIPPortNet struct{}
type IPSetHashNetPortNet struct{}
type IPSetHashNetPortNetPort struct{}

func (o *IPSetBitmapIP) ParseEntry(entry string, param *IPSetParam) error {
	startIP, endIP, af, pfx, err := parseAddrRange(entry)
	if err != nil {
		return fmt.Errorf("Parse models.IpsetMember Entry failed: %v", err)
	}

	param.SetAf(af)
	if startIP != nil {
		param.GetAddrRange().SetMinAddr(startIP)
	}
	if endIP != nil {
		param.GetAddrRange().SetMaxAddr(endIP)
	} else {
		param.GetAddrRange().SetMaxAddr(startIP)
	}
	param.SetCidr(pfx)

	return nil
}

func (o *IPSetBitmapIP) ModelEntry(af uint8, member *IPSetMember) (*models.IpsetMember, error) {
	model := &models.IpsetMember{}
	entry := ""

	if member.GetCidr() > 0 {
		entry = fmt.Sprintf("%s/%d", member.GetAddr(af), member.GetCidr())
	} else {
		entry = fmt.Sprintf("%s", member.GetAddr(af))
	}
	model.Entry = &entry

	return model, nil
}

func (o *IPSetBitmapIP) CheckParam(param *IPSetParam) error {
	if param.af == syscall.AF_INET6 {
		return fmt.Errorf("bitmap:ip doesn't support ipv6")
	}
	if param.opcode != IPSET_OP_CREATE {
		return nil
	}
	if param.cidr > 0 {
		if param.cidr < 16 {
			return fmt.Errorf("bitmap:ip net seg too big, cidr should be no smaller than 16")
		}
		return nil
	}
	if param.af == syscall.AF_INET {
		startIP, endIP, _, _ := param.addrRange.Decode(param.af)
		if ip4ToUint32(startIP) >= ip4ToUint32(endIP) {
			return fmt.Errorf("bitmap:ip requires a network range or cidr")
		}
	}
	return nil
}

func (o *IPSetBitmapIPMac) ParseEntry(entry string, param *IPSetParam) error {
	segs := strings.Split(entry, ",")

	startIP, endIP, af, pfx, err := parseAddrRange(segs[0])
	if err != nil {
		return fmt.Errorf("invalid addr range %s", segs[0])
	}
	param.SetAf(af)
	if startIP != nil {
		param.GetAddrRange().SetMinAddr(startIP)
	}
	if endIP != nil {
		param.GetAddrRange().SetMaxAddr(endIP)
	} else {
		param.GetAddrRange().SetMaxAddr(startIP)
	}
	param.SetCidr(pfx)

	if len(segs) > 1 {
		if err := param.SetMacAddr(segs[1]); err != nil {
			return fmt.Errorf("invalid mac address: %s", err.Error())
		}
	}

	return nil
}

func (o *IPSetBitmapIPMac) ModelEntry(af uint8, member *IPSetMember) (*models.IpsetMember, error) {
	model := &models.IpsetMember{}
	entry := fmt.Sprintf("%s,%s", member.GetAddr(af), member.GetMacAddr())
	model.Entry = &entry

	return model, nil
}

func (o *IPSetBitmapIPMac) CheckParam(param *IPSetParam) error {
	if param.af == syscall.AF_INET6 {
		return fmt.Errorf("bitmap:ip,mac doesn't support ipv6")
	}
	if param.opcode != IPSET_OP_CREATE {
		if param.cidr > 0 {
			return fmt.Errorf("bitmap:ip,mac doesn't support addr cidr")
		}
		if param.af == syscall.AF_INET {
			startIP, endIP, _, _ := param.addrRange.Decode(param.af)
			if endIP != nil && !endIP.Equal(startIP) {
				return fmt.Errorf("bitmap:ip,mac doesn't support addr range")
			}
		}
	} else {
		if param.cidr > 0 {
			if param.cidr < 16 {
				return fmt.Errorf("bitmap:ip,mac net seg too big, cidr should be no smaller than 16")
			}
			return nil
		}
		if param.af == syscall.AF_INET {
			startIP, endIP, _, _ := param.addrRange.Decode(param.af)
			if ip4ToUint32(startIP) >= ip4ToUint32(endIP) {
				return fmt.Errorf("bitmap:ip,mac create requires a network range or cidr")
			}
		}
	}
	return nil
}

func (o *IPSetBitmapPort) ParseEntry(entry string, param *IPSetParam) error {
	startPort, endPort, proto, err := parsePortRange(entry)
	if err != nil {
		return err
	}
	param.GetAddrRange().SetMinPort(startPort)
	if endPort > 0 {
		param.GetAddrRange().SetMaxPort(endPort)
	} else {
		param.GetAddrRange().SetMaxPort(startPort)
	}
	param.SetProto(proto)
	return nil
}

func (o *IPSetBitmapPort) ModelEntry(af uint8, member *IPSetMember) (*models.IpsetMember, error) {
	model := &models.IpsetMember{}

	entry := fmt.Sprintf("%s:%d", protoString(member.GetProto()), member.GetPort())
	model.Entry = &entry

	return model, nil
}

func (o *IPSetBitmapPort) CheckParam(param *IPSetParam) error {
	if param.opcode == IPSET_OP_CREATE {
		if param.proto != 0 {
			return fmt.Errorf("bitmap:port doesn't support proto in create")
		}
	} else {
		if param.addrRange.minPort > 0 &&
			param.proto != syscall.IPPROTO_TCP && param.proto != syscall.IPPROTO_UDP {
			return fmt.Errorf("invalid bitmap:port protocol %s", protoString(param.proto))
		}
	}
	return nil
}

func (o *IPSetHashIP) ParseEntry(entry string, param *IPSetParam) error {
	startIP, endIP, af, pfx, err := parseAddrRange(entry)
	if err != nil {
		return fmt.Errorf("invalid addr range %s", entry)
	}
	param.SetAf(af)
	if startIP != nil {
		param.GetAddrRange().SetMinAddr(startIP)
	}
	if endIP != nil {
		param.GetAddrRange().SetMaxAddr(endIP)
	} else {
		param.GetAddrRange().SetMaxAddr(startIP)
	}
	param.SetCidr(pfx)
	return nil
}

func (o *IPSetHashIP) ModelEntry(af uint8, member *IPSetMember) (*models.IpsetMember, error) {
	model := &models.IpsetMember{}

	entry := member.GetAddr(af).String()
	model.Entry = &entry

	return model, nil
}

func (o *IPSetHashIP) CheckParam(param *IPSetParam) error {
	if param.opcode != IPSET_OP_ADD && param.opcode != IPSET_OP_DEL {
		return nil
	}
	if param.af == syscall.AF_INET6 {
		if param.cidr > 0 {
			return fmt.Errorf("hash:ip doesn't support IPv6 cidr")
		}
	} else if param.af == syscall.AF_INET {
		if param.cidr > 0 && param.cidr < 16 {
			return fmt.Errorf("ipv4 address cidr range too big, 65536 at most")
		}
	}
	startIP, endIP, _, _ := param.addrRange.Decode(param.af)
	if param.af == syscall.AF_INET {
		startIPNum, endIPNum := ip4ToUint32(startIP), ip4ToUint32(endIP)
		if endIPNum > 0 && endIPNum-startIPNum >= 65535 {
			return fmt.Errorf("ipv4 address range too big, 65536 at most")
		}
	}
	return nil
}

func (o *IPSetHashNet) ParseEntry(entry string, param *IPSetParam) error {
	// the same as IPSetHashIP
	var iphash IPSetHashIP
	return iphash.ParseEntry(entry, param)
}

func (o *IPSetHashNet) ModelEntry(af uint8, member *IPSetMember) (*models.IpsetMember, error) {
	model := &models.IpsetMember{}

	entry := fmt.Sprintf("%s/%d", member.GetAddr(af).String(), member.GetCidr())
	model.Entry = &entry

	return model, nil
}

func (o *IPSetHashNet) CheckParam(param *IPSetParam) error {
	// nothing to do
	return nil
}

func (o *IPSetHashIPPort) ParseEntry(entry string, param *IPSetParam) error {
	segs := strings.Split(entry, ",")

	startIP, endIP, af, pfx, err := parseAddrRange(segs[0])
	if err != nil {
		return fmt.Errorf("invalid addr range %s", segs[0])
	}
	param.SetAf(af)
	if startIP != nil {
		param.GetAddrRange().SetMinAddr(startIP)
	}
	if endIP != nil {
		param.GetAddrRange().SetMaxAddr(endIP)
	} else {
		param.GetAddrRange().SetMaxAddr(startIP)
	}
	param.SetCidr(pfx)

	if len(segs) > 1 {
		startPort, endPort, proto, err := parsePortRange(segs[1])
		if err != nil {
			return err
		}
		param.GetAddrRange().SetMinPort(startPort)
		if endPort > 0 {
			param.GetAddrRange().SetMaxPort(endPort)
		} else {
			param.GetAddrRange().SetMaxPort(startPort)
		}
		param.SetProto(proto)
	}

	return nil
}

func (o *IPSetHashIPPort) ModelEntry(af uint8, member *IPSetMember) (*models.IpsetMember, error) {
	model := &models.IpsetMember{}

	entry := fmt.Sprintf("%s,%s:%d",
		member.GetAddr(af).String(),
		protoString(member.GetProto()),
		member.GetPort())
	model.Entry = &entry

	return model, nil
}

func (o *IPSetHashIPPort) CheckParam(param *IPSetParam) error {
	if param.opcode != IPSET_OP_ADD && param.opcode != IPSET_OP_DEL {
		return nil
	}
	if param.af == syscall.AF_INET6 {
		if param.cidr > 0 {
			return fmt.Errorf("hash:ip,port doesn't support IPv6 cidr")
		}
	} else if param.af == syscall.AF_INET {
		if param.cidr > 0 && param.cidr < 24 {
			return fmt.Errorf("ipv4 address cidr range too big, 256 at most")
		}
	}

	startIP, endIP, startPort, endPort := param.addrRange.Decode(param.af)
	if param.af == syscall.AF_INET {
		startIPNum, endIPNum := ip4ToUint32(startIP), ip4ToUint32(endIP)
		if endIPNum > 0 && endIPNum-startIPNum >= 256 {
			return fmt.Errorf("ipv4 address range too big, 256 at most")
		}
	}
	if endPort > 0 && endPort-startPort >= 256 {
		return fmt.Errorf("port range too big, 256 at most")
	}
	return nil
}

func (o *IPSetHashNetPort) ParseEntry(entry string, param *IPSetParam) error {
	// the same as IPSetHashIPPort
	var ipport IPSetHashIPPort
	return ipport.ParseEntry(entry, param)
}

func (o *IPSetHashNetPort) ModelEntry(af uint8, member *IPSetMember) (*models.IpsetMember, error) {
	model := &models.IpsetMember{}

	entry := fmt.Sprintf("%s/%d,%s:%d",
		member.GetAddr(af).String(),
		member.GetPort(),
		protoString(member.GetProto()),
		member.GetPort())
	model.Entry = &entry

	return model, nil
}

func (o *IPSetHashNetPort) CheckParam(param *IPSetParam) error {
	// nothing to do
	return nil
}

func (o *IPSetHashNetPortIface) ParseEntry(entry string, param *IPSetParam) error {
	segs := strings.Split(entry, ",")
	if len(segs) < 3 {
		return fmt.Errorf("invalid hash:net,port,iface entry: %s", entry)
	}

	startIP, endIP, af, pfx, err := parseAddrRange(segs[0])
	if err != nil {
		return fmt.Errorf("invalid addr range %s, error %v", segs[0], err)
	}
	param.SetAf(af)
	if startIP != nil {
		param.GetAddrRange().SetMinAddr(startIP)
	}
	if endIP != nil {
		param.GetAddrRange().SetMaxAddr(endIP)
	} else {
		param.GetAddrRange().SetMaxAddr(startIP)
	}
	param.SetCidr(pfx)

	segs = segs[1:]
	startPort, endPort, proto, err := parsePortRange(segs[0])
	if err != nil {
		return fmt.Errorf("invalid port range %s, error %v", segs[0], err)
	}
	param.GetAddrRange().SetMinPort(startPort)
	if endPort > 0 {
		param.GetAddrRange().SetMaxPort(endPort)
	} else {
		param.GetAddrRange().SetMaxPort(startPort)
	}
	param.SetProto(proto)

	segs = segs[1:]
	if len(segs[0]) == 0 {
		return fmt.Errorf("empty interface name")
	}
	param.SetIface(segs[0])

	return nil
}

func (o *IPSetHashNetPortIface) ModelEntry(af uint8, member *IPSetMember) (*models.IpsetMember, error) {
	model := &models.IpsetMember{}

	entry := fmt.Sprintf("%s/%d,%s:%d,%s",
		member.GetAddr(af).String(),
		member.GetPort(),
		protoString(member.GetProto()),
		member.GetPort(),
		member.GetIface())
	model.Entry = &entry

	return model, nil
}

func (o *IPSetHashNetPortIface) CheckParam(param *IPSetParam) error {
	// nothing to do
	return nil
}

func (o *IPSetHashIPPortIP) ParseEntry(entry string, param *IPSetParam) error {
	segs := strings.Split(entry, ",")
	if len(segs) < 3 {
		return fmt.Errorf("invalid hash:ip,port,ip entry: %s", entry)
	}

	startIP, endIP, af, pfx, err := parseAddrRange(segs[0])
	if err != nil {
		return fmt.Errorf("invalid addr range %s, error %v", segs[0], err)
	}
	param.SetAf(af)
	if startIP != nil {
		param.GetAddrRange().SetMinAddr(startIP)
	}
	if endIP != nil {
		param.GetAddrRange().SetMaxAddr(endIP)
	} else {
		param.GetAddrRange().SetMaxAddr(startIP)
	}
	param.SetCidr(pfx)

	segs = segs[1:]
	startPort, endPort, proto, err := parsePortRange(segs[0])
	if err != nil {
		return fmt.Errorf("invalid port range %s, err %v", segs[0], err)
	}
	param.GetAddrRange().SetMinPort(startPort)
	if endPort > 0 {
		param.GetAddrRange().SetMaxPort(endPort)
	} else {
		param.GetAddrRange().SetMaxPort(startPort)
	}
	param.SetProto(proto)

	segs = segs[1:]
	startIP2, endIP2, af2, pfx2, err := parseAddrRange(segs[0])
	if err != nil {
		return fmt.Errorf("invalid addr range2 %s, error %v", segs[0], err)
	}
	if af2 != af {
		return fmt.Errorf("address family mismatch in hash:ip,port,ip member")
	}
	if startIP2 != nil {
		param.GetAddrRange2().SetMinAddr(startIP2)
	}
	if endIP2 != nil {
		param.GetAddrRange2().SetMaxAddr(endIP2)
	} else {
		param.GetAddrRange2().SetMaxAddr(startIP2)
	}
	param.SetCidr2(pfx2)

	return nil
}

func (o *IPSetHashIPPortIP) ModelEntry(af uint8, member *IPSetMember) (*models.IpsetMember, error) {
	model := &models.IpsetMember{}

	entry := fmt.Sprintf("%s,%s:%d,%s",
		member.GetAddr(af).String(),
		protoString(member.GetProto()),
		member.GetPort(),
		member.GetAddr2(af).String())
	model.Entry = &entry

	return model, nil
}

func (o *IPSetHashIPPortIP) CheckParam(param *IPSetParam) error {
	if param.opcode != IPSET_OP_ADD && param.opcode != IPSET_OP_DEL {
		return nil
	}

	if param.af == syscall.AF_INET6 {
		if param.cidr > 0 || param.cidr2 > 0 {
			return fmt.Errorf("hash:ip,port,ip doesn't support IPv6 cidr")
		}
	} else if param.af == syscall.AF_INET {
		if param.cidr > 0 && param.cidr < 24 {
			return fmt.Errorf("ipv4 address cidr range too big, 256 at most")
		}
		if param.cidr2 > 0 && param.cidr2 < 24 {
			return fmt.Errorf("ipv4 address cidr2 range too big, 256 at most")
		}
	}

	startIP, endIP, startPort, endPort := param.addrRange.Decode(param.af)
	if param.af == syscall.AF_INET {
		startIPNum, endIPNum := ip4ToUint32(startIP), ip4ToUint32(endIP)
		if endIPNum > 0 && endIPNum-startIPNum >= 256 {
			return fmt.Errorf("ipv4 address range too big, 256 at most")
		}
	}
	if endPort > 0 && endPort-startPort >= 256 {
		return fmt.Errorf("port range too big, 256 at most")
	}

	startIP2, endIP2, _, _ := param.addrRange.Decode(param.af)
	if param.af == syscall.AF_INET {
		startIPNum2, endIPNum2 := ip4ToUint32(startIP2), ip4ToUint32(endIP2)
		if endIPNum2 > 0 && endIPNum2-startIPNum2 >= 256 {
			return fmt.Errorf("ipv4 address range2 too big, 256 at most")
		}
	}

	return nil
}

func (o *IPSetHashIPPortNet) ParseEntry(entry string, param *IPSetParam) error {
	segs := strings.Split(entry, ",")
	if len(segs) < 3 {
		return fmt.Errorf("invalid hash:ip,port,net entry: %s", entry)
	}

	// Notes: The "ip" and "net" parts in hash:ip,port,net corresponds to addr range1
	//        and addr range2 respectively, so that match from a source address network
	//        to a single dest address can be implemented easily.

	// the "ip" part corresponds to address range2
	startIP2, endIP2, af2, pfx2, err := parseAddrRange(segs[0])
	if err != nil {
		return fmt.Errorf("invalid addr range %s, error %v", segs[0], err)
	}
	param.SetAf(af2)
	if startIP2 != nil {
		param.GetAddrRange2().SetMinAddr(startIP2)
	}
	if endIP2 != nil {
		param.GetAddrRange2().SetMaxAddr(endIP2)
	} else {
		param.GetAddrRange2().SetMaxAddr(startIP2)
	}
	param.SetCidr2(pfx2)

	// the "port" part
	segs = segs[1:]
	startPort, endPort, proto, err := parsePortRange(segs[0])
	if err != nil {
		return fmt.Errorf("invalid port range %s, err %v", segs[0], err)
	}
	param.GetAddrRange().SetMinPort(startPort)
	if endPort > 0 {
		param.GetAddrRange().SetMaxPort(endPort)
	} else {
		param.GetAddrRange().SetMaxPort(startPort)
	}
	param.SetProto(proto)

	// the "net" part corresponds to address range1
	segs = segs[1:]
	startIP, endIP, af, pfx, err := parseAddrRange(segs[0])
	if err != nil {
		return fmt.Errorf("invalid addr range %s, error %v", segs[0], err)
	}
	if af != af2 {
		return fmt.Errorf("address family mismatch in hash:ip,port,net member")
	}
	if startIP != nil {
		param.GetAddrRange().SetMinAddr(startIP)
	}
	if endIP != nil {
		param.GetAddrRange().SetMaxAddr(endIP)
	} else {
		param.GetAddrRange().SetMaxAddr(startIP)
	}
	param.SetCidr(pfx)

	return nil
}

func (o *IPSetHashIPPortNet) ModelEntry(af uint8, member *IPSetMember) (*models.IpsetMember, error) {
	model := &models.IpsetMember{}

	entry := fmt.Sprintf("%s/%d,%s:%d,%s",
		member.GetAddr(af).String(),
		member.GetCidr(),
		protoString(member.GetProto()),
		member.GetPort(),
		member.GetAddr2(af).String())
	model.Entry = &entry

	return model, nil
}

func (o *IPSetHashIPPortNet) CheckParam(param *IPSetParam) error {
	if param.opcode != IPSET_OP_ADD && param.opcode != IPSET_OP_DEL {
		return nil
	}

	if param.af == syscall.AF_INET6 {
		if param.cidr2 > 0 {
			return fmt.Errorf("hash:ip,port,net doesn't support IPv6 cidr")
		}
	} else if param.af == syscall.AF_INET {
		if param.cidr2 > 0 && param.cidr2 < 24 {
			return fmt.Errorf("ipv4 address cidr2 range too big, 256 at most")
		}
	}

	_, _, startPort, endPort := param.addrRange.Decode(param.af)
	if endPort > 0 && endPort-startPort >= 256 {
		return fmt.Errorf("port range too big, 256 at most")
	}

	startIP2, endIP2, _, _ := param.addrRange.Decode(param.af)
	if param.af == syscall.AF_INET {
		startIPNum2, endIPNum2 := ip4ToUint32(startIP2), ip4ToUint32(endIP2)
		if endIPNum2 > 0 && endIPNum2-startIPNum2 >= 256 {
			return fmt.Errorf("ipv4 address range2 too big, 256 at most")
		}
	}

	return nil
}

func (o *IPSetHashNetPortNet) ParseEntry(entry string, param *IPSetParam) error {
	// Notes: almost the same as IPSetHashIPPortIP except the error message,

	segs := strings.Split(entry, ",")
	if len(segs) < 3 {
		return fmt.Errorf("invalid hash:net,port,net entry: %s", entry)
	}

	startIP, endIP, af, pfx, err := parseAddrRange(segs[0])
	if err != nil {
		return fmt.Errorf("invalid addr range %s, error %v", segs[0], err)
	}
	param.SetAf(af)
	if startIP != nil {
		param.GetAddrRange().SetMinAddr(startIP)
	}
	if endIP != nil {
		param.GetAddrRange().SetMaxAddr(endIP)
	} else {
		param.GetAddrRange().SetMaxAddr(startIP)
	}
	param.SetCidr(pfx)

	segs = segs[1:]
	startPort, endPort, proto, err := parsePortRange(segs[0])
	if err != nil {
		return fmt.Errorf("invalid port range %s, err %v", segs[0], err)
	}
	param.GetAddrRange().SetMinPort(startPort)
	if endPort > 0 {
		param.GetAddrRange().SetMaxPort(endPort)
	} else {
		param.GetAddrRange().SetMaxPort(startPort)
	}
	param.SetProto(proto)

	segs = segs[1:]
	startIP2, endIP2, af2, pfx2, err := parseAddrRange(segs[0])
	if err != nil {
		return fmt.Errorf("invalid addr range2 %s, error %v", segs[0], err)
	}
	if af2 != af {
		return fmt.Errorf("address family mismatch in hash:net,port,net member")
	}
	if startIP2 != nil {
		param.GetAddrRange2().SetMinAddr(startIP2)
	}
	if endIP2 != nil {
		param.GetAddrRange2().SetMaxAddr(endIP2)
	} else {
		param.GetAddrRange2().SetMaxAddr(startIP2)
	}
	param.SetCidr2(pfx2)

	return nil
}

func (o *IPSetHashNetPortNet) ModelEntry(af uint8, member *IPSetMember) (*models.IpsetMember, error) {
	model := &models.IpsetMember{}

	entry := fmt.Sprintf("%s/%d,%s:%d,%s/%d",
		member.GetAddr(af).String(),
		member.GetCidr(),
		protoString(member.GetProto()),
		member.GetPort(),
		member.GetAddr2(af).String(),
		member.GetCidr2())
	model.Entry = &entry

	return model, nil
}

func (o *IPSetHashNetPortNet) CheckParam(param *IPSetParam) error {
	// nothing to do
	return nil
}

func (o *IPSetHashNetPortNetPort) ParseEntry(entry string, param *IPSetParam) error {
	segs := strings.Split(entry, ",")
	if len(segs) < 4 {
		return fmt.Errorf("invalid hash:net,port,net,port entry: %s", entry)
	}

	startIP, endIP, af, pfx, err := parseAddrRange(segs[0])
	if err != nil {
		return fmt.Errorf("invalid addr range %s, error %v", segs[0], err)
	}
	param.SetAf(af)
	if startIP != nil {
		param.GetAddrRange().SetMinAddr(startIP)
	}
	if endIP != nil {
		param.GetAddrRange().SetMaxAddr(endIP)
	} else {
		param.GetAddrRange().SetMaxAddr(startIP)
	}
	param.SetCidr(pfx)

	segs = segs[1:]
	startPort, endPort, proto, err := parsePortRange(segs[0])
	if err != nil {
		return fmt.Errorf("invalid port range %s, err %v", segs[0], err)
	}
	param.GetAddrRange().SetMinPort(startPort)
	if endPort > 0 {
		param.GetAddrRange().SetMaxPort(endPort)
	} else {
		param.GetAddrRange().SetMaxPort(startPort)
	}
	param.SetProto(proto)

	segs = segs[1:]
	startIP2, endIP2, af2, pfx2, err := parseAddrRange(segs[0])
	if err != nil {
		return fmt.Errorf("invalid addr range2 %s, error %v", segs[0], err)
	}
	if af2 != af {
		return fmt.Errorf("address family mismatch in hash:net,port,net,port member")
	}
	if startIP2 != nil {
		param.GetAddrRange2().SetMinAddr(startIP2)
	}
	if endIP2 != nil {
		param.GetAddrRange2().SetMaxAddr(endIP2)
	} else {
		param.GetAddrRange2().SetMaxAddr(startIP2)
	}
	param.SetCidr2(pfx2)

	segs = segs[1:]
	startPort2, endPort2, proto2, err := parsePortRange(segs[0])
	if err != nil {
		return fmt.Errorf("invalid port range2 %s, err %v", segs[0], err)
	}
	if proto2 != proto {
		return fmt.Errorf("protocol mismatch in hash:net,port,net,port member")
	}
	param.GetAddrRange2().SetMinPort(startPort2)
	if endPort2 > 0 {
		param.GetAddrRange2().SetMaxPort(endPort2)
	} else {
		param.GetAddrRange2().SetMaxPort(startPort2)
	}

	return nil
}

func (o *IPSetHashNetPortNetPort) ModelEntry(af uint8, member *IPSetMember) (*models.IpsetMember, error) {
	model := &models.IpsetMember{}

	proto := protoString(member.GetProto())
	entry := fmt.Sprintf("%s/%d,%s:%d,%s/%d,%s:%d",
		member.GetAddr(af).String(),
		member.GetCidr(),
		proto, member.GetPort(),
		member.GetAddr2(af).String(),
		member.GetCidr2(),
		proto, member.GetPort2())
	model.Entry = &entry

	return model, nil
}

func (o *IPSetHashNetPortNetPort) CheckParam(param *IPSetParam) error {
	// nothing to do
	return nil
}

var ipsetTypes = map[models.IpsetType]IPSetType{
	models.IpsetTypeBitmapIP:           &IPSetBitmapIP{},
	models.IpsetTypeBitmapIPMac:        &IPSetBitmapIPMac{},
	models.IpsetTypeBitmapPort:         &IPSetBitmapPort{},
	models.IpsetTypeHashIP:             &IPSetHashIP{},
	models.IpsetTypeHashNet:            &IPSetHashNet{},
	models.IpsetTypeHashIPPort:         &IPSetHashIPPort{},
	models.IpsetTypeHashNetPort:        &IPSetHashNetPort{},
	models.IpsetTypeHashNetPortIface:   &IPSetHashNetPortIface{},
	models.IpsetTypeHashIPPortIP:       &IPSetHashIPPortIP{},
	models.IpsetTypeHashIPPortNet:      &IPSetHashIPPortNet{},
	models.IpsetTypeHashNetPortNet:     &IPSetHashNetPortNet{},
	models.IpsetTypeHashNetPortNetPort: &IPSetHashNetPortNetPort{},
}

func IPSetTypeGet(kind models.IpsetType) IPSetType {
	return ipsetTypes[kind]
}

func afCode(family string) uint8 {
	switch strings.ToLower(family) {
	case "":
		return syscall.AF_UNSPEC
	case "ipv4":
		return syscall.AF_INET
	case "ipv6":
		return syscall.AF_INET6
	default:
		return syscall.AF_MAX
	}
}

func afString(af uint8) string {
	switch af {
	case syscall.AF_INET:
		return "ipv4"
	case syscall.AF_INET6:
		return "ipv6"
	default:
		return "not-supported"
	}
}

func protoString(proto uint8) string {
	switch proto {
	case syscall.IPPROTO_TCP:
		return "tcp"
	case syscall.IPPROTO_UDP:
		return "udp"
	case syscall.IPPROTO_ICMP:
		return "icmp"
	case syscall.IPPROTO_ICMPV6:
		return "icmp6"
	}
	return "unspec"
}

func ip4ToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
}

// Parse IP range
// Format:
//
//	{ IPv4 | IPv4-IPv4 | IPv4/pfx4 | IPv6 | IPv6/pfx6 }
//
// Example:
//   - 192.168.1.0/24
//   - 192.168.88.100-120
//   - 2001::/112
func parseAddrRange(ar string) (startIP, endIP net.IP, af, cidr uint8, err error) {
	if strings.Contains(ar, ":") {
		af = syscall.AF_INET6
	} else {
		af = syscall.AF_INET
	}

	if af == syscall.AF_INET {
		if strings.Contains(ar, "-") {
			parts := strings.Split(ar, "-")
			if len(parts) != 2 {
				err = fmt.Errorf("invalid IPv4 range format %q", ar)
				return
			}
			startIP = net.ParseIP(parts[0]).To4()
			endIP = net.ParseIP(parts[1]).To4()
			if startIP == nil || endIP == nil {
				err = fmt.Errorf("invalid IPv4 address %q", ar)
				return
			}
			if ip4ToUint32(startIP) > ip4ToUint32(endIP) {
				err = fmt.Errorf("invalid IPv4 range %q", ar)
				return
			}
		} else if strings.Contains(ar, "/") {
			ip, ipNet, err2 := net.ParseCIDR(ar)
			if err2 != nil {
				err = fmt.Errorf("invalid IPv4 CIDR format: %v", err2)
				return
			}
			startIP = ip.To4()
			pfx, _ := ipNet.Mask.Size()
			cidr = uint8(pfx)
		} else {
			if startIP = net.ParseIP(ar); startIP != nil {
				startIP = startIP.To4()
			}
			if startIP == nil {
				err = fmt.Errorf("unsupported IPv4 format")
				return
			}
		}
	} else { // syscall.AF_INET6
		if strings.Contains(ar, "/") {
			ip, ipNet, err2 := net.ParseCIDR(ar)
			if err2 != nil {
				err = fmt.Errorf("invalid IPv6 CIDR format: %v", err2)
				return
			}
			startIP = ip.To16()
			pfx, _ := ipNet.Mask.Size()
			cidr = uint8(pfx)
		} else {
			startIP = net.ParseIP(ar)
			if startIP == nil {
				err = fmt.Errorf("unsupported IPv6 format")
				return
			}
		}
	}

	return
}

// Format:
//
//	PROTO:PORT[-PORT]
//	PROTO := tcp | udp | icmp | icmp6
//	PORT := NUM(0-65535)
//
// Example:
//
//	tcp:8080-8082
func parsePortRange(pr string) (port1, port2 uint16, proto uint8, err error) {
	parts := strings.Split(pr, ":")
	if len(parts) > 2 {
		err = fmt.Errorf("too many segments in %q", pr)
		return
	}

	if len(parts) > 1 {
		protoStr := strings.ToLower(parts[0])
		switch protoStr {
		case "tcp":
			proto = syscall.IPPROTO_TCP
		case "udp":
			proto = syscall.IPPROTO_UDP
		case "icmp":
			proto = syscall.IPPROTO_ICMP
		case "icmp6":
			proto = syscall.IPPROTO_ICMPV6
		default:
			err = fmt.Errorf("invalid protocol %q", protoStr)
			return
		}
		parts = parts[1:]
	}

	portRange := parts[0]
	parts = strings.Split(portRange, "-")
	if len(parts) > 2 {
		err = fmt.Errorf("too many segments in port range %q", portRange)
		return
	}

	_port1, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		err = fmt.Errorf("invalid port number %q", parts[0])
		return
	}
	port1 = uint16(_port1)

	if len(parts) > 1 {
		var _port2 uint64
		_port2, err = strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			err = fmt.Errorf("invalid port number %q", parts[1])
			return
		}
		port2 = uint16(_port2)
	}
	return
}

func (o *IPSetParam) Build(model *models.IpsetInfo) error {
	if len(model.Entries) > 0 && model.CreationOptions != nil {
		return fmt.Errorf("Entries and CreationOptions cannot both set")
	}
	if len(model.Entries) > 1 {
		return fmt.Errorf("More than 1 entry set for IPSetParam")
	}

	o.SetName(*model.Name)
	o.SetKind(string(*model.Type))

	if model.CreationOptions != nil {
		options := model.CreationOptions
		if options.Comment != nil {
			o.SetCommentFlag(*options.Comment)
		}
		o.SetMaxElem(options.HashMaxElem)
		o.SetHashSize(options.HashSize)
		af := afCode(options.Family)
		if af == syscall.AF_MAX {
			return fmt.Errorf("Unsupported address family %q", options.Family)
		}
		o.SetAf(af)
		if len(options.Range) > 0 {
			if strings.ContainsAny(options.Range, ".:") && unicode.Is(unicode.ASCII_Hex_Digit,
				rune(options.Range[0])) { // IPv4 or IPv6
				startIP, endIP, af2, pfx, err := parseAddrRange(options.Range)
				if err != nil {
					return err
				}
				if af2 != af {
					if af == syscall.AF_UNSPEC {
						o.SetAf(af2)
					} else {
						return fmt.Errorf("Address family mismatch")
					}
				}
				o.GetAddrRange().SetMinAddr(startIP)
				if endIP != nil {
					o.GetAddrRange().SetMaxAddr(endIP)
				}
				if pfx > 0 {
					o.SetCidr(pfx)
				}
			} else { // Port
				startPort, endPort, proto, err := parsePortRange(options.Range)
				if err != nil {
					return err
				}
				o.GetAddrRange().SetMinPort(startPort)
				if endPort != 0 {
					o.GetAddrRange().SetMaxPort(endPort)
				} else {
					o.GetAddrRange().SetMaxPort(startPort)
				}
				o.SetProto(proto)
			}
		}
	}

	if len(model.Entries) > 0 {
		return o.BuildMember(model.Entries[0])
	}
	return nil
}

func (o *IPSetParamArray) Build(opcode uint16, model *models.IpsetInfo) error {
	if opcode == IPSET_OP_FLUSH {
		param := new(IPSetParam)
		param.SetOpcode(opcode)
		param.SetName(*model.Name)
		param.SetKind(string(*model.Type))
		*o = append(*o, *param)
		return nil
	}

	if len(model.Entries) < 1 {
		return fmt.Errorf("No Entries found in IpsetInfo model")
	}
	if model.CreationOptions != nil {
		return fmt.Errorf("CreationOptions supplied with multiple Entries")
	}

	for _, entry := range model.Entries {
		param := new(IPSetParam)
		param.SetOpcode(opcode)
		param.SetName(*model.Name)
		param.SetKind(string(*model.Type))
		err := param.BuildMember(entry)
		if err != nil {
			return fmt.Errorf("Parse ipset member %v failed: %v", entry.Entry, err)
		}
		*o = append(*o, *param)
	}
	return nil
}

// o.kind must be filled before calling BuildMember
func (o *IPSetParam) BuildMember(model *models.IpsetMember) error {
	kind := o.getKind()
	setType := IPSetTypeGet(models.IpsetType(kind))
	if setType == nil {
		return fmt.Errorf("Unsupported ipset type %q", kind)
	}

	if model.Entry == nil {
		return fmt.Errorf("Empty ipset member entry")
	}

	o.SetComment(model.Comment)
	if model.Options != nil {
		if model.Options.Force != nil && *model.Options.Force {
			o.AddFlag(IPSET_F_FORCE)
		} else {
			o.DelFlag(IPSET_F_FORCE)
		}
		if model.Options.NoMatch != nil {
			o.SetNomatch(*model.Options.NoMatch)
		}
	}

	return setType.ParseEntry(*model.Entry, o)
}

func (o *IPSetParam) Check() error {
	if o.opcode >= IPSET_OP_MAX {
		return fmt.Errorf("Invalid ipset opcode %v", o.opcode)
	} else if o.opcode == IPSET_OP_LIST {
		return nil
	} else if o.opcode == IPSET_OP_TEST {
		if o.cidr > 0 || o.cidr2 > 0 {
			return fmt.Errorf("Cidr set in IPSET_OP_TEST (IsIn)")
		}
	}

	kind := o.getKind()
	setType := IPSetTypeGet(models.IpsetType(kind))
	if setType == nil {
		return fmt.Errorf("Unsupported ipset type %q", kind)
	}

	startIP1, endIP1, startPort1, endPort1 := o.addrRange.Decode(o.af)
	startIP2, endIP2, startPort2, endPort2 := o.addrRange2.Decode(o.af)
	if o.af == syscall.AF_INET6 {
		if !endIP1.Equal(net.IPv6zero) && !endIP1.Equal(startIP1) {
			return fmt.Errorf("IPv6 range is not supported")
		}
		if !endIP2.Equal(net.IPv6zero) && !endIP2.Equal(startIP2) {
			return fmt.Errorf("IPv6 range is not supported")
		}
	} else if o.af == syscall.AF_INET {
		start, end := ip4ToUint32(startIP1), ip4ToUint32(endIP1)
		if end != 0 && start > end {
			return fmt.Errorf("Invalid IPv4 range: %v-%v", startIP1, endIP1)
		}
		start, end = ip4ToUint32(startIP2), ip4ToUint32(endIP2)
		if end != 0 && start > end {
			return fmt.Errorf("Invalid IPv4 range: %v-%v", startIP2, endIP2)
		}
	}

	if endPort1 > 0 && startPort1 > endPort1 {
		return fmt.Errorf("Invalid port range: %d-%d", startPort1, endPort1)
	}

	if endPort2 > 0 && startPort2 > endPort2 {
		return fmt.Errorf("Invalid port range: %d-%d", startPort2, endPort2)
	}

	return setType.CheckParam(o)
}

func (o *IPSetParamArray) Check() error {
	for _, param := range *o {
		if err := param.Check(); err != nil {
			return err
		}
	}
	return nil
}

func (o *IPSetMember) Model(af uint8, kind models.IpsetType) (*models.IpsetMember, error) {
	setType := IPSetTypeGet(kind)
	if setType == nil {
		return nil, fmt.Errorf("Unsupported ipset type %q", kind)
	}

	model, err := setType.ModelEntry(af, o)
	if err != nil {
		return nil, err
	}

	model.Comment = o.GetComment()
	nomatch := o.GetNoMatch()
	if nomatch {
		model.Options = &models.IpsetOption{}
		model.Options.NoMatch = &nomatch
	}
	return model, nil
}

func (o *IPSetInfo) Model() (*models.IpsetInfo, error) {
	model := new(models.IpsetInfo)
	model.Name = new(string)
	model.Type = new(models.IpsetType)
	model.CreationOptions = new(models.IpsetCreationOption)

	*model.Name = o.GetName()
	*model.Type = models.IpsetType(o.GetKind())
	model.Opcode = IPSET_OP_LIST

	af := o.GetAf()
	cidr := o.GetCidr()
	withIP := false

	copts := model.CreationOptions
	if o.GetComment() {
		copts.Comment = new(bool)
		*copts.Comment = true
	}
	copts.Family = afString(af)
	if strings.HasPrefix(string(*model.Type), "hash:") {
		copts.HashMaxElem = o.GetHashMaxElem()
		copts.HashSize = o.GetHashSize()
	} else if strings.HasPrefix(string(*model.Type), "bitmap:") {
		copts.Range = ""
		startIP, endIP, startPort, endPort := o.GetAddrRange()
		if cidr > 0 {
			copts.Range += fmt.Sprintf("%s/%d", startIP, cidr)
			withIP = true
		} else if af == syscall.AF_INET {
			startIPNum, endIPNum := ip4ToUint32(startIP), ip4ToUint32(endIP)
			if endIPNum > startIPNum {
				copts.Range += fmt.Sprintf("%s-%s", startIP.String(), endIP.String())
				withIP = true
			}
		}
		if endPort > startPort {
			if withIP {
				copts.Range += ":"
			}
			copts.Range += fmt.Sprintf("%d-%d", startPort, endPort)
		}
	}

	for _, member := range o.GetMembers() {
		memberModel, err := member.Model(af, *model.Type)
		if err != nil {
			return nil, err
		}
		model.Entries = append(model.Entries, memberModel)
	}

	return model, nil
}

func (o *IPSetInfoArray) Model() (*models.IpsetInfoArray, error) {
	model := new(models.IpsetInfoArray)
	for _, info := range o.GetIPSetInfos() {
		infoModel, err := info.Model()
		if err != nil {
			return nil, err
		}
		model.Infos = append(model.Infos, infoModel)
	}
	model.Count = int32(len(model.Infos))

	return model, nil
}
