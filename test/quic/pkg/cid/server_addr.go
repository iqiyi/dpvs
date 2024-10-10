package cid

import (
	"net"
)

func FindLocalIP(targetIP string) (net.IP, error) {
	if len(targetIP) == 0 {
		targetIP = "8.8.8.8"
	}

	raddr, err := net.ResolveIPAddr("ip", targetIP)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialIP("ip:icmp", nil, raddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.IPAddr)
	return localAddr.IP, nil
}
