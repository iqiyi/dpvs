package manager

import "net"

// VAID represents VirtualAddress ID.
// It must have the same format of net.IP::String().
type VAID string

type VirtualAddress struct {
	IP net.IP
}
