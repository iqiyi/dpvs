package device

import (
	"golang.org/x/sys/unix"
)

func ioctl(fd int, code, data uintptr) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), code, data)
	if errno != 0 {
		return errno
	}
	return nil
}

type socketAddr4Request struct {
	name [unix.IFNAMSIZ]byte
	addr unix.RawSockaddrInet4
}

type socketAddr6Request struct {
	name [unix.IFNAMSIZ]byte
	addr unix.RawSockaddrInet6
}
