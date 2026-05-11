//go:build linux

package collectors

import (
	"os"
	"syscall"
)

// setNonBlocking sets O_NONBLOCK on a file so reads don't block waiting
// for new kernel messages. /dev/kmsg blocks by default.
func setNonBlocking(f *os.File) error {
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(),
		syscall.F_SETFL, syscall.O_NONBLOCK)
	if errno != 0 {
		return errno
	}
	return nil
}
