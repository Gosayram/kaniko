//go:build linux && !go1.23

package platform

import (
	"golang.org/x/sys/unix"
)

// runtimeArchitecture gets the name of the current architecture (x86, x86_64, i86pc, sun4v, ...)
func runtimeArchitecture() (string, error) {
	utsname := &unix.Utsname{}
	if err := unix.Uname(utsname); err != nil {
		return "", err
	}
	return unix.ByteSliceToString(utsname.Machine[:]), nil
}

// possibleCPUs returns the set of possible CPUs on the host.
// For Linux systems without Go 1.23+, this is not implemented and returns nil,
// which will trigger the fallback in platform.go
func possibleCPUs() []int {
	// not implemented for Linux without Go 1.23+
	return nil
}
