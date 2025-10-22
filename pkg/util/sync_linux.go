//go:build linux
// +build linux

package util

import "syscall"

// syncFilesystem performs a filesystem sync on Linux.
// On Linux, syscall.Sync() does not return an error.
func syncFilesystem() error {
	syscall.Sync()
	return nil
}
