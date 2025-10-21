//go:build linux

package snapshot

import "syscall"

// syncFilesystem performs a filesystem sync on Linux
func syncFilesystem() {
	// Linux syscall.Sync() doesn't return error
	syscall.Sync()
}
