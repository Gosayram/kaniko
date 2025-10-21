//go:build !linux

package snapshot

import (
	"syscall"

	"github.com/sirupsen/logrus"
)

// syncFilesystem performs a filesystem sync on non-Linux systems
func syncFilesystem() {
	// Non-Linux systems may return error
	if err := syscall.Sync(); err != nil {
		logrus.Warnf("Failed to sync filesystem: %v", err)
	}
}
