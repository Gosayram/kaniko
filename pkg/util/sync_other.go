//go:build !linux
// +build !linux

package util

import (
	"syscall"

	"github.com/sirupsen/logrus"
)

// syncFilesystem performs a filesystem sync on non-Linux systems.
// On other systems, syscall.Sync() may return an error.
func syncFilesystem() error {
	if err := syscall.Sync(); err != nil {
		logrus.Warnf("Failed to sync filesystem: %v", err)
		return err
	}
	return nil
}
