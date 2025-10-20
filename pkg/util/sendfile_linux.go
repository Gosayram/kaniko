//go:build linux

/*
Copyright 2024 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"fmt"
	"syscall"
)

// Constants for sendfile operations
const (
	maxSendfileChunk = 0x7ffff000 // Maximum chunk size for sendfile
)

// sendfileLinux implements sendfile() system call for Linux
func sendfileLinux(dstFd, srcFd int, size int64) (int64, error) {
	var offset int64
	var written int64

	for written < size {
		remaining := size - written
		if remaining > maxSendfileChunk { // Max chunk size for sendfile
			remaining = maxSendfileChunk
		}

		n, err := syscall.Sendfile(dstFd, srcFd, &offset, int(remaining))
		if err != nil {
			return written, err
		}

		if n == 0 {
			break // EOF
		}

		written += int64(n)
	}

	return written, nil
}

// getFileSystemInfoLinux gets filesystem information for Linux
func getFileSystemInfoLinux(path string) (uint64, error) {
	var stat syscall.Statfs_t
	err := syscall.Statfs(path, &stat)
	if err != nil {
		return 0, err
	}
	// Safe conversion to prevent overflow
	if stat.Type >= 0 {
		return uint64(stat.Type), nil
	}
	return 0, fmt.Errorf("filesystem type is negative: %d", stat.Type)
}

// isSameFilesystemLinux checks if two files are on the same filesystem on Linux
func isSameFilesystemLinux(src, dst string) bool {
	srcFS, err := getFileSystemInfoLinux(src)
	if err != nil {
		return false
	}

	dstFS, err := getFileSystemInfoLinux(dst)
	if err != nil {
		return false
	}

	return srcFS == dstFS
}

// sendfilePlatform provides platform-specific sendfile implementation
func sendfilePlatform(dstFd, srcFd int, size int64) (int64, error) {
	return sendfileLinux(dstFd, srcFd, size)
}

// isSameFilesystemPlatform provides platform-specific filesystem check
func isSameFilesystemPlatform(src, dst string) bool {
	return isSameFilesystemLinux(src, dst)
}
