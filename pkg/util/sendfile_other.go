//go:build !linux

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
)

// sendfileOther provides fallback implementation for non-Linux platforms
func sendfileOther(dstFd, srcFd int, size int64) (int64, error) {
	return 0, fmt.Errorf("sendfile() not supported on this platform")
}

// isSendfileSupportedOther checks if sendfile() is supported on non-Linux platforms
func isSendfileSupportedOther(srcFd, dstFd int) bool {
	return false // sendfile() not supported on non-Linux platforms
}

// getFileSystemInfoOther gets filesystem information for non-Linux platforms
func getFileSystemInfoOther(path string) (uint64, error) {
	return 0, fmt.Errorf("filesystem info not available on this platform")
}

// isSameFilesystemOther checks if two files are on the same filesystem on non-Linux platforms
func isSameFilesystemOther(src, dst string) bool {
	// Conservative approach: assume different filesystems
	return false
}

// getFileSizeOther gets file size using fstat on non-Linux platforms
func getFileSizeOther(fd int) (int64, error) {
	return 0, fmt.Errorf("file size not available on this platform")
}

// copyFileWithSendfileOther copies a file using sendfile() on non-Linux platforms
func copyFileWithSendfileOther(srcFd, dstFd int) (int64, error) {
	return 0, fmt.Errorf("sendfile() not supported on this platform")
}

// sendfilePlatform provides platform-specific sendfile implementation
func sendfilePlatform(dstFd, srcFd int, size int64) (int64, error) {
	return sendfileOther(dstFd, srcFd, size)
}

// isSameFilesystemPlatform provides platform-specific filesystem check
func isSameFilesystemPlatform(src, dst string) bool {
	return isSameFilesystemOther(src, dst)
}
