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
func sendfileOther(_, _ int, _ int64) (int64, error) {
	return 0, fmt.Errorf("sendfile() not supported on this platform")
}

// isSameFilesystemOther checks if two files are on the same filesystem on non-Linux platforms
func isSameFilesystemOther(_, _ string) bool {
	// Conservative approach: assume different filesystems
	return false
}

// sendfilePlatform provides platform-specific sendfile implementation
func sendfilePlatform(dstFd, srcFd int, size int64) (int64, error) {
	return sendfileOther(dstFd, srcFd, size)
}

// isSameFilesystemPlatform provides platform-specific filesystem check
func isSameFilesystemPlatform(src, dst string) bool {
	return isSameFilesystemOther(src, dst)
}
