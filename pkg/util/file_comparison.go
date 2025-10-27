/*
Copyright 2018 Google LLC

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
	"os"
	"syscall"
)

// File comparison utilities
// These functions provide common file comparison logic used across different
// file system operations while maintaining the specific behavior required
// by each context.

// IsFileInfoSame compares two os.FileInfo objects to determine if they represent
// the same file state. This is used by both GetFSInfoMap and WalkFS functions
// but may have different requirements in different contexts.
//
// The comparison includes:
// - File mode (permissions)
// - Modification time
// - File size
// - User ID
// - Group ID
//
// Note: This function assumes both FileInfo objects are from Unix-like systems
// and will panic if the Sys() method doesn't return *syscall.Stat_t
func IsFileInfoSame(fi1, fi2 os.FileInfo) bool {
	if fi1 == nil || fi2 == nil {
		return fi1 == fi2
	}

	return fi1.Mode() == fi2.Mode() &&
		// file modification time
		fi1.ModTime().Equal(fi2.ModTime()) &&
		// file size
		fi1.Size() == fi2.Size() &&
		// file user id
		uint64(fi1.Sys().(*syscall.Stat_t).Uid) == uint64(fi2.Sys().(*syscall.Stat_t).Uid) &&
		// file group id
		uint64(fi1.Sys().(*syscall.Stat_t).Gid) == uint64(fi2.Sys().(*syscall.Stat_t).Gid)
}

// SafeFileInfoSame is a safer version of IsFileInfoSame that handles
// cases where Sys() might not return *syscall.Stat_t
func SafeFileInfoSame(fi1, fi2 os.FileInfo) bool {
	if fi1 == nil || fi2 == nil {
		return fi1 == fi2
	}

	// Basic comparison that works on all systems
	if fi1.Mode() != fi2.Mode() ||
		!fi1.ModTime().Equal(fi2.ModTime()) ||
		fi1.Size() != fi2.Size() {
		return false
	}

	// Try to compare UID/GID if available
	if stat1, ok1 := fi1.Sys().(*syscall.Stat_t); ok1 {
		if stat2, ok2 := fi2.Sys().(*syscall.Stat_t); ok2 {
			return uint64(stat1.Uid) == uint64(stat2.Uid) &&
				uint64(stat1.Gid) == uint64(stat2.Gid)
		}
	}

	// If we can't compare UID/GID, assume they're the same
	// This maintains backward compatibility
	return true
}
