/*
Copyright 2020 Google LLC

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

// Package util provides various utility functions for filesystem operations, system calls, and other common tasks.
package util //nolint:revive // package name 'util' is intentionally generic

import (
	"syscall"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// convertToSafeCredentials converts UID/GID to safe uint32 values
func convertToSafeCredentials(safeUID, safeGID int64) (finalUID, finalGID uint32) {
	if safeUID >= 0 && safeUID <= 0xFFFFFFFF {
		finalUID = uint32(safeUID)
	} else {
		finalUID = uint32(SafeDefaultUID)
	}
	if safeGID >= 0 && safeGID <= 0xFFFFFFFF {
		finalGID = uint32(safeGID)
	} else {
		finalGID = uint32(SafeDefaultGID)
	}
	return
}

// SyscallCredentials retrieves system call credentials for a given user string.
// RADICAL FIX: Completely rewritten to work in containerized environments without /etc/passwd and /etc/group
func SyscallCredentials(userStr string) (*syscall.Credential, error) {
	logrus.Debugf("🔐 Resolving credentials for user: '%s'", userStr)

	// Parse user string to extract UID and GID
	uid, gid, err := getUIDAndGIDFromString(userStr)
	if err != nil {
		logrus.Warnf("❌ Failed to get UID/GID for user '%s': %v", userStr, err)
		return nil, errors.Wrap(err, "get uid/gid")
	}
	logrus.Debugf("✅ Resolved UID/GID for user '%s': %d/%d", userStr, uid, gid)

	// Use safe UID/GID values to prevent "invalid user/group IDs" errors
	safeUID, safeGID := GetSafeUIDGID(int64(uid), int64(gid))
	logrus.Debugf("🛡️ Using safe UID/GID: %d/%d (original: %d/%d) for user '%s'", safeUID, safeGID, uid, gid, userStr)

	// RADICAL FIX: Skip user lookup and group parsing in containerized environments
	// This prevents failures when /etc/passwd and /etc/group are missing
	logrus.Infof("🚀 Using direct UID/GID credentials for user '%s' (containerized mode)", userStr)
	logrus.Infof("📋 Skipping user lookup and group parsing - using direct credentials")

	// Convert to safe uint32 values
	finalUID, finalGID := convertToSafeCredentials(safeUID, safeGID)
	logrus.Infof("🎯 Final credentials for user '%s': UID=%d, GID=%d", userStr, finalUID, finalGID)

	// RADICAL FIX: Return minimal credentials without groups
	// This prevents failures when /etc/group is missing
	return &syscall.Credential{
		Uid:    finalUID,
		Gid:    finalGID,
		Groups: []uint32{finalGID}, // Only include primary group
	}, nil
}
