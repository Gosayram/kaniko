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
	"fmt"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// parseUserGroups parses group IDs for a user
func parseUserGroups(u *user.User) ([]uint32, error) {
	groups := []uint32{}
	gidStr, err := groupIDs(u)
	if err != nil {
		return nil, errors.Wrap(err, "group ids for user")
	}

	for _, g := range gidStr {
		i, err := strconv.ParseUint(g, 10, 32)
		if err != nil {
			return nil, errors.Wrap(err, "parseuint")
		}
		groups = append(groups, uint32(i))
	}
	return groups, nil
}

// adjustGIDForUserString adjusts GID based on user string format
func adjustGIDForUserString(userStr string, u *user.User, safeGID int64) int64 {
	if len(strings.Split(userStr, ":")) <= 1 {
		if u.Gid != "" {
			if gid, err := getGID(u.Gid); err == nil {
				return int64(gid)
			}
		}
	}
	return safeGID
}

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
// It parses the user string to extract UID and GID, looks up user information,
// and returns a syscall.Credential structure with the appropriate credentials.
// CRITICAL FIX: Added detailed logging for user resolution debugging
func SyscallCredentials(userStr string) (*syscall.Credential, error) {
	logrus.Debugf("🔐 Resolving credentials for user: '%s'", userStr)

	uid, gid, err := getUIDAndGIDFromString(userStr)
	if err != nil {
		logrus.Warnf("❌ Failed to get UID/GID for user '%s': %v", userStr, err)
		return nil, errors.Wrap(err, "get uid/gid")
	}
	logrus.Debugf("✅ Resolved UID/GID for user '%s': %d/%d", userStr, uid, gid)

	// Use safe UID/GID values to prevent "invalid user/group IDs" errors
	safeUID, safeGID := GetSafeUIDGID(int64(uid), int64(gid))
	logrus.Debugf("🛡️ Using safe UID/GID: %d/%d (original: %d/%d) for user '%s'", safeUID, safeGID, uid, gid, userStr)

	u, err := LookupUser(fmt.Sprint(safeUID))
	if err != nil {
		logrus.Warnf("❌ Failed to lookup user '%s' (UID %d): %v", userStr, safeUID, err)
		return nil, errors.Wrap(err, "lookup")
	}
	logrus.Infof("✅ Successfully looked up user '%s': UID=%s, GID=%s, Home=%s, Name=%s",
		userStr, u.Uid, u.Gid, u.HomeDir, u.Name)

	groups, err := parseUserGroups(u)
	if err != nil {
		logrus.Warnf("❌ Failed to parse user groups for '%s': %v", userStr, err)
		return nil, err
	}
	logrus.Debugf("👥 User '%s' belongs to %d groups: %v", userStr, len(groups), groups)

	// Adjust GID based on user string format
	safeGID = adjustGIDForUserString(userStr, u, safeGID)
	logrus.Debugf("🔧 Adjusted GID for user '%s': %d", userStr, safeGID)

	// Convert to safe uint32 values
	finalUID, finalGID := convertToSafeCredentials(safeUID, safeGID)
	logrus.Infof("🎯 Final credentials for user '%s': UID=%d, GID=%d", userStr, finalUID, finalGID)

	return &syscall.Credential{
		Uid:    finalUID,
		Gid:    finalGID,
		Groups: groups,
	}, nil
}
