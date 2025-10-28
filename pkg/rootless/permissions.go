/*
Copyright 2024 Kaniko Contributors

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

package rootless

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// PermissionSetup handles permission setup for rootless mode
type PermissionSetup struct {
	manager *Manager
}

// NewPermissionSetup creates a new PermissionSetup instance
func NewPermissionSetup(manager *Manager) *PermissionSetup {
	return &PermissionSetup{
		manager: manager,
	}
}

// SetupCriticalDirectories creates and sets up critical directories
func (ps *PermissionSetup) SetupCriticalDirectories() error {
	logrus.Infof("Setting up critical directories...")

	for _, path := range ps.manager.criticalPaths {
		if err := ps.setupDirectory(path); err != nil {
			return fmt.Errorf("failed to setup directory %s: %w", path, err)
		}
	}

	logrus.Infof("Critical directories setup completed")
	return nil
}

// CreateUserIfNeeded creates the target user if it doesn't exist
func (ps *PermissionSetup) CreateUserIfNeeded() error {
	logrus.Infof("Creating user if needed: %s", ps.manager.targetUser)

	// IMPORTANT: In containerized environments, we don't create system users
	// The target user will be used for process spawning via SysProcAttr.Credential
	// This avoids issues with missing useradd/groupadd commands and /etc/passwd

	logrus.Infof("Skipping user creation - will use target user %s (UID: %d) for process spawning",
		ps.manager.targetUser, ps.manager.targetUID)
	logrus.Infof("Process spawning will use SysProcAttr.Credential for user %s", ps.manager.targetUser)

	return nil
}

// GrantAccessToPaths grants access to critical paths for the target user
func (ps *PermissionSetup) GrantAccessToPaths() error {
	logrus.Infof("Granting access to critical paths...")

	for _, path := range ps.manager.criticalPaths {
		if err := ps.grantAccessToPath(path); err != nil {
			logrus.Warnf("Failed to grant access to %s: %v", path, err)
			// Continue with other paths
		}
	}

	logrus.Infof("Access granted to critical paths")
	return nil
}

// SetupUserEnvironment sets up the user environment
func (ps *PermissionSetup) SetupUserEnvironment() error {
	logrus.Infof("Setting up user environment...")

	// Create user home directory
	homeDir := ps.getUserHomeDir()
	if err := ps.setupDirectory(homeDir); err != nil {
		return fmt.Errorf("failed to setup home directory %s: %w", homeDir, err)
	}

	// Create user-specific directories
	userDirs := []string{
		filepath.Join(homeDir, ".local"),
		filepath.Join(homeDir, ".local", "bin"),
		filepath.Join(homeDir, ".local", "lib"),
		filepath.Join(homeDir, ".local", "share"),
	}

	for _, dir := range userDirs {
		if err := ps.setupDirectory(dir); err != nil {
			logrus.Warnf("Failed to setup user directory %s: %v", dir, err)
		}
	}

	logrus.Infof("User environment setup completed")
	return nil
}

// Helper methods

func (ps *PermissionSetup) setupDirectory(path string) error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(path, DefaultDirectoryPermissions); err != nil {
		return err
	}

	// Set ownership to target user
	if err := os.Chown(path, ps.manager.targetUID, ps.manager.targetGID); err != nil {
		return err
	}

	// Set permissions
	if err := os.Chmod(path, DefaultDirectoryPermissions); err != nil {
		return err
	}

	logrus.Debugf("Directory setup completed: %s", path)
	return nil
}

func (ps *PermissionSetup) createUser(username string, uid int) error {
	// Parse username and group
	userParts := strings.Split(username, ":")
	userName := userParts[0]
	groupName := userName // Default group name same as username

	if len(userParts) > 1 {
		groupName = userParts[1]
	}

	// Create group first
	if err := ps.createGroup(groupName, ps.manager.targetGID); err != nil {
		logrus.Warnf("Failed to create group %s: %v", groupName, err)
	}

	// Validate username to prevent command injection
	if !isValidUsername(userName) {
		return fmt.Errorf("invalid username: %s", userName)
	}

	// Additional validation for UID/GID to prevent injection
	if uid < 0 || uid > 65534 {
		return fmt.Errorf("invalid UID: %d", uid)
	}
	if ps.manager.targetGID < 0 || ps.manager.targetGID > 65534 {
		return fmt.Errorf("invalid GID: %d", ps.manager.targetGID)
	}

	// Create user with validated arguments
	// #nosec G204 - Arguments are validated above to prevent injection
	cmd := exec.Command("useradd",
		"-u", strconv.Itoa(uid),
		"-g", strconv.Itoa(ps.manager.targetGID),
		"-m",              // Create home directory
		"-s", "/bin/bash", // Default shell
		userName)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create user %s: %w", userName, err)
	}

	logrus.Debugf("User %s created with UID %d", userName, uid)
	return nil
}

func (ps *PermissionSetup) createGroup(groupName string, gid int) error {
	// Validate group name to prevent command injection
	if !isValidGroupName(groupName) {
		return fmt.Errorf("invalid group name: %s", groupName)
	}

	// Additional validation for GID to prevent injection
	if gid < 0 || gid > 65534 {
		return fmt.Errorf("invalid GID: %d", gid)
	}

	// #nosec G204 - Arguments are validated above to prevent injection
	cmd := exec.Command("groupadd",
		"-g", strconv.Itoa(gid),
		groupName)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create group %s: %w", groupName, err)
	}

	logrus.Debugf("Group %s created with GID %d", groupName, gid)
	return nil
}

// isValidUsername validates username to prevent command injection
func isValidUsername(username string) bool {
	// Check for dangerous characters
	if strings.ContainsAny(username, " \t\n\r;&|`$(){}[]<>\"'\\") {
		return false
	}
	// Check length
	if username == "" || len(username) > 32 {
		return false
	}
	return true
}

// isValidGroupName validates group name to prevent command injection
func isValidGroupName(groupName string) bool {
	// Check for dangerous characters
	if strings.ContainsAny(groupName, " \t\n\r;&|`$(){}[]<>\"'\\") {
		return false
	}
	// Check length
	if groupName == "" || len(groupName) > 32 {
		return false
	}
	return true
}

func (ps *PermissionSetup) grantAccessToPath(path string) error {
	// Check if path exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("path %s does not exist", path)
	}

	// Set ownership
	if err := os.Chown(path, ps.manager.targetUID, ps.manager.targetGID); err != nil {
		return err
	}

	// Set permissions (read/write/execute for owner, read/execute for group and others)
	if err := os.Chmod(path, DefaultDirectoryPermissions); err != nil {
		return err
	}

	logrus.Debugf("Access granted to: %s", path)
	return nil
}

func (ps *PermissionSetup) getUserHomeDir() string {
	if ps.manager.targetUser == RootUser {
		return "/root"
	}

	// Extract username from user:group format
	userParts := strings.Split(ps.manager.targetUser, ":")
	username := userParts[0]

	return "/home/" + username
}
