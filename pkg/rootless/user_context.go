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
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
)

// UserContext manages user context and switching
type UserContext struct {
	CurrentUser string
	TargetUser  string
	UID         int
	GID         int
	HomeDir     string
	IsRootless  bool
	manager     *Manager
}

// NewUserContext creates a new UserContext instance
func NewUserContext(manager *Manager) *UserContext {
	return &UserContext{
		CurrentUser: getCurrentUser(),
		TargetUser:  manager.targetUser,
		UID:         manager.targetUID,
		GID:         manager.targetGID,
		HomeDir:     getUserHomeDir(manager.targetUser),
		IsRootless:  false,
		manager:     manager,
	}
}

// SwitchToTarget switches to the target user
func (uc *UserContext) SwitchToTarget() error {
	logrus.Infof("Switching user context to: %s", uc.TargetUser)

	// Validate permissions before switching
	if err := uc.ValidatePermissions(); err != nil {
		return fmt.Errorf("permission validation failed: %w", err)
	}

	// Switch UID
	if err := syscall.Setuid(uc.UID); err != nil {
		return fmt.Errorf("failed to set UID to %d: %w", uc.UID, err)
	}

	// Switch GID
	if err := syscall.Setgid(uc.GID); err != nil {
		return fmt.Errorf("failed to set GID to %d: %w", uc.GID, err)
	}

	// Update environment variables
	if err := uc.updateEnvironment(); err != nil {
		logrus.Warnf("Failed to update environment: %v", err)
	}

	// Update context
	uc.CurrentUser = uc.TargetUser
	uc.IsRootless = true

	logrus.Infof("Successfully switched to user: %s (UID: %d, GID: %d)",
		uc.TargetUser, uc.UID, uc.GID)

	return nil
}

// ValidatePermissions validates that the current user has necessary permissions
func (uc *UserContext) ValidatePermissions() error {
	logrus.Debugf("Validating permissions for user switch...")

	// Check if we're currently root
	if os.Getuid() != 0 {
		return fmt.Errorf("user switch requires root privileges (current UID: %d)", os.Getuid())
	}

	// Check if target user is valid
	if uc.UID < 0 || uc.GID < 0 {
		return fmt.Errorf("invalid target user UID/GID: %d/%d", uc.UID, uc.GID)
	}

	// Check if target user exists
	if _, err := user.LookupId(strconv.Itoa(uc.UID)); err != nil {
		logrus.Warnf("Target user %d not found in system: %v", uc.UID, err)
		// Don't fail - user might be created dynamically
	}

	// Validate home directory access
	if err := uc.validateHomeDirectory(); err != nil {
		return fmt.Errorf("home directory validation failed: %w", err)
	}

	logrus.Debugf("Permission validation passed")
	return nil
}

// GetCurrentUserInfo returns information about the current user
func (uc *UserContext) GetCurrentUserInfo() map[string]interface{} {
	return map[string]interface{}{
		"current_user": uc.CurrentUser,
		"target_user":  uc.TargetUser,
		"uid":          uc.UID,
		"gid":          uc.GID,
		"home_dir":     uc.HomeDir,
		"is_rootless":  uc.IsRootless,
		"is_root":      os.Getuid() == 0,
	}
}

// IsRootUser checks if the current user is root
func (uc *UserContext) IsRootUser() bool {
	return os.Getuid() == 0
}

// IsTargetUser checks if we're running as the target user
func (uc *UserContext) IsTargetUser() bool {
	return os.Getuid() == uc.UID && os.Getgid() == uc.GID
}

// Helper methods

func (uc *UserContext) updateEnvironment() error {
	// Set HOME environment variable
	if err := os.Setenv("HOME", uc.HomeDir); err != nil {
		return err
	}

	// Set USER environment variable
	userParts := strings.Split(uc.TargetUser, ":")
	if len(userParts) > 0 {
		if err := os.Setenv("USER", userParts[0]); err != nil {
			return err
		}
	}

	// Update PATH to include user-specific directories
	userBinDir := fmt.Sprintf("%s/.local/bin", uc.HomeDir)
	currentPath := os.Getenv("PATH")
	newPath := fmt.Sprintf("%s:%s", userBinDir, currentPath)

	if err := os.Setenv("PATH", newPath); err != nil {
		return err
	}

	logrus.Debugf("Environment updated for user: %s", uc.TargetUser)
	return nil
}

func (uc *UserContext) validateHomeDirectory() error {
	// Check if home directory exists and is accessible
	if _, err := os.Stat(uc.HomeDir); os.IsNotExist(err) {
		logrus.Warnf("Home directory %s does not exist", uc.HomeDir)
		// Don't fail - directory might be created later
		return nil
	}

	// Check if we can access the home directory
	if _, err := os.Open(uc.HomeDir); err != nil {
		return fmt.Errorf("cannot access home directory %s: %w", uc.HomeDir, err)
	}

	return nil
}

// Utility functions

func getCurrentUser() string {
	if os.Getuid() == 0 {
		return RootUser
	}

	if currentUser, err := user.Current(); err == nil {
		return currentUser.Username
	}

	return fmt.Sprintf("user%d", os.Getuid())
}

func getUserHomeDir(targetUser string) string {
	if targetUser == RootUser {
		return "/root"
	}

	// Extract username from user:group format
	userParts := strings.Split(targetUser, ":")
	username := userParts[0]

	return "/home/" + username
}
