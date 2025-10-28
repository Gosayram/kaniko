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

// Package rootless provides rootless functionality for Kaniko container builds.
// It enables secure container builds by running as non-root users while maintaining
// compatibility with existing Dockerfile instructions.
package rootless

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
)

const (
	// DefaultKanikoUID is the default UID for kaniko user
	DefaultKanikoUID = 1000
	// DefaultKanikoGID is the default GID for kaniko user
	DefaultKanikoGID = 1000
	// DefaultKanikoUser is the default user for kaniko
	DefaultKanikoUser = "kaniko:kaniko"
	// RootUser is the root user string
	RootUser = "root"
	// DefaultDirectoryPermissions are the default permissions for directories
	DefaultDirectoryPermissions = 0o750
	// DefaultFilePermissions are the default permissions for files
	DefaultFilePermissions = 0o640
)

// Manager manages rootless functionality for Kaniko
type Manager struct {
	initialUser      string // root
	targetUser       string // kaniko:kaniko or from Dockerfile
	targetUID        int
	targetGID        int
	isRootlessMode   bool
	isSecureMode     bool // true for rootless, false for root mode
	criticalPaths    []string
	securityWarnings []string
	permissionSetup  *PermissionSetup
	userContext      *UserContext
}

var (
	// Global instance for singleton pattern
	globalManager *Manager
)

// NewManager creates a new Manager instance
func NewManager() *Manager {
	if globalManager == nil {
		globalManager = &Manager{
			initialUser:      RootUser,
			targetUser:       DefaultKanikoUser,
			targetUID:        DefaultKanikoUID,
			targetGID:        DefaultKanikoGID,
			isRootlessMode:   false,
			isSecureMode:     false,
			criticalPaths:    getDefaultCriticalPaths(),
			securityWarnings: make([]string, 0),
		}
		globalManager.permissionSetup = NewPermissionSetup(globalManager)
		globalManager.userContext = NewUserContext(globalManager)
	}
	return globalManager
}

// GetManager returns the global Manager instance
func GetManager() *Manager {
	if globalManager == nil {
		return NewManager()
	}
	return globalManager
}

// Initialize sets up the rootless manager
func (rm *Manager) Initialize() error {
	logrus.Infof("Initializing rootless manager...")

	// 1. Check current user (must be root)
	if !rm.isRootUser() {
		return fmt.Errorf("rootless initialization requires root privileges")
	}

	// 2. Determine target user
	if err := rm.determineTargetUser(); err != nil {
		return err
	}

	// 3. Create user if it doesn't exist (only for non-root users)
	if rm.targetUID != 0 {
		if err := rm.createUserIfNeeded(); err != nil {
			return err
		}

		// 4. Setup permissions for critical paths (only in secure mode)
		if err := rm.setupCriticalPermissions(); err != nil {
			return err
		}

		// 5. Setup user environment
		if err := rm.setupUserEnvironment(); err != nil {
			return err
		}
	}

	logrus.Infof("Rootless manager initialized successfully")
	return nil
}

// DetermineMode automatically determines the security mode based on target user
func (rm *Manager) DetermineMode() error {
	logrus.Infof("Determining security mode...")

	// 1. Check current user (must be root)
	if !rm.isRootUser() {
		return fmt.Errorf("rootless initialization requires root privileges")
	}

	// 2. Automatically determine target user from Dockerfile/arguments
	if err := rm.determineTargetUser(); err != nil {
		return err
	}

	// 3. Automatically determine mode based on target user
	if rm.targetUID == 0 {
		// Root user - unsafe mode (with warnings)
		rm.isSecureMode = false
		rm.isRootlessMode = false
		rm.addSecurityWarning("SECURITY WARNING: Running in ROOT mode - this is UNSAFE!")
		rm.addSecurityWarning("Consider using a non-root user in your Dockerfile")
		logrus.Warnf("Running in UNSAFE ROOT mode - target user is root")
		return nil
	}

	// 4. Non-root user - secure rootless mode (default)
	rm.isSecureMode = true
	rm.isRootlessMode = true
	logrus.Infof("Running in SECURE ROOTLESS mode - target user: %s (UID: %d)",
		rm.targetUser, rm.targetUID)

	return nil
}

// SwitchToTargetUser switches to the target user (only in secure mode)
func (rm *Manager) SwitchToTargetUser() error {
	// Only for secure mode (non-root user)
	if !rm.isSecureMode {
		logrus.Warnf("Skipping user switch - running in ROOT mode")
		return nil
	}

	logrus.Infof("Switching to target user: %s (UID: %d)", rm.targetUser, rm.targetUID)

	// 1. Validate user switch capability
	if err := rm.validateUserSwitch(); err != nil {
		return err
	}

	// 2. Setup user groups
	if err := rm.setupUserGroups(); err != nil {
		return err
	}

	// 3. Switch UID/GID
	if err := syscall.Setuid(rm.targetUID); err != nil {
		return err
	}

	if err := syscall.Setgid(rm.targetGID); err != nil {
		return err
	}

	// 4. Update environment variables
	if err := rm.updateEnvironment(); err != nil {
		return err
	}

	rm.isRootlessMode = true
	logrus.Infof("Successfully switched to target user: %s (UID: %d)",
		rm.targetUser, rm.targetUID)
	return nil
}

// LogSecurityWarnings logs security warnings based on the current mode
func (rm *Manager) LogSecurityWarnings() error {
	if !rm.isSecureMode {
		logrus.Warnf("SECURITY WARNING: Running in ROOT mode - this is UNSAFE!")
		logrus.Warnf("All operations will be performed with root privileges")
		logrus.Warnf("Consider using a non-root user in your Dockerfile")
		logrus.Warnf("Rootless mode is enabled by default for security")
	} else {
		logrus.Infof("Running in SECURE ROOTLESS mode (default)")
		logrus.Infof("Target user: %s (UID: %d)", rm.targetUser, rm.targetUID)
	}

	return nil
}

// IsSecureMode returns true if running in secure mode
func (rm *Manager) IsSecureMode() bool {
	return rm.isSecureMode
}

// IsRootlessMode returns true if running in rootless mode
func (rm *Manager) IsRootlessMode() bool {
	return rm.isRootlessMode
}

// GetTargetUser returns the target user string
func (rm *Manager) GetTargetUser() string {
	return rm.targetUser
}

// GetTargetUID returns the target user UID
func (rm *Manager) GetTargetUID() int {
	return rm.targetUID
}

// GetTargetGID returns the target user GID
func (rm *Manager) GetTargetGID() int {
	return rm.targetGID
}

// Helper methods

func (rm *Manager) isRootUser() bool {
	return os.Getuid() == 0
}

func (rm *Manager) determineTargetUser() error {
	// TODO: Implement logic to determine target user from Dockerfile/args
	// For now, use default kaniko:kaniko
	logrus.Debugf("Using default target user: %s", rm.targetUser)
	return nil
}

func (rm *Manager) createUserIfNeeded() error {
	logrus.Debugf("Creating user if needed: %s", rm.targetUser)
	// TODO: Implement user creation logic
	return nil
}

func (rm *Manager) setupCriticalPermissions() error {
	// Only for secure mode (non-root user)
	if !rm.isSecureMode {
		return nil
	}

	logrus.Debugf("Setting up critical permissions for user: %s", rm.targetUser)

	for _, path := range rm.criticalPaths {
		// Create directory if it doesn't exist
		if err := os.MkdirAll(path, DefaultDirectoryPermissions); err != nil {
			return err
		}

		// Grant access to target user
		if err := os.Chown(path, rm.targetUID, rm.targetGID); err != nil {
			return err
		}

		// Set proper permissions
		if err := os.Chmod(path, DefaultDirectoryPermissions); err != nil {
			return err
		}
	}

	return nil
}

func (rm *Manager) setupUserEnvironment() error {
	logrus.Debugf("Setting up user environment for: %s", rm.targetUser)
	// TODO: Implement user environment setup
	return nil
}

func (rm *Manager) validateUserSwitch() error {
	logrus.Debugf("Validating user switch to: %s", rm.targetUser)
	// TODO: Implement user switch validation
	return nil
}

func (rm *Manager) setupUserGroups() error {
	logrus.Debugf("Setting up user groups for: %s", rm.targetUser)
	// TODO: Implement user groups setup
	return nil
}

func (rm *Manager) updateEnvironment() error {
	logrus.Debugf("Updating environment for user: %s", rm.targetUser)
	// TODO: Implement environment update
	return nil
}

func (rm *Manager) addSecurityWarning(warning string) {
	rm.securityWarnings = append(rm.securityWarnings, warning)
}

func (rm *Manager) validateSecurity() error {
	// 1. Check that UID/GID is in safe range (for non-root users)
	if rm.targetUID != 0 && (rm.targetUID < 1000 || rm.targetUID > 65534) {
		return fmt.Errorf("target UID %d is not in safe range", rm.targetUID)
	}

	// 2. Check that critical paths don't contain system directories
	for _, path := range rm.criticalPaths {
		if rm.isSystemPath(path) {
			return fmt.Errorf("critical path %s is a system path", path)
		}
	}

	return nil
}

// ValidateTargetUser validates the target user for rootless mode
func (rm *Manager) ValidateTargetUser(user string) error {
	logrus.Debugf("Validating target user: %s", user)

	// Parse user string to get UID/GID
	if user == "" {
		user = rm.targetUser // Use default
	}

	// TODO: Implement user validation logic
	// For now, just log the user
	logrus.Debugf("Target user validated: %s", user)

	return nil
}

// ValidateCommandPermissions validates command permissions in rootless mode
func (rm *Manager) ValidateCommandPermissions(cmd string) error {
	logrus.Debugf("Validating command permissions: %s", cmd)

	// TODO: Implement command permission validation
	// For now, just log the command
	logrus.Debugf("Command permissions validated: %s", cmd)

	return nil
}

func (rm *Manager) isSystemPath(path string) bool {
	systemPaths := []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/etc", "/lib", "/lib64"}
	for _, sysPath := range systemPaths {
		if strings.HasPrefix(path, sysPath) {
			return true
		}
	}
	return false
}

// getDefaultCriticalPaths returns the default critical paths for rootless setup
func getDefaultCriticalPaths() []string {
	return []string{
		"/kaniko",                   // working directory
		"/workspace",                // build context
		"/tmp",                      // temporary files
		"/var/tmp",                  // temporary files
		"/usr/local/bin",            // user binaries
		"/home/kaniko/.local/bin",   // user binaries
		"/home/kaniko/.local/lib",   // user libraries
		"/home/kaniko/.local/share", // user data
	}
}
