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
	"os/user"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/util"
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
	// RootHomeDir is the root home directory
	RootHomeDir = "/root"
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

	// IMPORTANT: In containerized environments, we don't actually switch the process user
	// Instead, we configure the system to use the target user for spawned processes
	// This is handled by SysProcAttr.Credential in command execution

	// 1. Validate user switch capability
	if err := rm.validateUserSwitch(); err != nil {
		return err
	}

	// 2. Setup user groups (for process spawning)
	if err := rm.setupUserGroups(); err != nil {
		return err
	}

	// 3. Update environment variables for the target user
	if err := rm.updateEnvironment(); err != nil {
		return err
	}

	// 4. Mark as rootless mode (process spawning will use target user)
	rm.isRootlessMode = true

	logrus.Infof("Successfully configured for target user: %s (UID: %d)",
		rm.targetUser, rm.targetUID)
	logrus.Infof("Process spawning will use target user credentials")

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

// SetTargetUserFromConfig sets the target user from Kaniko configuration
func (rm *Manager) SetTargetUserFromConfig(defaultUser string) error {
	logrus.Debugf("Setting target user from config: %s", defaultUser)

	if defaultUser != "" {
		rm.targetUser = defaultUser
		logrus.Debugf("Target user set from config: %s", defaultUser)
	} else {
		logrus.Debugf("No default user in config, using default: %s", DefaultKanikoUser)
		rm.targetUser = DefaultKanikoUser
	}

	// Parse the user string to get UID/GID
	if err := rm.parseUserString(rm.targetUser); err != nil {
		return fmt.Errorf("failed to parse user string %s: %w", rm.targetUser, err)
	}

	logrus.Debugf("Target user configured: %s (UID: %d, GID: %d)",
		rm.targetUser, rm.targetUID, rm.targetGID)

	return nil
}

// Helper methods

func (rm *Manager) isRootUser() bool {
	return os.Getuid() == 0
}

func (rm *Manager) determineTargetUser() error {
	logrus.Debugf("Determining target user from Dockerfile and arguments...")

	// 1. Check if target user is already set (from previous calls)
	if rm.targetUser != DefaultKanikoUser {
		logrus.Debugf("Target user already set: %s", rm.targetUser)
		return nil
	}

	// 2. Try to determine from Dockerfile USER instruction
	// This would require access to the Dockerfile parsing context
	// For now, we'll use a placeholder that can be extended

	// 3. Use default user if no other source is available
	// The actual user will be set via SetTargetUserFromConfig() from the executor

	// 4. Parse user string to get UID/GID
	if err := rm.parseUserString(rm.targetUser); err != nil {
		return fmt.Errorf("failed to parse user string %s: %w", rm.targetUser, err)
	}

	logrus.Debugf("Target user determined: %s (UID: %d, GID: %d)",
		rm.targetUser, rm.targetUID, rm.targetGID)

	return nil
}

// parseUserString parses a user string (e.g., "user:group" or "1000:1000") and sets UID/GID
func (rm *Manager) parseUserString(userStr string) error {
	if userStr == "" {
		return fmt.Errorf("user string cannot be empty")
	}

	// Split user:group format
	parts := strings.Split(userStr, ":")
	userPart := parts[0]
	groupPart := userPart // Default group same as user

	if len(parts) > 1 {
		groupPart = parts[1]
	}

	// Try to parse as numeric UID:GID first
	if uid, err := strconv.Atoi(userPart); err == nil {
		rm.targetUID = uid
		if gid, err := strconv.Atoi(groupPart); err == nil {
			rm.targetGID = gid
		} else {
			rm.targetGID = uid // Default GID same as UID
		}
		logrus.Debugf("Parsed numeric user: UID=%d, GID=%d", rm.targetUID, rm.targetGID)
		return nil
	}

	// Try to lookup user by name
	if userInfo, err := user.Lookup(userPart); err == nil {
		rm.targetUID, _ = strconv.Atoi(userInfo.Uid)
		rm.targetGID, _ = strconv.Atoi(userInfo.Gid)
		logrus.Debugf("Parsed named user: %s (UID=%d, GID=%d)", userPart, rm.targetUID, rm.targetGID)
		return nil
	}

	// If user doesn't exist, we'll need to create it
	// For now, use default values
	rm.targetUID = DefaultKanikoUID
	rm.targetGID = DefaultKanikoGID

	logrus.Debugf("User %s not found, will create with default UID/GID: %d/%d",
		userPart, rm.targetUID, rm.targetGID)

	return nil
}

func (rm *Manager) createUserIfNeeded() error {
	logrus.Debugf("Creating user if needed: %s", rm.targetUser)

	// Skip creation for root user
	if rm.targetUID == 0 {
		logrus.Debugf("Skipping user creation for root user")
		return nil
	}

	// IMPORTANT: In containerized environments, we don't create system users
	// The target user will be used for process spawning via SysProcAttr.Credential
	// This avoids issues with missing useradd/groupadd commands and /etc/passwd

	logrus.Infof("Skipping user creation - will use target user %s (UID: %d) for process spawning",
		rm.targetUser, rm.targetUID)
	logrus.Infof("Process spawning will use SysProcAttr.Credential for user %s", rm.targetUser)

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

	// Skip setup for root user
	if rm.targetUID == 0 {
		logrus.Debugf("Skipping user environment setup for root user")
		return nil
	}

	// Use PermissionSetup to setup user environment
	if err := rm.permissionSetup.SetupUserEnvironment(); err != nil {
		return fmt.Errorf("failed to setup user environment: %w", err)
	}

	// Setup additional environment variables
	if err := rm.setupEnvironmentVariables(); err != nil {
		return fmt.Errorf("failed to setup environment variables: %w", err)
	}

	logrus.Debugf("User environment setup completed for: %s", rm.targetUser)
	return nil
}

// setupEnvironmentVariables sets up basic environment variables for the user
func (rm *Manager) setupEnvironmentVariables() error {
	// Set HOME environment variable
	homeDir := rm.getUserHomeDir()
	if err := os.Setenv("HOME", homeDir); err != nil {
		return fmt.Errorf("failed to set HOME environment variable: %w", err)
	}

	// Set USER environment variable
	userParts := strings.Split(rm.targetUser, ":")
	if len(userParts) > 0 {
		if err := os.Setenv("USER", userParts[0]); err != nil {
			return fmt.Errorf("failed to set USER environment variable: %w", err)
		}
	}

	// Set PATH to include user-specific directories
	userBinDir := fmt.Sprintf("%s/.local/bin", homeDir)
	currentPath := os.Getenv("PATH")
	newPath := fmt.Sprintf("%s:%s", userBinDir, currentPath)

	if err := os.Setenv("PATH", newPath); err != nil {
		return fmt.Errorf("failed to set PATH environment variable: %w", err)
	}

	logrus.Debugf("Environment variables set: HOME=%s, USER=%s", homeDir, userParts[0])
	return nil
}

// getUserHomeDir returns the home directory for the target user
func (rm *Manager) getUserHomeDir() string {
	if rm.targetUID == 0 {
		return RootHomeDir
	}

	// Extract username from user:group format
	userParts := strings.Split(rm.targetUser, ":")
	username := userParts[0]

	return fmt.Sprintf("/home/%s", username)
}

func (rm *Manager) validateUserSwitch() error {
	logrus.Debugf("Validating user switch to: %s", rm.targetUser)

	// 1. Check if we're currently root
	if !rm.isRootUser() {
		return fmt.Errorf("user switch requires root privileges (current UID: %d)", os.Getuid())
	}

	// 2. Check if target user is valid
	if rm.targetUID < 0 || rm.targetGID < 0 {
		return fmt.Errorf("invalid target user UID/GID: %d/%d", rm.targetUID, rm.targetGID)
	}

	// 3. Check if target user exists (for non-root users)
	if rm.targetUID != 0 {
		if _, err := user.LookupId(strconv.Itoa(rm.targetUID)); err != nil {
			logrus.Warnf("Target user %d not found in system: %v", rm.targetUID, err)
			logrus.Infof("This is expected in containerized environments - will use UID/GID for process spawning")
			// Don't fail - user will be used for process spawning via SysProcAttr.Credential
		}
	}

	// 4. Check if we can switch to the target user
	if err := rm.validateUserSwitchCapability(); err != nil {
		return fmt.Errorf("user switch capability validation failed: %w", err)
	}

	logrus.Debugf("User switch validation passed for: %s", rm.targetUser)
	return nil
}

// validateUserSwitchCapability validates that we can switch to the target user
func (rm *Manager) validateUserSwitchCapability() error {
	// Check if target UID/GID are in valid ranges
	if rm.targetUID != 0 && (rm.targetUID < 1000 || rm.targetUID > 65534) {
		return fmt.Errorf("target UID %d is not in safe range (1000-65534)", rm.targetUID)
	}

	if rm.targetGID != 0 && (rm.targetGID < 1000 || rm.targetGID > 65534) {
		return fmt.Errorf("target GID %d is not in safe range (1000-65534)", rm.targetGID)
	}

	return nil
}

func (rm *Manager) setupUserGroups() error {
	logrus.Debugf("Setting up user groups for: %s", rm.targetUser)

	// Skip setup for root user
	if rm.targetUID == 0 {
		logrus.Debugf("Skipping user groups setup for root user")
		return nil
	}

	// IMPORTANT: In containerized environments, we don't setup system groups
	// The target user GID will be used for process spawning via SysProcAttr.Credential

	logrus.Infof("Skipping user groups setup - will use target GID %d for process spawning", rm.targetGID)
	logrus.Infof("Process spawning will use SysProcAttr.Credential for user %s", rm.targetUser)

	return nil
}

func (rm *Manager) updateEnvironment() error {
	logrus.Debugf("Updating environment for user: %s", rm.targetUser)

	// Use UserContext to update environment
	if err := rm.userContext.updateEnvironment(); err != nil {
		return fmt.Errorf("failed to update environment: %w", err)
	}

	logrus.Debugf("Environment updated successfully for user: %s", rm.targetUser)
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
	// Get filesystem structure to check for temp directories
	fs := util.GetFilesystemStructure()
	tempDirs := fs.GetTempDirectories()
	tempDirMap := make(map[string]bool)
	for _, tempDir := range tempDirs {
		tempDirMap[tempDir] = true
	}

	for _, path := range rm.criticalPaths {
		// Skip validation for temp directories - they are safe to use even if in system paths
		if tempDirMap[path] {
			continue
		}
		if rm.isSystemPath(path) {
			return fmt.Errorf("critical path %s is a system path", path)
		}
	}

	return nil
}

// ValidateTargetUser validates the target user for rootless mode
func (rm *Manager) ValidateTargetUser(targetUser string) error {
	logrus.Debugf("Validating target user: %s", targetUser)

	// Parse user string to get UID/GID
	if targetUser == "" {
		targetUser = rm.targetUser // Use default
	}

	// Parse the user string
	if err := rm.parseUserString(targetUser); err != nil {
		return fmt.Errorf("failed to parse user string %s: %w", targetUser, err)
	}

	// Validate security constraints
	if err := rm.validateSecurity(); err != nil {
		return fmt.Errorf("security validation failed: %w", err)
	}

	// Update target user if different
	if targetUser != rm.targetUser {
		rm.targetUser = targetUser
		logrus.Debugf("Updated target user to: %s", targetUser)
	}

	logrus.Debugf("Target user validated successfully: %s (UID: %d, GID: %d)",
		rm.targetUser, rm.targetUID, rm.targetGID)

	return nil
}

// ValidateCommandPermissions validates command permissions in rootless mode
func (rm *Manager) ValidateCommandPermissions(cmd string) error {
	logrus.Debugf("Validating command permissions: %s", cmd)

	// Skip validation if not in rootless mode
	if !rm.isRootlessMode {
		logrus.Debugf("Skipping command validation - not in rootless mode")
		return nil
	}

	// Skip validation for root user
	if rm.targetUID == 0 {
		logrus.Debugf("Skipping command validation - running as root")
		return nil
	}

	// Basic command validation
	if err := rm.validateCommandSyntax(cmd); err != nil {
		return fmt.Errorf("command syntax validation failed: %w", err)
	}

	// Check for dangerous commands
	if err := rm.validateCommandSafety(cmd); err != nil {
		return fmt.Errorf("command safety validation failed: %w", err)
	}

	// Check file system access
	if err := rm.validateFileSystemAccess(cmd); err != nil {
		return fmt.Errorf("file system access validation failed: %w", err)
	}

	logrus.Debugf("Command permissions validated successfully: %s", cmd)
	return nil
}

// validateCommandSyntax validates basic command syntax
func (rm *Manager) validateCommandSyntax(cmd string) error {
	// Check for empty command
	if strings.TrimSpace(cmd) == "" {
		return fmt.Errorf("command cannot be empty")
	}

	// Check for dangerous characters
	dangerousChars := []string{"`", "$(", "${", "&&", "||", ";", "|", "&"}
	for _, char := range dangerousChars {
		if strings.Contains(cmd, char) {
			logrus.Warnf("Command contains potentially dangerous character '%s': %s", char, cmd)
			// Don't fail - just warn
		}
	}

	return nil
}

// validateCommandSafety validates command safety
func (rm *Manager) validateCommandSafety(cmd string) error {
	// Check for system-level commands that should be restricted
	restrictedCommands := []string{
		"rm -rf /", "rm -rf /*", "rm -rf /root", "rm -rf /home",
		"chmod 777 /", "chown -R root:root /",
		"mount", "umount", "fdisk", "mkfs",
		"passwd", "userdel", "groupdel",
		"systemctl", "service", "init",
	}

	cmdLower := strings.ToLower(cmd)
	for _, restricted := range restrictedCommands {
		if strings.Contains(cmdLower, restricted) {
			return fmt.Errorf("command contains restricted operation: %s", restricted)
		}
	}

	return nil
}

// validateFileSystemAccess validates file system access
func (rm *Manager) validateFileSystemAccess(cmd string) error {
	// Get filesystem structure (dynamic if analyzed, fallback if not)
	fs := util.GetFilesystemStructure()

	// Get system directories dynamically
	systemDirs := fs.GetSystemDirectories()
	// Also include root home directory
	systemPaths := make([]string, len(systemDirs), len(systemDirs)+1)
	copy(systemPaths, systemDirs)
	systemPaths = append(systemPaths, RootHomeDir)

	for _, sysPath := range systemPaths {
		if strings.Contains(cmd, sysPath) {
			logrus.Warnf("Command accesses system path %s: %s", sysPath, cmd)
			// For critical system paths, return an error
			if sysPath == RootHomeDir || sysPath == "/etc" {
				return fmt.Errorf("command accesses critical system path %s: %s", sysPath, cmd)
			}
		}
	}

	return nil
}

func (rm *Manager) isSystemPath(path string) bool {
	// Get filesystem structure (dynamic if analyzed, fallback if not)
	fs := util.GetFilesystemStructure()

	// Use the dynamic filesystem structure to check if path is a system directory
	return fs.IsSystemDirectory(path)
}

// getDefaultCriticalPaths returns the default critical paths for rootless setup
// Uses dynamic filesystem structure analysis for temp and bin directories when available.
func getDefaultCriticalPaths() []string {
	// Get filesystem structure (dynamic if analyzed, fallback if not)
	fs := util.GetFilesystemStructure()

	// Start with kaniko-specific paths
	paths := []string{
		"/kaniko",                   // working directory
		"/workspace",                // build context
		"/home/kaniko/.local/bin",   // user binaries
		"/home/kaniko/.local/lib",   // user libraries
		"/home/kaniko/.local/share", // user data
	}

	// Add temp directories dynamically
	paths = append(paths, fs.GetTempDirectories()...)

	// Add bin directories dynamically (for user binaries)
	binDirs := fs.GetBinDirectories()
	// Filter to only include /usr/local/bin (user space)
	for _, binDir := range binDirs {
		if binDir == "/usr/local/bin" {
			paths = append(paths, binDir)
			break
		}
	}

	return paths
}
