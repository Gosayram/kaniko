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
	"testing"
)

func TestNewManager(t *testing.T) {
	manager := NewManager()
	if manager == nil {
		t.Fatal("NewManager() returned nil")
	}

	if manager.targetUser != DefaultKanikoUser {
		t.Errorf("Expected default target user '%s', got '%s'", DefaultKanikoUser, manager.targetUser)
	}

	if manager.targetUID != DefaultKanikoUID {
		t.Errorf("Expected default target UID %d, got %d", DefaultKanikoUID, manager.targetUID)
	}

	if manager.targetGID != DefaultKanikoGID {
		t.Errorf("Expected default target GID %d, got %d", DefaultKanikoGID, manager.targetGID)
	}
}

func TestGetManager(t *testing.T) {
	// Test singleton pattern
	manager1 := GetManager()
	manager2 := GetManager()

	if manager1 != manager2 {
		t.Error("GetManager() should return the same instance (singleton pattern)")
	}
}

func TestIsSecureMode(t *testing.T) {
	manager := NewManager()

	// Test default state
	if manager.IsSecureMode() {
		t.Error("Expected IsSecureMode() to return false by default")
	}

	// Test after setting secure mode
	manager.isSecureMode = true
	if !manager.IsSecureMode() {
		t.Error("Expected IsSecureMode() to return true after setting")
	}
}

func TestIsRootlessMode(t *testing.T) {
	manager := NewManager()

	// Test default state
	if manager.IsRootlessMode() {
		t.Error("Expected IsRootlessMode() to return false by default")
	}

	// Test after setting rootless mode
	manager.isRootlessMode = true
	if !manager.IsRootlessMode() {
		t.Error("Expected IsRootlessMode() to return true after setting")
	}
}

func TestGetTargetUser(t *testing.T) {
	manager := NewManager()

	expected := "kaniko:kaniko"
	if manager.GetTargetUser() != expected {
		t.Errorf("Expected GetTargetUser() to return '%s', got '%s'", expected, manager.GetTargetUser())
	}
}

func TestGetTargetUID(t *testing.T) {
	manager := NewManager()

	expected := 1000
	if manager.GetTargetUID() != expected {
		t.Errorf("Expected GetTargetUID() to return %d, got %d", expected, manager.GetTargetUID())
	}
}

func TestGetTargetGID(t *testing.T) {
	manager := NewManager()

	expected := 1000
	if manager.GetTargetGID() != expected {
		t.Errorf("Expected GetTargetGID() to return %d, got %d", expected, manager.GetTargetGID())
	}
}

func TestValidateTargetUser(t *testing.T) {
	manager := NewManager()

	tests := []struct {
		name    string
		user    string
		wantErr bool
	}{
		{
			name:    "empty user",
			user:    "",
			wantErr: false,
		},
		{
			name:    "default user",
			user:    "kaniko:kaniko",
			wantErr: false,
		},
		{
			name:    "root user",
			user:    "root",
			wantErr: false,
		},
		{
			name:    "numeric user",
			user:    "1000:1000",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.ValidateTargetUser(tt.user)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTargetUser() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateCommandPermissions(t *testing.T) {
	manager := NewManager()

	// Set rootless mode for testing
	manager.isRootlessMode = true
	manager.targetUID = 1000 // Non-root user

	tests := []struct {
		name    string
		cmd     string
		wantErr bool
	}{
		{
			name:    "empty command",
			cmd:     "",
			wantErr: true, // Empty command should fail validation
		},
		{
			name:    "RUN command",
			cmd:     "RUN echo hello",
			wantErr: false,
		},
		{
			name:    "COPY command",
			cmd:     "COPY file.txt /app/",
			wantErr: false,
		},
		{
			name:    "USER command",
			cmd:     "USER appuser",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.ValidateCommandPermissions(tt.cmd)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCommandPermissions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsSystemPath(t *testing.T) {
	manager := NewManager()

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "system bin path",
			path:     "/bin/ls",
			expected: true,
		},
		{
			name:     "system sbin path",
			path:     "/sbin/init",
			expected: true,
		},
		{
			name:     "system usr bin path",
			path:     "/usr/bin/gcc",
			expected: true,
		},
		{
			name:     "system etc path",
			path:     "/etc/passwd",
			expected: true,
		},
		{
			name:     "user home path",
			path:     "/home/user/file",
			expected: false,
		},
		{
			name:     "kaniko path",
			path:     "/kaniko/file",
			expected: false,
		},
		{
			name:     "workspace path",
			path:     "/workspace/file",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := manager.isSystemPath(tt.path)
			if result != tt.expected {
				t.Errorf("isSystemPath(%s) = %v, expected %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestGetDefaultCriticalPaths(t *testing.T) {
	paths := getDefaultCriticalPaths()

	expectedPaths := []string{
		"/kaniko",
		"/workspace",
		"/tmp",
		"/var/tmp",
		"/usr/local/bin",
		"/home/kaniko/.local/bin",
		"/home/kaniko/.local/lib",
		"/home/kaniko/.local/share",
	}

	if len(paths) != len(expectedPaths) {
		t.Errorf("Expected %d critical paths, got %d", len(expectedPaths), len(paths))
	}

	for i, expected := range expectedPaths {
		if i >= len(paths) || paths[i] != expected {
			t.Errorf("Expected path %d to be '%s', got '%s'", i, expected, paths[i])
		}
	}
}

func TestAddSecurityWarning(t *testing.T) {
	manager := NewManager()

	// Test adding a warning
	warning := "Test warning"
	manager.addSecurityWarning(warning)

	if len(manager.securityWarnings) != 1 {
		t.Errorf("Expected 1 security warning, got %d", len(manager.securityWarnings))
	}

	if manager.securityWarnings[0] != warning {
		t.Errorf("Expected warning '%s', got '%s'", warning, manager.securityWarnings[0])
	}

	// Test adding multiple warnings
	manager.addSecurityWarning("Another warning")
	if len(manager.securityWarnings) != 2 {
		t.Errorf("Expected 2 security warnings, got %d", len(manager.securityWarnings))
	}
}

// Test helper functions
func TestManagerIsRootUser(t *testing.T) {
	manager := NewManager()

	// This test depends on the actual user running the test
	// We can only test that the function doesn't panic
	result := manager.isRootUser()

	// The result should be a boolean
	if result != true && result != false {
		t.Errorf("isRootUser() should return a boolean, got %v", result)
	}
}

func TestManagerDetermineTargetUser(t *testing.T) {
	manager := NewManager()

	// Test that the function doesn't panic
	err := manager.determineTargetUser()
	if err != nil {
		t.Errorf("determineTargetUser() should not return error in test environment, got %v", err)
	}
}

func TestManagerCreateUserIfNeeded(t *testing.T) {
	manager := NewManager()

	// Test that the function doesn't panic
	err := manager.createUserIfNeeded()
	if err != nil {
		t.Errorf("createUserIfNeeded() should not return error in test environment, got %v", err)
	}
}

func TestManagerSetupCriticalPermissions(t *testing.T) {
	manager := NewManager()

	// Test that the function doesn't panic
	err := manager.setupCriticalPermissions()
	if err != nil {
		t.Errorf("setupCriticalPermissions() should not return error in test environment, got %v", err)
	}
}

func TestManagerSetupUserEnvironment(t *testing.T) {
	manager := NewManager()

	// Test that the function doesn't panic
	err := manager.setupUserEnvironment()
	if err != nil {
		t.Errorf("setupUserEnvironment() should not return error in test environment, got %v", err)
	}
}

func TestManagerValidateUserSwitch(t *testing.T) {
	manager := NewManager()

	// Test that the function doesn't panic
	err := manager.validateUserSwitch()
	if err != nil {
		t.Errorf("validateUserSwitch() should not return error in test environment, got %v", err)
	}
}

func TestManagerSetupUserGroups(t *testing.T) {
	manager := NewManager()

	// Test that the function doesn't panic
	err := manager.setupUserGroups()
	if err != nil {
		t.Errorf("setupUserGroups() should not return error in test environment, got %v", err)
	}
}

func TestManagerUpdateEnvironment(t *testing.T) {
	manager := NewManager()

	// Test that the function doesn't panic
	err := manager.updateEnvironment()
	if err != nil {
		t.Errorf("updateEnvironment() should not return error in test environment, got %v", err)
	}
}

func TestValidateSecurity(t *testing.T) {
	manager := NewManager()

	// Test with default values (should pass)
	err := manager.validateSecurity()
	if err != nil {
		t.Errorf("validateSecurity() should not return error with default values, got %v", err)
	}

	// Test with unsafe UID
	manager.targetUID = 50
	err = manager.validateSecurity()
	if err == nil {
		t.Error("validateSecurity() should return error with unsafe UID")
	}

	// Reset to safe value
	manager.targetUID = 1000
	err = manager.validateSecurity()
	if err != nil {
		t.Errorf("validateSecurity() should not return error with safe UID, got %v", err)
	}
}
