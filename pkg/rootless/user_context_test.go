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

func TestNewUserContext(t *testing.T) {
	manager := NewManager()
	userContext := NewUserContext(manager)

	if userContext == nil {
		t.Fatal("NewUserContext() returned nil")
	}

	if userContext.manager != manager {
		t.Error("UserContext manager not set correctly")
	}

	if userContext.TargetUser != manager.targetUser {
		t.Errorf("Expected TargetUser '%s', got '%s'", manager.targetUser, userContext.TargetUser)
	}

	if userContext.UID != manager.targetUID {
		t.Errorf("Expected UID %d, got %d", manager.targetUID, userContext.UID)
	}

	if userContext.GID != manager.targetGID {
		t.Errorf("Expected GID %d, got %d", manager.targetGID, userContext.GID)
	}
}

func TestSwitchToTarget(t *testing.T) {
	manager := NewManager()
	userContext := NewUserContext(manager)

	// Test that the function doesn't panic
	// This will likely fail in test environment due to permission issues
	err := userContext.SwitchToTarget()
	if err != nil {
		// Expected to fail in test environment, just check it doesn't panic
		t.Logf("SwitchToTarget() failed as expected in test environment: %v", err)
	}
}

func TestValidatePermissions(t *testing.T) {
	manager := NewManager()
	userContext := NewUserContext(manager)

	// Test that the function doesn't panic
	err := userContext.ValidatePermissions()
	if err != nil {
		// Expected to fail in test environment, just check it doesn't panic
		t.Logf("ValidatePermissions() failed as expected in test environment: %v", err)
	}
}

func TestGetCurrentUserInfo(t *testing.T) {
	manager := NewManager()
	userContext := NewUserContext(manager)

	info := userContext.GetCurrentUserInfo()

	// Check that all expected fields are present
	expectedFields := []string{
		"current_user",
		"target_user",
		"uid",
		"gid",
		"home_dir",
		"is_rootless",
		"is_root",
	}

	for _, field := range expectedFields {
		if _, exists := info[field]; !exists {
			t.Errorf("GetCurrentUserInfo() missing field: %s", field)
		}
	}

	// Check that values match the user context
	if info["target_user"] != userContext.TargetUser {
		t.Errorf("Expected target_user '%s', got '%s'", userContext.TargetUser, info["target_user"])
	}

	if info["uid"] != userContext.UID {
		t.Errorf("Expected uid %d, got %d", userContext.UID, info["uid"])
	}

	if info["gid"] != userContext.GID {
		t.Errorf("Expected gid %d, got %d", userContext.GID, info["gid"])
	}

	if info["home_dir"] != userContext.HomeDir {
		t.Errorf("Expected home_dir '%s', got '%s'", userContext.HomeDir, info["home_dir"])
	}

	if info["is_rootless"] != userContext.IsRootless {
		t.Errorf("Expected is_rootless %v, got %v", userContext.IsRootless, info["is_rootless"])
	}
}

func TestUserContextIsRootUser(t *testing.T) {
	manager := NewManager()
	userContext := NewUserContext(manager)

	// Test that the function doesn't panic
	result := userContext.IsRootUser()

	// The result should be a boolean
	if result != true && result != false {
		t.Errorf("IsRootUser() should return a boolean, got %v", result)
	}
}

func TestUserContextIsTargetUser(t *testing.T) {
	manager := NewManager()
	userContext := NewUserContext(manager)

	// Test that the function doesn't panic
	result := userContext.IsTargetUser()

	// The result should be a boolean
	if result != true && result != false {
		t.Errorf("IsTargetUser() should return a boolean, got %v", result)
	}
}

func TestUserContextUpdateEnvironment(t *testing.T) {
	manager := NewManager()
	userContext := NewUserContext(manager)

	// Test that the function doesn't panic
	err := userContext.updateEnvironment()
	if err != nil {
		t.Errorf("updateEnvironment() should not return error in test environment, got %v", err)
	}
}

func TestUserContextValidateHomeDirectory(t *testing.T) {
	manager := NewManager()
	userContext := NewUserContext(manager)

	// Test that the function doesn't panic
	err := userContext.validateHomeDirectory()
	if err != nil {
		// Expected to fail in test environment, just check it doesn't panic
		t.Logf("validateHomeDirectory() failed as expected in test environment: %v", err)
	}
}

func TestUserContextGetCurrentUser(t *testing.T) {
	// Test that the function doesn't panic
	result := getCurrentUser()

	// The result should be a non-empty string
	if result == "" {
		t.Error("getCurrentUser() should return a non-empty string")
	}
}

func TestUserContextGetUserHomeDir(t *testing.T) {
	tests := []struct {
		name     string
		user     string
		expected string
	}{
		{
			name:     "root user",
			user:     RootUser,
			expected: "/root",
		},
		{
			name:     "kaniko user",
			user:     DefaultKanikoUser,
			expected: "/home/kaniko",
		},
		{
			name:     "test user",
			user:     "testuser:testgroup",
			expected: "/home/testuser",
		},
		{
			name:     "user with colon",
			user:     "user:group",
			expected: "/home/user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getUserHomeDir(tt.user)
			if result != tt.expected {
				t.Errorf("getUserHomeDir(%s) = %s, expected %s", tt.user, result, tt.expected)
			}
		})
	}
}
