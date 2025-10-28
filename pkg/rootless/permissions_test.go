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
	"os"
	"path/filepath"
	"testing"
)

func TestNewPermissionSetup(t *testing.T) {
	manager := NewManager()
	permissionSetup := NewPermissionSetup(manager)

	if permissionSetup == nil {
		t.Fatal("NewPermissionSetup() returned nil")
	}

	if permissionSetup.manager != manager {
		t.Error("PermissionSetup manager not set correctly")
	}
}

func TestSetupCriticalDirectories(t *testing.T) {
	manager := NewManager()
	permissionSetup := NewPermissionSetup(manager)

	// Test that the function doesn't panic
	err := permissionSetup.SetupCriticalDirectories()
	if err != nil {
		t.Errorf("SetupCriticalDirectories() should not return error in test environment, got %v", err)
	}
}

func TestPermissionSetupCreateUserIfNeeded(t *testing.T) {
	manager := NewManager()
	permissionSetup := NewPermissionSetup(manager)

	// Test that the function doesn't panic
	err := permissionSetup.CreateUserIfNeeded()
	if err != nil {
		t.Errorf("CreateUserIfNeeded() should not return error in test environment, got %v", err)
	}
}

func TestPermissionSetupSetupUserEnvironment(t *testing.T) {
	manager := NewManager()
	permissionSetup := NewPermissionSetup(manager)

	// Test that the function doesn't panic
	err := permissionSetup.SetupUserEnvironment()
	if err != nil {
		t.Errorf("SetupUserEnvironment() should not return error in test environment, got %v", err)
	}
}

func TestSetupDirectory(t *testing.T) {
	manager := NewManager()
	permissionSetup := NewPermissionSetup(manager)

	// Create a temporary directory for testing
	tempDir := filepath.Join(os.TempDir(), "kaniko-test-dir")
	defer os.RemoveAll(tempDir)

	// Test setting up a directory
	err := permissionSetup.setupDirectory(tempDir)
	if err != nil {
		t.Errorf("setupDirectory() should not return error, got %v", err)
	}

	// Check if directory was created
	if _, err := os.Stat(tempDir); os.IsNotExist(err) {
		t.Error("Directory was not created")
	}
}

func TestCreateUser(t *testing.T) {
	manager := NewManager()
	permissionSetup := NewPermissionSetup(manager)

	// Test creating a user (this will likely fail in test environment, but shouldn't panic)
	err := permissionSetup.createUser("testuser", 1001)
	if err != nil {
		// Expected to fail in test environment, just check it doesn't panic
		t.Logf("createUser() failed as expected in test environment: %v", err)
	}
}

func TestCreateGroup(t *testing.T) {
	manager := NewManager()
	permissionSetup := NewPermissionSetup(manager)

	// Test creating a group (this will likely fail in test environment, but shouldn't panic)
	err := permissionSetup.createGroup("testgroup", 1001)
	if err != nil {
		// Expected to fail in test environment, just check it doesn't panic
		t.Logf("createGroup() failed as expected in test environment: %v", err)
	}
}

func TestGrantAccessToPath(t *testing.T) {
	manager := NewManager()
	permissionSetup := NewPermissionSetup(manager)

	// Create a temporary file for testing
	tempFile := filepath.Join(os.TempDir(), "kaniko-test-file")
	file, err := os.Create(tempFile)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	file.Close()
	defer os.Remove(tempFile)

	// Test granting access to the file
	err = permissionSetup.grantAccessToPath(tempFile)
	if err != nil {
		t.Errorf("grantAccessToPath() should not return error, got %v", err)
	}
}

func TestGrantAccessToPathNonExistent(t *testing.T) {
	manager := NewManager()
	permissionSetup := NewPermissionSetup(manager)

	// Test granting access to non-existent path
	nonExistentPath := "/non/existent/path"
	err := permissionSetup.grantAccessToPath(nonExistentPath)
	if err == nil {
		t.Error("grantAccessToPath() should return error for non-existent path")
	}
}

func TestPermissionSetupGetUserHomeDir(t *testing.T) {
	manager := NewManager()
	permissionSetup := NewPermissionSetup(manager)

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
			manager.targetUser = tt.user
			result := permissionSetup.getUserHomeDir()
			if result != tt.expected {
				t.Errorf("getUserHomeDir() for user '%s' = %s, expected %s", tt.user, result, tt.expected)
			}
		})
	}
}
