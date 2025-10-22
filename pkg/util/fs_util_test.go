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
	"path/filepath"
	"strings"
	"testing"
)

func TestPermissionManagerUserDetection(t *testing.T) {
	tests := []struct {
		name           string
		envVars        map[string]string
		expectedUser   string
		expectedHome   string
		expectedBinDir string
	}{
		{
			name: "Default user detection",
			envVars: map[string]string{
				"USER": "testuser",
				"HOME": "/home/testuser",
			},
			expectedUser:   "testuser",
			expectedHome:   "/home/testuser",
			expectedBinDir: "/home/testuser/.local/bin",
		},
		{
			name: "Custom user via KANIKO_USER_NAME",
			envVars: map[string]string{
				"KANIKO_USER_NAME": "customuser",
				"USER":             "testuser",
				"HOME":             "/home/testuser",
			},
			expectedUser:   "customuser",
			expectedHome:   "/home/testuser",
			expectedBinDir: "/home/testuser/.local/bin",
		},
		{
			name: "Fallback to LOGNAME",
			envVars: map[string]string{
				"LOGNAME": "fallbackuser",
				"HOME":    "/home/fallbackuser",
				"USER":    "", // Clear USER to test LOGNAME fallback
			},
			expectedUser:   "fallbackuser",
			expectedHome:   "/home/fallbackuser",
			expectedBinDir: "/home/fallbackuser/.local/bin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up environment
			originalEnv := make(map[string]string)
			for key, value := range tt.envVars {
				originalEnv[key] = os.Getenv(key)
				if value == "" {
					os.Unsetenv(key)
				} else {
					os.Setenv(key, value)
				}
			}

			// Clean up environment after test
			defer func() {
				for key, originalValue := range originalEnv {
					if originalValue == "" {
						os.Unsetenv(key)
					} else {
						os.Setenv(key, originalValue)
					}
				}
			}()

			// Create permission manager
			pm := NewPermissionManager()

			// Verify user detection
			if pm.userName != tt.expectedUser {
				t.Errorf("Expected user name %s, got %s", tt.expectedUser, pm.userName)
			}
			if pm.userHome != tt.expectedHome {
				t.Errorf("Expected home %s, got %s", tt.expectedHome, pm.userHome)
			}
			if pm.userBinDir != tt.expectedBinDir {
				t.Errorf("Expected bin dir %s, got %s", tt.expectedBinDir, pm.userBinDir)
			}
		})
	}
}

func TestFindFileInAlternativeLocations(t *testing.T) {
	// Create temporary directory structure
	tempDir := t.TempDir()

	// Create test files in different locations
	testFiles := map[string]string{
		"testfile1": filepath.Join(tempDir, "some", "nested", "dir", "testfile1"),
		"testfile2": filepath.Join(tempDir, "another", "path", "testfile2"),
		"testfile3": filepath.Join(tempDir, "user_bin", "testfile3"),
	}

	// Create directories and files
	for _, filePath := range testFiles {
		dir := filepath.Dir(filePath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("Failed to create directory %s: %v", dir, err)
		}
		if err := os.WriteFile(filePath, []byte("test content"), 0644); err != nil {
			t.Fatalf("Failed to create file %s: %v", filePath, err)
		}
	}

	// Set up custom user directories
	os.Setenv("KANIKO_USER_BIN_DIR", filepath.Join(tempDir, "user_bin"))
	os.Setenv("KANIKO_USER_LIB_DIR", filepath.Join(tempDir, "user_lib"))
	os.Setenv("KANIKO_USER_SHARE_DIR", filepath.Join(tempDir, "user_share"))

	defer func() {
		os.Unsetenv("KANIKO_USER_BIN_DIR")
		os.Unsetenv("KANIKO_USER_LIB_DIR")
		os.Unsetenv("KANIKO_USER_SHARE_DIR")
	}()

	tests := []struct {
		name        string
		src         string
		root        string
		expectFound bool
	}{
		{
			name:        "Find in user bin directory",
			src:         "testfile3",
			root:        tempDir,
			expectFound: true,
		},
		{
			name:        "Find by walking directory tree",
			src:         "testfile1",
			root:        tempDir,
			expectFound: true,
		},
		{
			name:        "File not found",
			src:         "nonexistent",
			root:        tempDir,
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			foundPath, err := findFileInAlternativeLocations(tt.src, tt.root)

			if tt.expectFound {
				if err != nil {
					t.Errorf("Expected to find file, but got error: %v", err)
					return
				}
				if !strings.Contains(foundPath, tt.src) {
					t.Errorf("Expected path to contain %s, got %s", tt.src, foundPath)
				}
			} else {
				if err == nil {
					t.Errorf("Expected error for nonexistent file, but got path: %s", foundPath)
				}
			}
		})
	}
}

func TestFindFileByWalking(t *testing.T) {
	tempDir := t.TempDir()

	// Create a nested file structure
	testFile := filepath.Join(tempDir, "level1", "level2", "testfile.txt")
	if err := os.MkdirAll(filepath.Dir(testFile), 0755); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	// Test finding file within depth limit
	foundPath, err := findFileByWalking(tempDir, "testfile.txt", 3)
	if err != nil {
		t.Errorf("Expected to find file, got error: %v", err)
	}
	if !strings.Contains(foundPath, "testfile.txt") {
		t.Errorf("Expected path to contain testfile.txt, got %s", foundPath)
	}

	// Test not finding file beyond depth limit
	_, err = findFileByWalking(tempDir, "testfile.txt", 1)
	if err == nil {
		t.Error("Expected error when depth limit exceeded, got nil")
	}
}

func TestIsProtectedDirectory(t *testing.T) {
	tests := []struct {
		path        string
		isProtected bool
	}{
		{"/usr/local/bin/pnpm", true},
		{"/usr/bin/node", true},
		{"/bin/sh", true},
		{"/home/user/bin/pnpm", false},
		{"/custom/path/bin/pnpm", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := isProtectedDirectory(tt.path)
			if result != tt.isProtected {
				t.Errorf("isProtectedDirectory(%s) = %v, want %v", tt.path, result, tt.isProtected)
			}
		})
	}
}

func TestCreateSymlinkWithFallback(t *testing.T) {
	tempDir := t.TempDir()

	// Create a target file
	targetFile := filepath.Join(tempDir, "target.sh")
	if err := os.WriteFile(targetFile, []byte("#!/bin/sh\necho test"), 0755); err != nil {
		t.Fatalf("Failed to create target file: %v", err)
	}

	// Test creating symlink in writable directory
	linkPath := filepath.Join(tempDir, "link.sh")
	if err := CreateSymlinkWithFallback(targetFile, linkPath); err != nil {
		t.Errorf("Failed to create symlink: %v", err)
	}

	// Verify symlink was created
	if _, err := os.Lstat(linkPath); err != nil {
		t.Errorf("Symlink was not created: %v", err)
	}
}
