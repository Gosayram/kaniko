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

package commands

import (
	"testing"
)

func TestValidateFilePath(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid relative path",
			path:        "src/main.go",
			expectError: false,
		},
		{
			name:        "valid nested path",
			path:        "src/pkg/utils.go",
			expectError: false,
		},
		{
			name:        "directory traversal with ..",
			path:        "../etc/passwd",
			expectError: true,
			errorMsg:    "directory traversal detected",
		},
		{
			name:        "absolute path",
			path:        "/etc/passwd",
			expectError: true,
			errorMsg:    "absolute paths not allowed",
		},
		{
			name:        "home directory reference",
			path:        "~/secret.txt",
			expectError: true,
			errorMsg:    "suspicious path pattern detected",
		},
		{
			name:        "environment variable",
			path:        "$HOME/secret.txt",
			expectError: true,
			errorMsg:    "suspicious path pattern detected",
		},
		{
			name:        "double slashes",
			path:        "src//main.go",
			expectError: true,
			errorMsg:    "suspicious path pattern detected",
		},
		{
			name:        "windows path separators",
			path:        "src\\main.go",
			expectError: true,
			errorMsg:    "suspicious path pattern detected",
		},
		{
			name:        "null byte injection",
			path:        "src\x00main.go",
			expectError: true,
			errorMsg:    "null byte injection detected",
		},
		{
			name:        "empty path",
			path:        "",
			expectError: false,
		},
		{
			name:        "current directory",
			path:        ".",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFilePath(tt.path)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error message to contain %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateFilePathEdgeCases(t *testing.T) {
	// Test with very long path
	longPath := make([]byte, 10000)
	for i := range longPath {
		longPath[i] = 'a'
	}

	err := validateFilePath(string(longPath))
	if err != nil {
		t.Errorf("unexpected error for long path: %v", err)
	}

	// Test with unicode characters
	unicodePath := "src/测试文件.go"
	err = validateFilePath(unicodePath)
	if err != nil {
		t.Errorf("unexpected error for unicode path: %v", err)
	}

	// Test with special characters that should be allowed
	specialPath := "src/file-with-dashes_and_underscores.go"
	err = validateFilePath(specialPath)
	if err != nil {
		t.Errorf("unexpected error for special characters: %v", err)
	}
}

func TestValidateFilePathPerformance(t *testing.T) {
	// Test performance with many validations
	paths := []string{
		"src/main.go",
		"src/pkg/utils.go",
		"src/internal/helper.go",
		"src/vendor/dependency.go",
		"src/test/unit_test.go",
	}

	for i := 0; i < 1000; i++ {
		for _, path := range paths {
			err := validateFilePath(path)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		}
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			(len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					containsMiddle(s, substr))))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
