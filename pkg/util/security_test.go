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

package util

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateFilePath_Security(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		expectError bool
		description string
	}{
		{
			name:        "Valid absolute path",
			path:        "/valid/path",
			expectError: false,
			description: "Should allow valid absolute paths",
		},
		{
			name:        "Valid relative path",
			path:        "valid/path",
			expectError: false,
			description: "Should allow valid relative paths",
		},
		{
			name:        "Directory traversal with ../",
			path:        "../etc/passwd",
			expectError: true,
			description: "Should block directory traversal attempts",
		},
		{
			name:        "Directory traversal with /../",
			path:        "/path/../etc/passwd",
			expectError: true,
			description: "Should block directory traversal in middle of path",
		},
		{
			name:        "Directory traversal with /..",
			path:        "/path/..",
			expectError: true,
			description: "Should block directory traversal at end of path",
		},
		{
			name:        "Just ..",
			path:        "..",
			expectError: true,
			description: "Should block just ..",
		},
		{
			name:        "Multiple traversal attempts",
			path:        "../../etc/passwd",
			expectError: true,
			description: "Should block multiple traversal attempts",
		},
		{
			name:        "Traversal in middle",
			path:        "path/../other/path",
			expectError: true,
			description: "Should block traversal in middle of path",
		},
		{
			name:        "Valid nested path",
			path:        "path/to/file",
			expectError: false,
			description: "Should allow valid nested paths",
		},
		{
			name:        "Empty path",
			path:        "",
			expectError: false,
			description: "Should allow empty path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFilePath(tt.path)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for path '%s' but got none. %s", tt.path, tt.description)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for path '%s': %v. %s", tt.path, err, tt.description)
				}
			}
		})
	}
}

func TestValidateLinkPathName_Security(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		expectError bool
		description string
	}{
		{
			name:        "Valid link name",
			path:        "valid-link",
			expectError: false,
			description: "Should allow valid link names",
		},
		{
			name:        "Directory traversal in link name",
			path:        "../etc/passwd",
			expectError: true,
			description: "Should block directory traversal in link names",
		},
		{
			name:        "Traversal in middle of link name",
			path:        "path/../other",
			expectError: true,
			description: "Should block traversal in middle of link names",
		},
		{
			name:        "Just .. in link name",
			path:        "..",
			expectError: true,
			description: "Should block just .. in link names",
		},
		{
			name:        "Valid nested link name",
			path:        "path/to/link",
			expectError: false,
			description: "Should allow valid nested link names",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLinkPathName(tt.path)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for link name '%s' but got none. %s", tt.path, tt.description)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for link name '%s': %v. %s", tt.path, err, tt.description)
				}
			}
		})
	}
}

func TestValidateFileSize_Security(t *testing.T) {
	// Create temporary file for testing
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		fileSize    int64
		maxSize     int64
		expectError bool
		description string
	}{
		{
			name:        "File within limit",
			fileSize:    1024,
			maxSize:     2048,
			expectError: false,
			description: "Should allow files within size limit",
		},
		{
			name:        "File at limit",
			fileSize:    1024,
			maxSize:     1024,
			expectError: false,
			description: "Should allow files at size limit",
		},
		{
			name:        "File exceeds limit",
			fileSize:    2048,
			maxSize:     1024,
			expectError: true,
			description: "Should block files exceeding size limit",
		},
		{
			name:        "Zero size file",
			fileSize:    0,
			maxSize:     1024,
			expectError: false,
			description: "Should allow zero size files",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test file
			testFile := filepath.Join(tempDir, "test-file")
			file, err := os.Create(testFile)
			if err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			// Write data to file
			data := make([]byte, tt.fileSize)
			_, err = file.Write(data)
			if err != nil {
				t.Fatalf("Failed to write to test file: %v", err)
			}
			file.Close()

			// Test validation
			err = validateFileSize(testFile, tt.maxSize)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for file size %d with max %d but got none. %s", tt.fileSize, tt.maxSize, tt.description)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for file size %d with max %d: %v. %s", tt.fileSize, tt.maxSize, err, tt.description)
				}
			}
		})
	}
}

func TestValidateLinkPath_Security(t *testing.T) {
	tests := []struct {
		name        string
		link        string
		dest        string
		expectError bool
		description string
	}{
		{
			name:        "Valid link within destination",
			link:        "/dest/path/link",
			dest:        "/dest",
			expectError: false,
			description: "Should allow links within destination directory",
		},
		{
			name:        "Link escaping destination",
			link:        "/dest/../etc/passwd",
			dest:        "/dest",
			expectError: true,
			description: "Should block links escaping destination directory",
		},
		{
			name:        "Link to parent directory",
			link:        "/dest/../other",
			dest:        "/dest",
			expectError: true,
			description: "Should block links to parent directory",
		},
		{
			name:        "Valid nested link",
			link:        "/dest/path/to/link",
			dest:        "/dest",
			expectError: false,
			description: "Should allow valid nested links",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLinkPath(tt.link, tt.dest)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for link '%s' to dest '%s' but got none. %s", tt.link, tt.dest, tt.description)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for link '%s' to dest '%s': %v. %s", tt.link, tt.dest, err, tt.description)
				}
			}
		})
	}
}

func TestValidateSymlinkChain_Security(t *testing.T) {
	// Create temporary directory and symlink for testing
	tempDir := t.TempDir()
	symlinkPath := filepath.Join(tempDir, "test-symlink")

	// Create a target file
	targetFile := filepath.Join(tempDir, "target")
	if err := os.WriteFile(targetFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create target file: %v", err)
	}

	// Create symlink
	if err := os.Symlink(targetFile, symlinkPath); err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	tests := []struct {
		name        string
		symlinkPath string
		depth       int
		expectError bool
		description string
	}{
		{
			name:        "Valid symlink at depth 0",
			symlinkPath: symlinkPath,
			depth:       0,
			expectError: false,
			description: "Should allow valid symlinks at depth 0",
		},
		{
			name:        "Symlink chain too deep",
			symlinkPath: symlinkPath,
			depth:       15,
			expectError: true,
			description: "Should block symlink chains that are too deep",
		},
		{
			name:        "Symlink at maximum depth",
			symlinkPath: symlinkPath,
			depth:       10,
			expectError: false,
			description: "Should allow symlinks at maximum allowed depth",
		},
		{
			name:        "Symlink just over maximum depth",
			symlinkPath: symlinkPath,
			depth:       11,
			expectError: true,
			description: "Should block symlinks just over maximum depth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSymlinkChain(tt.symlinkPath, tt.depth)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for symlink '%s' at depth %d but got none. %s", tt.symlinkPath, tt.depth, tt.description)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for symlink '%s' at depth %d: %v. %s", tt.symlinkPath, tt.depth, err, tt.description)
				}
			}
		})
	}
}

func TestValidateSymlinkTarget_Security(t *testing.T) {
	tests := []struct {
		name        string
		target      string
		sourcePath  string
		expectError bool
		description string
	}{
		{
			name:        "Valid relative target",
			target:      "file.txt",
			sourcePath:  "/path/to/symlink",
			expectError: false,
			description: "Should allow valid relative targets",
		},
		{
			name:        "Valid relative target with subdirectory",
			target:      "subdir/file.txt",
			sourcePath:  "/path/to/symlink",
			expectError: false,
			description: "Should allow valid relative targets with subdirectories",
		},
		{
			name:        "Dangerous absolute target",
			target:      "/etc/passwd",
			sourcePath:  "/path/to/symlink",
			expectError: true,
			description: "Should block dangerous absolute targets",
		},
		{
			name:        "Traversal in relative target",
			target:      "../../etc/passwd",
			sourcePath:  "/path/to/symlink",
			expectError: true,
			description: "Should block traversal in relative targets that escape parent directory",
		},
		{
			name:        "Multiple traversal attempts",
			target:      "../../etc/passwd",
			sourcePath:  "/path/to/symlink",
			expectError: true,
			description: "Should block multiple traversal attempts",
		},
		{
			name:        "Valid sibling directory access",
			target:      "../sibling/file.txt",
			sourcePath:  "/path/to/symlink",
			expectError: false,
			description: "Should allow valid sibling directory access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSymlinkTarget(tt.target, tt.sourcePath)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for target '%s' from source '%s' but got none. %s", tt.target, tt.sourcePath, tt.description)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for target '%s' from source '%s': %v. %s", tt.target, tt.sourcePath, err, tt.description)
				}
			}
		})
	}
}

func TestValidateAbsoluteSymlinkTarget_Security(t *testing.T) {
	tests := []struct {
		name        string
		target      string
		expectError bool
		description string
	}{
		{
			name:        "Valid absolute target in safe directory",
			target:      "/tmp/file.txt",
			expectError: false,
			description: "Should allow absolute targets in safe directories",
		},
		{
			name:        "Dangerous system file",
			target:      "/etc/passwd",
			expectError: true,
			description: "Should block dangerous system files",
		},
		{
			name:        "Dangerous system directory",
			target:      "/etc/shadow",
			expectError: true,
			description: "Should block dangerous system directories",
		},
		{
			name:        "Root directory access",
			target:      "/root/file.txt",
			expectError: true,
			description: "Should block root directory access",
		},
		{
			name:        "Home directory access",
			target:      "/home/user/file.txt",
			expectError: true,
			description: "Should block home directory access",
		},
		{
			name:        "Log directory access",
			target:      "/var/log/file.txt",
			expectError: true,
			description: "Should block log directory access",
		},
		{
			name:        "Run directory access",
			target:      "/var/run/file.txt",
			expectError: true,
			description: "Should block run directory access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAbsoluteSymlinkTarget(tt.target)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for target '%s' but got none. %s", tt.target, tt.description)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for target '%s': %v. %s", tt.target, err, tt.description)
				}
			}
		})
	}
}
