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
	"os"
	"path/filepath"
	"testing"

	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/dockerfile"
	"github.com/Gosayram/kaniko/pkg/util"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
)

func TestCommonCommandHelper_SetupUserGroup(t *testing.T) {
	helper := NewCommonCommandHelper()

	tests := []struct {
		name            string
		chown           string
		replacementEnvs []string
		expectError     bool
	}{
		{
			name:            "Valid user:group",
			chown:           "1000:1000",
			replacementEnvs: []string{},
			expectError:     false,
		},
		{
			name:            "Valid user only",
			chown:           "1000",
			replacementEnvs: []string{},
			expectError:     false,
		},
		{
			name:            "Empty chown",
			chown:           "",
			replacementEnvs: []string{},
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uid, gid, err := helper.SetupUserGroup(tt.chown, tt.replacementEnvs)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if uid < 0 || gid < 0 {
					t.Errorf("Expected valid UID/GID, got uid=%d, gid=%d", uid, gid)
				}
			}
		})
	}
}

func TestCommonCommandHelper_ResolveUserFromConfig(t *testing.T) {
	helper := NewCommonCommandHelper()

	config := &v1.Config{
		User: "1000:1000",
		Env:  []string{},
	}
	buildArgs := &dockerfile.BuildArgs{}

	userStr, err := helper.ResolveUserFromConfig(config, buildArgs)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if userStr != "1000:1000" {
		t.Errorf("Expected '1000:1000', got '%s'", userStr)
	}
}

func TestCommonCommandHelper_ResolveEnvironmentVariable(t *testing.T) {
	helper := NewCommonCommandHelper()

	tests := []struct {
		name            string
		value           string
		replacementEnvs []string
		allowEmpty      bool
		expectError     bool
	}{
		{
			name:            "Simple value",
			value:           "test",
			replacementEnvs: []string{},
			allowEmpty:      false,
			expectError:     false,
		},
		{
			name:            "Empty value with allowEmpty=true",
			value:           "",
			replacementEnvs: []string{},
			allowEmpty:      true,
			expectError:     false,
		},
		{
			name:            "Empty value with allowEmpty=false",
			value:           "",
			replacementEnvs: []string{},
			allowEmpty:      false,
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := helper.ResolveEnvironmentVariable(tt.value, tt.replacementEnvs, tt.allowEmpty)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result != tt.value {
					t.Errorf("Expected '%s', got '%s'", tt.value, result)
				}
			}
		})
	}
}

func TestCommonCommandHelper_CreateDirectoryWithPermissions(t *testing.T) {
	helper := NewCommonCommandHelper()

	// Create temporary directory for testing
	tempDir := t.TempDir()
	testDir := filepath.Join(tempDir, "testdir")

	err := helper.CreateDirectoryWithPermissions(testDir, 0755, 1000, 1000)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Verify directory was created
	if _, err := os.Stat(testDir); os.IsNotExist(err) {
		t.Errorf("Directory was not created")
	}
}

func TestCommonCommandHelper_ValidatePath(t *testing.T) {
	helper := NewCommonCommandHelper()

	tests := []struct {
		name        string
		path        string
		expectError bool
	}{
		{
			name:        "Valid path",
			path:        "/valid/path",
			expectError: false,
		},
		{
			name:        "Path with directory traversal",
			path:        "/path/../etc/passwd",
			expectError: true,
		},
		{
			name:        "Relative path",
			path:        "relative/path",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := helper.ValidatePath(tt.path)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestCommonCommandHelper_ResolveWorkingDirectory(t *testing.T) {
	helper := NewCommonCommandHelper()

	tests := []struct {
		name              string
		workdirPath       string
		currentWorkingDir string
		replacementEnvs   []string
		expectedResult    string
		expectError       bool
	}{
		{
			name:              "Absolute path",
			workdirPath:       "/absolute/path",
			currentWorkingDir: "/current",
			replacementEnvs:   []string{},
			expectedResult:    "/absolute/path",
			expectError:       false,
		},
		{
			name:              "Relative path with current working dir",
			workdirPath:       "relative/path",
			currentWorkingDir: "/current",
			replacementEnvs:   []string{},
			expectedResult:    "/current/relative/path",
			expectError:       false,
		},
		{
			name:              "Relative path without current working dir",
			workdirPath:       "relative/path",
			currentWorkingDir: "",
			replacementEnvs:   []string{},
			expectedResult:    "/relative/path",
			expectError:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := helper.ResolveWorkingDirectory(tt.workdirPath, tt.currentWorkingDir, tt.replacementEnvs)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result != tt.expectedResult {
					t.Errorf("Expected '%s', got '%s'", tt.expectedResult, result)
				}
			}
		})
	}
}

func TestCommonCommandHelper_ValidateCommandArguments(t *testing.T) {
	helper := NewCommonCommandHelper()

	tests := []struct {
		name        string
		args        []string
		expectError bool
	}{
		{
			name:        "Valid arguments",
			args:        []string{"ls", "-la"},
			expectError: false,
		},
		{
			name:        "Arguments with dangerous characters",
			args:        []string{"ls", "&", "rm", "-rf"},
			expectError: true,
		},
		{
			name:        "Arguments with path traversal",
			args:        []string{"ls", "../etc/passwd"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := helper.ValidateCommandArguments(tt.args)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestCommonCommandHelper_SetupFileContext(t *testing.T) {
	helper := NewCommonCommandHelper()

	cmd := &instructions.CopyCommand{
		From: "stage1",
	}
	fileContext := util.FileContext{Root: "/original"}

	result := helper.SetupFileContext(cmd, fileContext)

	expectedRoot := filepath.Join(config.KanikoDir, "stage1")
	if result.Root != expectedRoot {
		t.Errorf("Expected root '%s', got '%s'", expectedRoot, result.Root)
	}
}

func TestBaseCommandExecutor_ExecuteWithErrorHandling(t *testing.T) {
	executor := NewBaseCommandExecutor()

	// Test successful execution
	err := executor.ExecuteWithErrorHandling("test operation", func() error {
		return nil
	})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Test error handling
	err = executor.ExecuteWithErrorHandling("test operation", func() error {
		return os.ErrNotExist
	})
	if err == nil {
		t.Errorf("Expected error but got none")
	}
}
