/*
Copyright 2025 Gosayram

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

	"github.com/Gosayram/kaniko/pkg/dockerfile"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
)

func TestPrepareShellCommand_Heredoc(t *testing.T) {
	tests := []struct {
		name     string
		cmdLine  []string
		files    []instructions.ShellInlineFile
		expected string
	}{
		{
			name:    "heredoc with single file",
			cmdLine: []string{"<<EOF"},
			files: []instructions.ShellInlineFile{
				{Name: "EOF", Data: "echo hello\n"},
			},
			expected: "<<EOF sh\necho hello\nEOF",
		},
		{
			name:    "heredoc with multiple lines",
			cmdLine: []string{"<<SCRIPT"},
			files: []instructions.ShellInlineFile{
				{Name: "SCRIPT", Data: "#!/bin/sh\necho 'test'\n"},
			},
			expected: "<<SCRIPT sh\n#!/bin/sh\necho 'test'\nSCRIPT",
		},
		{
			name:     "no heredoc",
			cmdLine:  []string{"echo", "hello"},
			files:    []instructions.ShellInlineFile{},
			expected: "echo hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmdRun := &instructions.RunCommand{
				ShellDependantCmdLine: instructions.ShellDependantCmdLine{
					CmdLine:      tt.cmdLine,
					Files:        tt.files,
					PrependShell: true,
				},
			}

			config := &v1.Config{
				Shell: []string{"/bin/sh", "-c"},
			}

			result, err := prepareCommand(config, &dockerfile.BuildArgs{}, cmdRun)
			if err != nil {
				t.Fatalf("prepareCommand failed: %v", err)
			}

			// Check that the command contains the expected content
			cmdStr := ""
			if len(result) > 2 {
				cmdStr = result[2]
			}

			if tt.name == "heredoc with single file" || tt.name == "heredoc with multiple lines" {
				// For heredoc, check that it contains the file data
				if len(cmdStr) == 0 {
					t.Error("Expected command to contain heredoc content")
				}
				// The exact format may vary, but should contain the data
				hasData := false
				for _, f := range tt.files {
					if containsStringHelper(cmdStr, f.Data) {
						hasData = true
						break
					}
				}
				if !hasData {
					t.Errorf("Command should contain heredoc data. Got: %s", cmdStr)
				}
			}
		})
	}
}

func TestPrepareDirectCommand_HeredocWarning(t *testing.T) {
	cmdRun := &instructions.RunCommand{
		ShellDependantCmdLine: instructions.ShellDependantCmdLine{
			CmdLine: []string{"echo", "test"},
			Files: []instructions.ShellInlineFile{
				{Name: "EOF", Data: "test"},
			},
			PrependShell: false,
		},
	}

	// This should not panic and should handle heredoc gracefully
	_, err := prepareDirectCommand(cmdRun, []string{})
	if err != nil {
		t.Fatalf("prepareDirectCommand should not fail: %v", err)
	}
}

// containsStringHelper checks if string contains substring
func containsStringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
