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
	"testing"
)

func TestSecureCommandBuilder(t *testing.T) {
	builder := NewSecureCommandBuilder("useradd")

	// Test valid arguments
	if err := builder.AddArg("-u"); err != nil {
		t.Errorf("Failed to add valid argument: %v", err)
	}

	if err := builder.AddUID(1000); err != nil {
		t.Errorf("Failed to add valid UID: %v", err)
	}

	if err := builder.AddUsername("testuser"); err != nil {
		t.Errorf("Failed to add valid username: %v", err)
	}

	// Test invalid arguments
	if err := builder.AddArg("; rm -rf /"); err == nil {
		t.Error("Should reject dangerous argument")
	}

	if err := builder.AddUID(999); err == nil {
		t.Error("Should reject UID below minimum")
	}

	if err := builder.AddUsername("test;user"); err == nil {
		t.Error("Should reject username with semicolon")
	}
}

func TestIsValidUsernameStrict(t *testing.T) {
	tests := []struct {
		username string
		expected bool
	}{
		{"validuser", true},
		{"valid_user", true},
		{"valid-user", true},
		{"ValidUser123", true},
		{"", false},
		{"a", true},
		{"user;rm", false},
		{"user|cat", false},
		{"user&kill", false},
		{"user$(rm)", false},
		{"user`rm`", false},
		{"user\n", false},
		{"user\t", false},
		{"user ", false},
		{"user$", false},
		{"user~", false},
		{"user..", false},
		{"user/", false},
		{"user\\", false},
		{"user*", false},
		{"user?", false},
		{"user[", false},
		{"user]", false},
		{"user{", false},
		{"user}", false},
		{"user(", false},
		{"user)", false},
		{"user<", false},
		{"user>", false},
		{"user!", false},
		{"user@", false},
		{"user#", false},
		{"user%", false},
		{"user^", false},
		{"user+", false},
		{"user=", false},
		{"user\"", false},
		{"user'", false},
		{"1user", false}, // Can't start with number
		{"-user", false}, // Can't start with dash
		{"_user", true},  // Can start with underscore
	}

	for _, test := range tests {
		result := isValidUsernameStrict(test.username)
		if result != test.expected {
			t.Errorf("isValidUsernameStrict(%q) = %v, expected %v", test.username, result, test.expected)
		}
	}
}

func TestIsValidUID(t *testing.T) {
	tests := []struct {
		uid      uint32
		expected bool
	}{
		{1000, true},
		{1001, true},
		{65534, true},
		{999, false},
		{65535, false},
		{0, false},
		{1, false},
		{100, false},
	}

	for _, test := range tests {
		result := isValidUID(test.uid)
		if result != test.expected {
			t.Errorf("isValidUID(%d) = %v, expected %v", test.uid, result, test.expected)
		}
	}
}

func TestIsValidShellPath(t *testing.T) {
	tests := []struct {
		shell    string
		expected bool
	}{
		{"/bin/bash", true},
		{"/bin/sh", true},
		{"/bin/zsh", true},
		{"/bin/false", true},
		{"/usr/bin/bash", true},
		{"/sbin/nologin", true},
		{"/bin/rm", false},
		{"/usr/bin/rm", false},
		{"/bin/bash;rm", false},
		{"bash", false},
		{"", false},
		{"/bin/bash\n", false},
		{"/bin/bash\t", false},
	}

	for _, test := range tests {
		result := isValidShellPath(test.shell)
		if result != test.expected {
			t.Errorf("isValidShellPath(%q) = %v, expected %v", test.shell, result, test.expected)
		}
	}
}

func TestEscapeForShell(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"user'name", "user'\"'\"'name"},
		{"user;rm", "userrm"},
		{"user|cat", "usercat"},
		{"user&kill", "userkill"},
		{"user$(rm)", "userrm"},
		{"user`rm`", "userrm"},
		{"user\n", "user"},
		{"user\t", "user"},
		{"user ", "user"},
		{"user$", "user"},
		{"user~", "user"},
		{"user..", "user"},
		{"user/", "user"},
		{"user\\", "user"},
		{"user*", "user"},
		{"user?", "user"},
		{"user[", "user"},
		{"user]", "user"},
		{"user{", "user"},
		{"user}", "user"},
		{"user(", "user"},
		{"user)", "user"},
		{"user<", "user"},
		{"user>", "user"},
		{"user!", "user"},
		{"user@", "user"},
		{"user#", "user"},
		{"user%", "user"},
		{"user^", "user"},
		{"user+", "user"},
		{"user=", "user"},
		{"user\"", "user"},
	}

	for _, test := range tests {
		result := EscapeForShell(test.input)
		if result != test.expected {
			t.Errorf("EscapeForShell(%q) = %q, expected %q", test.input, result, test.expected)
		}
	}
}

func TestSanitizeInput(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"user\nname", "user\nname"},
		{"user\tname", "user\tname"},
		{"user\rname", "user\rname"},
		{"user\x00name", "username"}, // Control character
		{"user\x01name", "username"}, // Control character
		{"  user  ", "user"},
		{"", ""},
		{string(make([]byte, 2000)), string(make([]byte, 1024))}, // Truncate long input
	}

	for _, test := range tests {
		result := SanitizeInput(test.input)
		if result != test.expected {
			t.Errorf("SanitizeInput(%q) = %q, expected %q", test.input, result, test.expected)
		}
	}
}

func TestValidateCommandInput(t *testing.T) {
	tests := []struct {
		username string
		uid      uint32
		shell    string
		expected bool
	}{
		{"validuser", 1000, "/bin/bash", true},
		{"valid_user", 1001, "/bin/sh", true},
		{"valid-user", 2000, "/bin/zsh", true},
		{"", 1000, "/bin/bash", false},
		{"validuser", 999, "/bin/bash", false},
		{"validuser", 1000, "/bin/rm", false},
		{"user;rm", 1000, "/bin/bash", false},
		{"validuser", 1000, "/bin/bash;rm", false},
	}

	for _, test := range tests {
		err := ValidateCommandInput(test.username, test.uid, test.shell)
		result := err == nil
		if result != test.expected {
			t.Errorf("ValidateCommandInput(%q, %d, %q) = %v, expected %v",
				test.username, test.uid, test.shell, result, test.expected)
		}
	}
}

func TestCreateSecureUserCommand(t *testing.T) {
	// Test valid command creation
	cmd, err := CreateSecureUserCommand("testuser", 1000, "/bin/bash")
	if err != nil {
		t.Errorf("Failed to create secure command: %v", err)
	}

	if cmd.Path != "useradd" {
		t.Errorf("Expected command path 'useradd', got %s", cmd.Path)
	}

	expectedArgs := []string{"-u", "1000", "-m", "-s", "/bin/bash", "testuser"}
	if len(cmd.Args) != len(expectedArgs)+1 { // +1 for command name
		t.Errorf("Expected %d args, got %d", len(expectedArgs)+1, len(cmd.Args))
	}

	// Test invalid command creation
	_, err = CreateSecureUserCommand("user;rm", 1000, "/bin/bash")
	if err == nil {
		t.Error("Should reject dangerous username")
	}

	_, err = CreateSecureUserCommand("testuser", 999, "/bin/bash")
	if err == nil {
		t.Error("Should reject invalid UID")
	}

	_, err = CreateSecureUserCommand("testuser", 1000, "/bin/rm")
	if err == nil {
		t.Error("Should reject dangerous shell")
	}
}

func TestIsValidUsernameRegex(t *testing.T) {
	tests := []struct {
		username string
		expected bool
	}{
		{"validuser", true},
		{"valid_user", true},
		{"valid-user", true},
		{"ValidUser123", true},
		{"", false},
		{"user;rm", false},
		{"user|cat", false},
		{"user&kill", false},
		{"user$(rm)", false},
		{"user`rm`", false},
		{"user\n", false},
		{"user\t", false},
		{"user ", false},
		{"user$", false},
		{"user~", false},
		{"user..", false},
		{"user/", false},
		{"user\\", false},
		{"user*", false},
		{"user?", false},
		{"user[", false},
		{"user]", false},
		{"user{", false},
		{"user}", false},
		{"user(", false},
		{"user)", false},
		{"user<", false},
		{"user>", false},
		{"user!", false},
		{"user@", false},
		{"user#", false},
		{"user%", false},
		{"user^", false},
		{"user+", false},
		{"user=", false},
		{"user\"", false},
		{"user'", false},
		{"1user", false},
		{"-user", false},
		{"_user", true},
	}

	for _, test := range tests {
		result := IsValidUsernameRegex(test.username)
		if result != test.expected {
			t.Errorf("IsValidUsernameRegex(%q) = %v, expected %v", test.username, result, test.expected)
		}
	}
}

func TestIsValidUIDRegex(t *testing.T) {
	tests := []struct {
		uid      string
		expected bool
	}{
		{"1000", true},
		{"1001", true},
		{"65534", true},
		{"999", false},
		{"65535", false},
		{"0", false},
		{"1", false},
		{"100", false},
		{"abc", false},
		{"1000a", false},
		{"a1000", false},
		{"", false},
		{"-1000", false},
		{"1000.0", false},
	}

	for _, test := range tests {
		result := IsValidUIDRegex(test.uid)
		if result != test.expected {
			t.Errorf("IsValidUIDRegex(%q) = %v, expected %v", test.uid, result, test.expected)
		}
	}
}

func TestIsValidShellRegex(t *testing.T) {
	tests := []struct {
		shell    string
		expected bool
	}{
		{"/bin/bash", true},
		{"/bin/sh", true},
		{"/bin/zsh", true},
		{"/bin/false", true},
		{"/usr/bin/bash", true},
		{"/sbin/nologin", true},
		{"/bin/rm", false},
		{"/usr/bin/rm", false},
		{"/bin/bash;rm", false},
		{"bash", false},
		{"", false},
		{"/bin/bash\n", false},
		{"/bin/bash\t", false},
		{"/bin/bash ", false},
		{"/bin/bash$", false},
		{"/bin/bash~", false},
		{"/bin/bash..", false},
		{"/bin/bash/", false},
		{"/bin/bash\\", false},
		{"/bin/bash*", false},
		{"/bin/bash?", false},
		{"/bin/bash[", false},
		{"/bin/bash]", false},
		{"/bin/bash{", false},
		{"/bin/bash}", false},
		{"/bin/bash(", false},
		{"/bin/bash)", false},
		{"/bin/bash<", false},
		{"/bin/bash>", false},
		{"/bin/bash!", false},
		{"/bin/bash@", false},
		{"/bin/bash#", false},
		{"/bin/bash%", false},
		{"/bin/bash^", false},
		{"/bin/bash+", false},
		{"/bin/bash=", false},
		{"/bin/bash\"", false},
		{"/bin/bash'", false},
	}

	for _, test := range tests {
		result := IsValidShellRegex(test.shell)
		if result != test.expected {
			t.Errorf("IsValidShellRegex(%q) = %v, expected %v", test.shell, result, test.expected)
		}
	}
}
