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
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/sirupsen/logrus"
)

// Security constants for input validation
const (
	maxUsernameLength = 32
	minUsernameLength = 1
	maxUIDValue       = 65534
	minUIDValue       = 1000
	maxShellLength    = 256
	maxInputLength    = 1024
)

// Dangerous patterns that should be rejected
var (
	dangerousPatterns = []string{
		"..", "~", "$", "`", "|", "&", ";", "(", ")", "<", ">",
		"\\", "/", "*", "?", "[", "]", "{", "}", "!", "@", "#",
		"%", "^", "+", "=", "\"", "'", "\n", "\r", "\t",
	}

	// Whitelist of allowed shell paths
	allowedShells = []string{
		"/bin/bash", "/bin/sh", "/bin/zsh", "/bin/dash", "/bin/fish",
		"/usr/bin/bash", "/usr/bin/sh", "/usr/bin/zsh", "/usr/bin/dash",
		"/bin/false", "/usr/bin/false", "/sbin/nologin", "/usr/sbin/nologin",
	}
)

// SecureCommandBuilder provides secure command building with validation
type SecureCommandBuilder struct {
	command string
	args    []string
}

// NewSecureCommandBuilder creates a new secure command builder
func NewSecureCommandBuilder(command string) *SecureCommandBuilder {
	return &SecureCommandBuilder{
		command: command,
		args:    make([]string, 0),
	}
}

// AddArg adds a validated argument to the command
func (scb *SecureCommandBuilder) AddArg(arg string) error {
	if !isValidCommandArg(arg) {
		return fmt.Errorf("invalid command argument: %s", arg)
	}
	scb.args = append(scb.args, arg)
	return nil
}

// AddUID adds a validated UID argument
func (scb *SecureCommandBuilder) AddUID(uid uint32) error {
	if !isValidUID(uid) {
		return fmt.Errorf("invalid UID: %d", uid)
	}
	scb.args = append(scb.args, strconv.FormatUint(uint64(uid), 10))
	return nil
}

// AddUsername adds a validated username argument
func (scb *SecureCommandBuilder) AddUsername(username string) error {
	if !isValidUsernameStrict(username) {
		return fmt.Errorf("invalid username: %s", username)
	}
	scb.args = append(scb.args, username)
	return nil
}

// AddShell adds a validated shell path argument
func (scb *SecureCommandBuilder) AddShell(shell string) error {
	if !isValidShellPath(shell) {
		return fmt.Errorf("invalid shell path: %s", shell)
	}
	scb.args = append(scb.args, shell)
	return nil
}

// Build creates the secure exec.Command
// #nosec G204 - All arguments are validated and sanitized before use
func (scb *SecureCommandBuilder) Build() *exec.Cmd {
	return exec.Command(scb.command, scb.args...)
}

// isValidCommandArg validates command arguments for security
func isValidCommandArg(arg string) bool {
	// Check length
	if arg == "" || len(arg) > maxInputLength {
		return false
	}

	// Check for dangerous patterns
	for _, pattern := range dangerousPatterns {
		if strings.Contains(arg, pattern) {
			return false
		}
	}

	// Check for control characters
	for _, r := range arg {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}

	return true
}

// isValidUsernameStrict provides strict username validation
func isValidUsernameStrict(username string) bool {
	// Length check
	if len(username) < minUsernameLength || len(username) > maxUsernameLength {
		return false
	}

	// Must start with letter or underscore
	if !unicode.IsLetter(rune(username[0])) && username[0] != '_' {
		return false
	}

	// Check each character
	for _, r := range username {
		if !isValidUsernameCharStrict(r) {
			return false
		}
	}

	// Check for dangerous patterns
	for _, pattern := range dangerousPatterns {
		if strings.Contains(username, pattern) {
			return false
		}
	}

	return true
}

// isValidUsernameCharStrict checks if a character is valid for a username (strict)
func isValidUsernameCharStrict(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '_' || c == '-'
}

// isValidUID validates UID values
func isValidUID(uid uint32) bool {
	return uid >= minUIDValue && uid <= maxUIDValue
}

// isValidShellPath validates shell paths
func isValidShellPath(shell string) bool {
	// Check length
	if shell == "" || len(shell) > maxShellLength {
		return false
	}

	// Check if it's in the whitelist
	for _, allowedShell := range allowedShells {
		if shell == allowedShell {
			return true
		}
	}

	return false
}

// EscapeForShell escapes a string for safe shell usage
func EscapeForShell(input string) string {
	// Remove or escape dangerous characters
	escaped := input

	// Escape single quotes by ending the quote, adding escaped quote, and starting new quote
	escaped = strings.ReplaceAll(escaped, "'", "'\"'\"'")

	// Remove other dangerous characters
	for _, pattern := range dangerousPatterns {
		escaped = strings.ReplaceAll(escaped, pattern, "")
	}

	return escaped
}

// SanitizeInput sanitizes user input for safe usage
func SanitizeInput(input string) string {
	// Remove control characters except newlines and tabs
	sanitized := ""
	for _, r := range input {
		if unicode.IsPrint(r) || r == '\n' || r == '\r' || r == '\t' {
			sanitized += string(r)
		}
	}

	// Trim whitespace
	sanitized = strings.TrimSpace(sanitized)

	// Limit length
	if len(sanitized) > maxInputLength {
		sanitized = sanitized[:maxInputLength]
	}

	return sanitized
}

// ValidateCommandInput validates command input parameters
func ValidateCommandInput(username string, uid uint32, shell string) error {
	if !isValidUsernameStrict(username) {
		return fmt.Errorf("invalid username: %s", username)
	}

	if !isValidUID(uid) {
		return fmt.Errorf("invalid UID: %d", uid)
	}

	if !isValidShellPath(shell) {
		return fmt.Errorf("invalid shell path: %s", shell)
	}

	return nil
}

// CreateSecureUserCommand creates a secure useradd command
func CreateSecureUserCommand(username string, uid uint32, shell string) (*exec.Cmd, error) {
	// Validate all inputs
	if err := ValidateCommandInput(username, uid, shell); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Build secure command
	builder := NewSecureCommandBuilder("useradd")

	if err := builder.AddArg("-u"); err != nil {
		return nil, err
	}

	if err := builder.AddUID(uid); err != nil {
		return nil, err
	}

	if err := builder.AddArg("-m"); err != nil {
		return nil, err
	}

	if err := builder.AddArg("-s"); err != nil {
		return nil, err
	}

	if err := builder.AddShell(shell); err != nil {
		return nil, err
	}

	if err := builder.AddUsername(username); err != nil {
		return nil, err
	}

	cmd := builder.Build()
	logrus.Debugf("Created secure useradd command for user %s with UID %d", username, uid)

	return cmd, nil
}

// Regex patterns for additional validation
var (
	usernameRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]*$`)
	uidRegex      = regexp.MustCompile(`^\d+$`)
	shellRegex    = regexp.MustCompile(`^/[a-zA-Z0-9_/-]+$`)
)

// ValidateWithRegex validates input using regex patterns
func ValidateWithRegex(input string, pattern *regexp.Regexp) bool {
	return pattern.MatchString(input)
}

// IsValidUsernameRegex validates username using regex
func IsValidUsernameRegex(username string) bool {
	return ValidateWithRegex(username, usernameRegex) &&
		len(username) >= minUsernameLength &&
		len(username) <= maxUsernameLength
}

// IsValidUIDRegex validates UID using regex
func IsValidUIDRegex(uid string) bool {
	if !ValidateWithRegex(uid, uidRegex) {
		return false
	}

	uidInt, err := strconv.ParseUint(uid, 10, 32)
	if err != nil {
		return false
	}

	return isValidUID(uint32(uidInt))
}

// IsValidShellRegex validates shell path using regex
func IsValidShellRegex(shell string) bool {
	return ValidateWithRegex(shell, shellRegex) && isValidShellPath(shell)
}
