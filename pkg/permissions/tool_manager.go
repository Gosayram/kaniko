// Package permissions provides tools for managing user permissions and tool access
package permissions

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

// ToolManager manages tool permissions for users
type ToolManager struct {
	userHome string
	userBin  string
}

const (
	// UserBinPermissions defines the permissions for user bin directory
	UserBinPermissions = 0o750
)

// NewToolManager creates a new tool manager for the given user
func NewToolManager(userHome string) *ToolManager {
	return &ToolManager{
		userHome: userHome,
		userBin:  filepath.Join(userHome, ".local", "bin"),
	}
}

// AnalyzeCommandForTools analyzes a command to determine which tools it might need
func (tm *ToolManager) AnalyzeCommandForTools(command string) []string {
	var tools []string

	// Extract executable names from command
	executables := tm.extractExecutablesFromCommand(command)
	tools = append(tools, executables...)

	// Remove duplicates
	return tm.deduplicate(tools)
}

// SetupToolEnvironment sets up the environment for tool execution
func (tm *ToolManager) SetupToolEnvironment(tools []string) error {
	// Ensure user bin directory exists
	if err := tm.ensureUserBinDirectory(); err != nil {
		return fmt.Errorf("failed to create user bin directory: %w", err)
	}

	// Create symlinks for required tools
	tm.createToolSymlinks(tools)

	// Set up environment variables
	tm.setupEnvironmentVariables()

	return nil
}

// ensureUserBinDirectory creates the user bin directory if it doesn't exist
func (tm *ToolManager) ensureUserBinDirectory() error {
	if err := os.MkdirAll(tm.userBin, UserBinPermissions); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", tm.userBin, err)
	}

	logrus.Debugf("✅ Created user bin directory: %s", tm.userBin)
	return nil
}

// createToolSymlinks creates symlinks for required tools
func (tm *ToolManager) createToolSymlinks(tools []string) {
	for _, tool := range tools {
		if err := tm.createToolSymlink(tool); err != nil {
			logrus.Warnf("Failed to create symlink for %s: %v", tool, err)
			// Continue with other tools
		}
	}
}

// createToolSymlink creates a symlink for a specific tool
func (tm *ToolManager) createToolSymlink(tool string) error {
	// Find the tool in system PATH
	toolPath, err := exec.LookPath(tool)
	if err != nil {
		logrus.Debugf("Tool %s not found in PATH: %v", tool, err)
		return nil // Not an error if tool doesn't exist
	}

	// Create symlink in user bin directory
	linkPath := filepath.Join(tm.userBin, tool)

	// Remove existing symlink if it exists
	if _, err := os.Lstat(linkPath); err == nil {
		if err := os.Remove(linkPath); err != nil {
			logrus.Debugf("Failed to remove existing symlink %s: %v", linkPath, err)
		}
	}

	// Create new symlink
	if err := os.Symlink(toolPath, linkPath); err != nil {
		return fmt.Errorf("failed to create symlink %s -> %s: %w", linkPath, toolPath, err)
	}

	logrus.Debugf("✅ Created symlink: %s -> %s", linkPath, toolPath)
	return nil
}

// setupEnvironmentVariables sets up environment variables for tool execution
func (tm *ToolManager) setupEnvironmentVariables() {
	// Set PATH to include user bin directory first
	path := fmt.Sprintf("PATH=%s:/usr/local/bin:/usr/bin:/bin", tm.userBin)

	// Set basic environment variables
	envVars := []string{
		path,
	}

	// Set environment variables
	const envVarParts = 2
	for _, envVar := range envVars {
		parts := strings.SplitN(envVar, "=", envVarParts)
		if len(parts) == envVarParts {
			if err := os.Setenv(parts[0], parts[1]); err != nil {
				logrus.Warnf("Failed to set environment variable %s: %v", parts[0], err)
			}
		}
	}

	logrus.Debugf("✅ Set up environment variables for tool execution")
}

// deduplicate removes duplicate strings from a slice
func (tm *ToolManager) deduplicate(slice []string) []string {
	keys := make(map[string]bool)
	var result []string

	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}

	return result
}

// extractExecutablesFromCommand extracts executable names from a command string
func (tm *ToolManager) extractExecutablesFromCommand(command string) []string {
	var executables []string

	// Split command into words
	words := strings.Fields(command)

	for _, word := range words {
		// Skip shell operators and flags
		if tm.isShellOperator(word) || tm.isFlag(word) {
			continue
		}

		// Extract executable name (before any arguments)
		execName := tm.extractExecutableName(word)
		if execName != "" {
			executables = append(executables, execName)
		}
	}

	return executables
}

// isShellOperator checks if a word is a shell operator
func (tm *ToolManager) isShellOperator(word string) bool {
	operators := []string{"&&", "||", "&", "|", ";", "(", ")", "<", ">", ">>", "<<"}
	for _, op := range operators {
		if word == op {
			return true
		}
	}
	return false
}

// isFlag checks if a word is a command line flag
func (tm *ToolManager) isFlag(word string) bool {
	return strings.HasPrefix(word, "-") || strings.HasPrefix(word, "--")
}

// extractExecutableName extracts the executable name from a command word
func (tm *ToolManager) extractExecutableName(word string) string {
	// Remove any path separators and get just the executable name
	baseName := filepath.Base(word)

	// Skip empty names or names that look like arguments
	if baseName == "" || baseName == "." || baseName == ".." {
		return ""
	}

	// Skip shell built-ins and special characters
	if tm.isShellBuiltin(baseName) {
		return ""
	}

	return baseName
}

// isShellBuiltin checks if a command is a shell built-in
func (tm *ToolManager) isShellBuiltin(cmd string) bool {
	builtins := []string{
		"cd", "pwd", "echo", "export", "unset", "alias", "unalias",
		"source", ".", ":", "true", "false", "exit", "return",
	}
	for _, builtin := range builtins {
		if cmd == builtin {
			return true
		}
	}
	return false
}

// GetEnvironmentVariables returns the environment variables for tool execution
func (tm *ToolManager) GetEnvironmentVariables() []string {
	return []string{
		fmt.Sprintf("PATH=%s:/usr/local/bin:/usr/bin:/bin", tm.userBin),
	}
}
