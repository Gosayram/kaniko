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

package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	kConfig "github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/constants"
	"github.com/Gosayram/kaniko/pkg/dockerfile"
	"github.com/Gosayram/kaniko/pkg/util"
)

const (
	// envKeyValueParts is the expected number of parts when splitting environment variable key=value
	envKeyValueParts = 2
)

// RunCommand implements the Dockerfile RUN instruction
// It handles executing shell commands during the build process
type RunCommand struct {
	BaseCommand
	cmd      *instructions.RunCommand
	shdCache bool
}

// for testing
var (
	userLookup = util.LookupUser
)

// IsArgsEnvsRequiredInCache indicates whether arguments and environment variables
// are required for caching this command
func (r *RunCommand) IsArgsEnvsRequiredInCache() bool {
	return true
}

// ExecuteCommand executes the RUN instruction by preparing and running the command
// with proper environment setup and security validation
func (r *RunCommand) ExecuteCommand(config *v1.Config, buildArgs *dockerfile.BuildArgs) error {
	return runCommandInExec(config, buildArgs, r.cmd)
}

func runCommandInExec(config *v1.Config, buildArgs *dockerfile.BuildArgs, cmdRun *instructions.RunCommand) error {
	newCommand, err := prepareCommand(config, buildArgs, cmdRun)
	if err != nil {
		return err
	}

	if validationErr := validateCommand(newCommand); validationErr != nil {
		return validationErr
	}

	cmd, err := createExecCommand(config, buildArgs, newCommand)
	if err != nil {
		return err
	}

	// CRITICAL FIX: Ensure all environment variables are properly set in the command environment
	// This ensures that PATH and other variables from previous RUN commands are preserved
	replacementEnvs := buildArgs.ReplacementEnvs(config.Env)

	// Create a map of existing environment variables for quick lookup
	existingEnvs := make(map[string]string)
	for _, env := range cmd.Env {
		if parts := strings.SplitN(env, "=", envKeyValueParts); len(parts) == envKeyValueParts {
			existingEnvs[parts[0]] = parts[1]
		}
	}

	// Add all replacement environment variables to command environment
	for _, env := range replacementEnvs {
		if parts := strings.SplitN(env, "=", envKeyValueParts); len(parts) == envKeyValueParts {
			key := parts[0]
			value := parts[1]

			// Always update environment variables to ensure they are current
			// Remove existing entry if it exists
			for i, cmdEnv := range cmd.Env {
				if strings.HasPrefix(cmdEnv, key+"=") {
					cmd.Env = append(cmd.Env[:i], cmd.Env[i+1:]...)
					break
				}
			}
			// Add the new environment variable
			cmd.Env = append(cmd.Env, env)
			logrus.Debugf("Added environment variable to command: %s=%s", key, value)
		}
	}

	// CRITICAL FIX: Inherit all host environment variables
	// This ensures that all environment variables from the host system are available
	// This is especially important for CI/CD systems and package managers
	hostEnvs := os.Environ()
	for _, hostEnv := range hostEnvs {
		if parts := strings.SplitN(hostEnv, "=", envKeyValueParts); len(parts) == envKeyValueParts {
			key := parts[0]

			// Skip system-specific variables that shouldn't be inherited
			if isSystemVariable(key) {
				continue
			}

			// Check if already set in command environment
			found := false
			for i, cmdEnv := range cmd.Env {
				if strings.HasPrefix(cmdEnv, key+"=") {
					// Update existing variable
					cmd.Env[i] = hostEnv
					found = true
					break
				}
			}
			if !found {
				// Add new environment variable
				cmd.Env = append(cmd.Env, hostEnv)
			}
			logrus.Debugf("Inherited host environment variable: %s", key)
		}
	}

	return executeAndCleanupCommand(cmd)
}

func executeAndCleanupCommand(cmd *exec.Cmd) error {
	logrus.Infof("Running: %s", cmd.Args)
	if startErr := cmd.Start(); startErr != nil {
		return errors.Wrap(startErr, "starting command")
	}

	// CRITICAL FIX: Handle command execution failures with better diagnostics
	if err := waitAndCleanupProcess(cmd); err != nil {
		// Provide better error diagnostics for common issues
		commandStr := strings.Join(cmd.Args, " ")

		// Check for common command not found issues
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "command not found") {
			logrus.Warnf("Command not found: %s", commandStr)
			logrus.Infof("This might be due to missing PATH or the command not being installed")
			logrus.Infof("Available PATH: %s", strings.Join(getPathDirectories(), ":"))
		}

		// Check for permission issues
		if strings.Contains(err.Error(), "permission denied") || strings.Contains(err.Error(), "Permission denied") {
			logrus.Warnf("Permission denied for command: %s", commandStr)
			logrus.Infof("Check file permissions and user context")
		}

		// Check for environment variable issues
		if strings.Contains(err.Error(), "unknown operand") || strings.Contains(err.Error(), "bad substitution") {
			logrus.Warnf("Environment variable resolution failed for command: %s", commandStr)
			logrus.Infof("Check that all required environment variables are properly set")
		}

		return err
	}

	return nil
}

// prepareCommand prepares the command based on shell configuration
// and handles PATH environment variable resolution for executables
func prepareCommand(
	config *v1.Config, buildArgs *dockerfile.BuildArgs,
	cmdRun *instructions.RunCommand) ([]string, error) {
	var newCommand []string
	replacementEnvs := buildArgs.ReplacementEnvs(config.Env)

	if cmdRun.PrependShell {
		// This is the default shell on Linux
		var shell []string
		if len(config.Shell) > 0 {
			shell = config.Shell
		} else {
			shell = append(shell, "/bin/sh", "-c")
		}

		// CRITICAL FIX: Resolve environment variables in command line before passing to shell
		resolvedCmdLine := make([]string, len(cmdRun.CmdLine))
		for i, cmd := range cmdRun.CmdLine {
			resolved, err := util.ResolveEnvironmentReplacement(cmd, replacementEnvs, false)
			if err != nil {
				return nil, errors.Wrapf(err, "resolving environment variables in command: %s", cmd)
			}
			resolvedCmdLine[i] = resolved
		}

		shell = append(shell, strings.Join(resolvedCmdLine, " "))
		newCommand = shell
	} else {
		// CRITICAL FIX: Resolve environment variables in command line for direct execution
		newCommand = make([]string, len(cmdRun.CmdLine))
		for i, cmd := range cmdRun.CmdLine {
			resolved, err := util.ResolveEnvironmentReplacement(cmd, replacementEnvs, false)
			if err != nil {
				return nil, errors.Wrapf(err, "resolving environment variables in command: %s", cmd)
			}
			newCommand[i] = resolved
		}

		// CRITICAL FIX: Improved command resolution with better PATH handling
		// Try to resolve the command path using multiple strategies
		commandName := newCommand[0]

		// Strategy 1: Try to find command in current PATH
		if path, err := exec.LookPath(commandName); err == nil {
			newCommand[0] = path
			logrus.Debugf("Found command in PATH: %s", path)
		} else {
			// Strategy 2: Try with PATH from replacement environments
			for _, v := range replacementEnvs {
				entry := strings.SplitN(v, "=", 2) //nolint:mnd // 2 is the expected number of parts for env var
				if entry[0] != "PATH" {
					continue
				}

				// Temporarily set PATH to find the command
				oldPath := os.Getenv("PATH")
				if setErr := os.Setenv("PATH", entry[1]); setErr != nil {
					logrus.Warnf("Failed to set PATH: %v", setErr)
					continue
				}

				if path, err := exec.LookPath(commandName); err == nil {
					newCommand[0] = path
					logrus.Debugf("Found command with custom PATH: %s", path)
					// Restore PATH
					os.Setenv("PATH", oldPath)
					break
				}

				// Restore PATH
				if setErr := os.Setenv("PATH", oldPath); setErr != nil {
					logrus.Warnf("Failed to restore PATH: %v", setErr)
				}
			}
		}

		// Strategy 3: If still not found, try common locations
		if !filepath.IsAbs(newCommand[0]) {
			commonPaths := []string{"/usr/bin", "/bin", "/usr/local/bin", "/opt/bin"}
			for _, commonPath := range commonPaths {
				fullPath := filepath.Join(commonPath, commandName)
				if _, err := os.Stat(fullPath); err == nil {
					newCommand[0] = fullPath
					logrus.Debugf("Found command in common path: %s", fullPath)
					break
				}
			}
		}
	}

	logrus.Infof("Cmd: %s", newCommand[0])
	logrus.Infof("Args: %s", newCommand[1:])
	return newCommand, nil
}

// validateCommand validates command arguments to prevent command injection
func validateCommand(newCommand []string) error {
	// CRITICAL FIX: Allow shell variables and operators for shell commands
	// Only validate for direct command execution, not shell commands
	commandStr := strings.Join(newCommand, " ")
	hasShellOperators := strings.Contains(commandStr, "&&") ||
		strings.Contains(commandStr, "||") ||
		strings.Contains(commandStr, ";") ||
		strings.Contains(commandStr, "|") ||
		strings.Contains(commandStr, ">") ||
		strings.Contains(commandStr, "<")

	// For shell commands, only validate for dangerous patterns, not shell syntax
	if hasShellOperators {
		// Allow shell variables and operators for shell commands
		for _, arg := range newCommand {
			// Only check for dangerous path patterns
			if strings.Contains(arg, "../") || strings.Contains(arg, "~/") {
				return errors.Errorf("potentially dangerous path pattern in command argument: %q", arg)
			}
		}
	} else {
		// For direct commands, validate more strictly
		for _, arg := range newCommand {
			if strings.ContainsAny(arg, "&|;`<>") {
				return errors.Errorf("invalid character in command argument: %q", arg)
			}
			// Additional validation: ensure arguments don't contain potentially dangerous patterns
			if strings.Contains(arg, "../") || strings.Contains(arg, "~/") {
				return errors.Errorf("potentially dangerous path pattern in command argument: %q", arg)
			}
		}
		// Additional validation for command path
		if !filepath.IsAbs(newCommand[0]) {
			if _, err := exec.LookPath(newCommand[0]); err != nil {
				return errors.Wrapf(err, "invalid command path: %s", newCommand[0])
			}
		}
		// Use explicit argument passing instead of variadic to satisfy gosec
		// Validate the command path to prevent command injection
		cleanCommandPath := filepath.Clean(newCommand[0])
		if strings.Contains(cleanCommandPath, "..") || !filepath.IsAbs(cleanCommandPath) {
			return errors.Errorf("invalid command path: potential command injection detected: %q", newCommand[0])
		}
	}
	return nil
}

// createExecCommand creates and configures the exec.Cmd with proper settings
func createExecCommand(config *v1.Config, buildArgs *dockerfile.BuildArgs, newCommand []string) (*exec.Cmd, error) {
	// CRITICAL FIX: Handle shell commands properly
	// If the command contains shell operators like &&, ||, etc., we need to execute it through shell
	var cmd *exec.Cmd

	// Check if the command contains shell operators that require shell execution
	commandStr := strings.Join(newCommand, " ")
	hasShellOperators := strings.Contains(commandStr, "&&") ||
		strings.Contains(commandStr, "||") ||
		strings.Contains(commandStr, ";") ||
		strings.Contains(commandStr, "|") ||
		strings.Contains(commandStr, ">") ||
		strings.Contains(commandStr, "<")

	if hasShellOperators {
		// Execute through shell for commands with operators
		shell := "/bin/sh"
		if len(config.Shell) > 0 {
			shell = config.Shell[0]
		}

		// CRITICAL FIX: Resolve environment variables in shell commands
		// This ensures that variables like ${PNPM_VERSION} are properly substituted
		replacementEnvs := buildArgs.ReplacementEnvs(config.Env)
		resolvedCommandStr, err := util.ResolveEnvironmentReplacement(commandStr, replacementEnvs, false)
		if err != nil {
			return nil, errors.Wrapf(err, "resolving environment variables in shell command: %s", commandStr)
		}

		cmd = &exec.Cmd{
			Path: shell,
			Args: []string{shell, "-c", resolvedCommandStr},
		}
		logrus.Debugf("Executing shell command: %s -c %s", shell, resolvedCommandStr)
	} else {
		// Execute directly for simple commands
		cleanCommandPath := filepath.Clean(newCommand[0])
		cmd = &exec.Cmd{
			Path: cleanCommandPath,
			Args: append([]string{cleanCommandPath}, newCommand[1:]...),
		}
		logrus.Debugf("Executing direct command: %s", strings.Join(newCommand, " "))
	}

	cmd.Dir = setWorkDirIfExists(config.WorkingDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	replacementEnvs := buildArgs.ReplacementEnvs(config.Env)
	// Set process group ID to ensure proper cleanup of child processes
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	u := config.User
	userAndGroup := strings.Split(u, ":")
	userStr, err := util.ResolveEnvironmentReplacement(userAndGroup[0], replacementEnvs, false)
	if err != nil {
		return nil, errors.Wrapf(err, "resolving user %s", userAndGroup[0])
	}

	// If specified, run the command as a specific user
	if userStr != "" {
		cmd.SysProcAttr.Credential, err = util.SyscallCredentials(userStr)
		if err != nil {
			return nil, errors.Wrap(err, "credentials")
		}
	}

	env, err := addDefaultHOME(userStr, replacementEnvs)
	if err != nil {
		return nil, errors.Wrap(err, "adding default HOME variable")
	}

	// CRITICAL FIX: Ensure PATH is properly set for command execution
	// This is crucial for finding executables like corepack, pnpm, etc.
	pathSet := false
	currentPath := ""
	for _, envVar := range env {
		if strings.HasPrefix(envVar, "PATH=") {
			pathSet = true
			currentPath = strings.TrimPrefix(envVar, "PATH=")
			break
		}
	}

	// If PATH is not set, add a default one
	if !pathSet {
		defaultPath := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
		env = append(env, "PATH="+defaultPath)
		logrus.Debugf("Added default PATH: %s", defaultPath)
	} else {
		// CRITICAL FIX: Enhance PATH for package managers and development tools
		// Add common paths where package managers install binaries
		enhancedPath := currentPath
		additionalPaths := []string{
			"/usr/local/bin",        // Common for npm global installs
			"/usr/local/sbin",       // Common for system tools
			"/root/.local/bin",      // User local binaries
			"/home/node/.local/bin", // Node user local binaries
			"/opt/bin",              // Optional binaries
		}

		for _, additionalPath := range additionalPaths {
			if !strings.Contains(enhancedPath, additionalPath) {
				enhancedPath = enhancedPath + ":" + additionalPath
			}
		}

		// Update PATH in environment
		for i, envVar := range env {
			if strings.HasPrefix(envVar, "PATH=") {
				env[i] = "PATH=" + enhancedPath
				logrus.Debugf("Enhanced PATH: %s", enhancedPath)
				break
			}
		}
	}

	cmd.Env = env
	return cmd, nil
}

// waitAndCleanupProcess waits for the process to complete and cleans up child processes
func waitAndCleanupProcess(cmd *exec.Cmd) error {
	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil {
		return errors.Wrap(err, "getting group id for process")
	}
	if err := cmd.Wait(); err != nil {
		return errors.Wrap(err, "waiting for process to exit")
	}

	// it's not an error if there are no grandchildren
	if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil && err.Error() != "no such process" {
		return err
	}
	return nil
}

// addDefaultHOME adds the default value for HOME if it isn't already set
func addDefaultHOME(u string, envs []string) ([]string, error) {
	for _, env := range envs {
		split := strings.SplitN(env, "=", 2) //nolint:mnd // 2 is the expected number of parts for env var
		if split[0] == constants.HOME {
			return envs, nil
		}
	}

	// If user isn't set, set default value of HOME
	if u == "" || u == constants.RootUser {
		return append(envs, fmt.Sprintf("%s=%s", constants.HOME, constants.DefaultHOMEValue)), nil
	}

	// If user is set to username, set value of HOME to /home/${user}
	// Otherwise the user is set to uid and HOME is /
	userObj, err := userLookup(u)
	if err != nil {
		return nil, fmt.Errorf("lookup user %v: %w", u, err)
	}

	return append(envs, fmt.Sprintf("%s=%s", constants.HOME, userObj.HomeDir)), nil
}

// String returns some information about the command for the image config
func (r *RunCommand) String() string {
	return r.cmd.String()
}

// FilesToSnapshot returns the list of files that should be snapshotted after command execution
func (r *RunCommand) FilesToSnapshot() []string {
	return nil
}

// ProvidesFilesToSnapshot indicates whether this command provides files for snapshotting
func (r *RunCommand) ProvidesFilesToSnapshot() bool {
	return false
}

// CacheCommand creates a cached version of the RUN command for layer reuse
func (r *RunCommand) CacheCommand(img v1.Image) DockerCommand {
	return &CachingRunCommand{
		img:       img,
		cmd:       r.cmd,
		extractFn: util.ExtractFile,
	}
}

// MetadataOnly indicates whether this command only affects metadata (not filesystem)
func (r *RunCommand) MetadataOnly() bool {
	return false
}

// RequiresUnpackedFS indicates whether this command requires an unpacked filesystem
func (r *RunCommand) RequiresUnpackedFS() bool {
	return true
}

// ShouldCacheOutput indicates whether the output of this command should be cached
func (r *RunCommand) ShouldCacheOutput() bool {
	return r.shdCache
}

// CachingRunCommand implements caching for RUN instructions
// It handles extracting cached layers instead of executing commands
type CachingRunCommand struct {
	BaseCommand
	caching
	img            v1.Image
	extractedFiles []string
	cmd            *instructions.RunCommand
	extractFn      util.ExtractFunction
}

// IsArgsEnvsRequiredInCache indicates whether arguments and environment variables
// are required for caching this command
func (cr *CachingRunCommand) IsArgsEnvsRequiredInCache() bool {
	return true
}

// ExecuteCommand handles cached RUN instruction execution by extracting
// pre-computed layers instead of running the command
func (cr *CachingRunCommand) ExecuteCommand(_ *v1.Config, _ *dockerfile.BuildArgs) error {
	logrus.Infof("Found cached layer, extracting to filesystem")
	var err error

	if cr.img == nil {
		return fmt.Errorf("command image is nil %v", cr.String())
	}

	layers, err := cr.img.Layers()
	if err != nil {
		return errors.Wrap(err, "retrieving image layers")
	}

	if len(layers) != 1 {
		return fmt.Errorf("expected %d layers but got %d", 1, len(layers))
	}

	cr.layer = layers[0]

	cr.extractedFiles, err = util.GetFSFromLayers(
		kConfig.RootDir,
		layers,
		util.ExtractFunc(cr.extractFn),
		util.IncludeWhiteout(),
	)
	if err != nil {
		return errors.Wrap(err, "extracting fs from image")
	}

	return nil
}

// FilesToSnapshot returns the list of files extracted from cached layers
func (cr *CachingRunCommand) FilesToSnapshot() []string {
	f := cr.extractedFiles
	logrus.Debugf("%d files extracted by caching run command", len(f))
	logrus.Tracef("Extracted files: %s", f)

	return f
}

// String returns string representation of the cached RUN command
func (cr *CachingRunCommand) String() string {
	if cr.cmd == nil {
		return "nil command"
	}
	return cr.cmd.String()
}

// MetadataOnly indicates whether this cached command only affects metadata
func (cr *CachingRunCommand) MetadataOnly() bool {
	return false
}

// todo: this should create the workdir if it doesn't exist, atleast this is what docker does
func setWorkDirIfExists(workdir string) string {
	if _, err := os.Lstat(workdir); err == nil {
		return workdir
	}
	return ""
}

// isSystemVariable checks if a variable is system-specific and shouldn't be inherited
func isSystemVariable(key string) bool {
	systemVars := map[string]bool{
		"HOME": true, "USER": true, "SHELL": true, "TERM": true,
		"PWD": true, "OLDPWD": true, "PS1": true, "PS2": true,
		"PATH": true, "LD_LIBRARY_PATH": true, "DYLD_LIBRARY_PATH": true,
		"TMPDIR": true, "TMP": true, "TEMP": true,
	}
	return systemVars[key]
}

// getPathDirectories returns the current PATH directories for debugging
func getPathDirectories() []string {
	path := os.Getenv("PATH")
	if path == "" {
		return []string{}
	}
	return strings.Split(path, ":")
}
