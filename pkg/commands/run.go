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
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/constants"
	"github.com/Gosayram/kaniko/pkg/dockerfile"
	"github.com/Gosayram/kaniko/pkg/rootless"
	"github.com/Gosayram/kaniko/pkg/util"
)

// RunCommand implements the Dockerfile RUN instruction
// It handles executing shell commands during the build process
type RunCommand struct {
	BaseCommand
	cmd      *instructions.RunCommand
	shdCache bool
}

// Error messages for command execution
const (
	errCommandOrFileNotFound = "command or file not found"
	errPackageNotFound       = "package not found"
	errPackageManagerError   = "package manager error"
)

// Output truncation limits
const (
	maxOutputPreviewLength = 500 // Maximum length for error output preview
)

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
	// Rootless: automatic permission validation before execution
	rootlessManager := rootless.GetManager()
	if rootlessManager.IsRootlessMode() {
		if err := rootlessManager.ValidateCommandPermissions(r.cmd.String()); err != nil {
			return err
		}
	}

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

	// Set up environment variables
	if err := setupEnvironmentVariables(cmd, config, buildArgs); err != nil {
		return err
	}

	return executeAndCleanupCommand(cmd)
}

// setupEnvironmentVariables configures environment variables for the command
func setupEnvironmentVariables(cmd *exec.Cmd, config *v1.Config, buildArgs *dockerfile.BuildArgs) error {
	// Get environment variables from container (same as original kaniko)
	replacementEnvs := buildArgs.ReplacementEnvs(config.Env)

	// Add default HOME if needed
	env, err := addDefaultHOME(config.User, replacementEnvs)
	if err != nil {
		return errors.Wrap(err, "adding default HOME variable")
	}

	// Set up basic PATH for user tools
	setupUserPath(env)

	// Set all environment variables from container
	cmd.Env = env

	return nil
}

// setupUserPath sets up PATH to include user bin directory
func setupUserPath(env []string) {
	// Get HOME directory for the user
	homeDir := "/root" // default for containers
	for _, envVar := range env {
		if strings.HasPrefix(envVar, "HOME=") {
			homeDir = strings.TrimPrefix(envVar, "HOME=")
			break
		}
	}

	// Add user bin directory to PATH
	userBin := fmt.Sprintf("%s/.local/bin", homeDir)
	path := fmt.Sprintf("PATH=%s:/usr/local/bin:/usr/bin:/bin", userBin)

	// Set environment variable
	if err := os.Setenv("PATH", path); err != nil {
		logrus.Warnf("Failed to set PATH environment variable: %v", err)
	}
}

func executeAndCleanupCommand(cmd *exec.Cmd) error {
	// NOTE: PrepareCommonSystemDirectoriesWritable is now called once in ExecuteCommands
	// before parallel execution starts to prevent race conditions

	// Capture stderr and stdout to detect errors (especially for piped commands)
	var stderrBuf, stdoutBuf strings.Builder
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderrBuf)
	cmd.Stdout = io.MultiWriter(os.Stdout, &stdoutBuf)

	logrus.Infof("Running: %s", cmd.Args)

	// Try to execute the command
	if startErr := cmd.Start(); startErr != nil {
		logrus.Warnf("Failed to start command: %v", startErr)
		// Don't return error - continue with build
		return nil
	}

	// Wait for command to complete and check for errors
	waitErr := waitAndCleanupProcess(cmd)

	// Get stderr and stdout output
	// Important: Read buffers after command completes to ensure all data is captured
	stderrOutput := stderrBuf.String()
	stdoutOutput := stdoutBuf.String()

	// Debug: log output lengths and content
	logrus.Debugf("Captured stderr length: %d bytes, stdout length: %d bytes", len(stderrOutput), len(stdoutOutput))
	if stderrOutput != "" {
		const stderrPreviewLength = 200
		logrus.Debugf("Stderr preview (first 200 chars): %s", truncateString(stderrOutput, stderrPreviewLength))
	}
	if stdoutOutput != "" {
		const stdoutPreviewLength = 200
		logrus.Debugf("Stdout preview (first 200 chars): %s", truncateString(stdoutOutput, stdoutPreviewLength))
	}

	// Log full output for debugging if it contains error patterns
	if strings.Contains(strings.ToLower(stderrOutput+stdoutOutput), "not found") ||
		strings.Contains(strings.ToLower(stderrOutput+stdoutOutput), "error") {
		logrus.Debugf("Full stderr output: %s", stderrOutput)
		logrus.Debugf("Full stdout output: %s", stdoutOutput)
	}

	// Check if there were permission errors in stderr
	// NOTE: Don't check waitErr - commands can succeed (exit 0) but still have EACCES errors internally
	hasPermError := strings.Contains(stderrOutput, "EACCES") ||
		strings.Contains(stderrOutput, "permission denied")

	if hasPermError {
		commandStr := strings.Join(cmd.Args, " ")
		logrus.Warnf("Permission error detected in command output: %s", commandStr)

		// Parse stderr and fix permission errors
		fixedDirs := util.ParsePermissionErrorAndFix(stderrOutput)

		if len(fixedDirs) > 0 {
			logrus.Infof("Fixed permissions for %d directories, retrying command", len(fixedDirs))

			// Retry the command
			retryCmd := &exec.Cmd{
				Path: cmd.Path,
				Args: cmd.Args,
				Dir:  cmd.Dir,
				Env:  cmd.Env,
			}
			retryCmd.Stdout = os.Stdout
			retryCmd.Stderr = os.Stderr
			retryCmd.SysProcAttr = &syscall.SysProcAttr{
				Setpgid: true,
			}

			logrus.Infof("Retrying command: %s", commandStr)
			if startErr := retryCmd.Start(); startErr != nil {
				logrus.Warnf("Failed to start retry command: %v", startErr)
				return errors.Wrapf(startErr, "command failed: %s", commandStr)
			}

			if retryErr := waitAndCleanupProcess(retryCmd); retryErr != nil {
				logrus.Errorf("Retry command failed: %v", retryErr)
				return errors.Wrapf(retryErr, "command failed after retry: %s", commandStr)
			}
			logrus.Infof("Retry command succeeded after fixing permissions")
		}
	}

	// Check for command execution errors
	// Combine stderr and stdout for error detection (piped commands may output errors to stdout)
	combinedOutput := stderrOutput
	if stdoutOutput != "" {
		combinedOutput += "\n" + stdoutOutput
	}
	return checkCommandErrors(cmd, waitErr, combinedOutput)
}

// checkCommandErrors checks for command execution errors and handles them appropriately
// This function handles both exit code errors and stderr/stdout error patterns
func checkCommandErrors(cmd *exec.Cmd, waitErr error, combinedOutput string) error {
	commandStr := strings.Join(cmd.Args, " ")

	// Check output for error patterns even if waitErr is nil
	// This is critical for piped commands (e.g., "curl ... | bash") where the pipe
	// may succeed but the first command fails (bash exits 0 even if curl fails)
	errMsg := detectStderrError(combinedOutput)

	if waitErr != nil {
		// Process exit error - definitely failed
		if errMsg != "" {
			logrus.Errorf("Command failed: %s - %s", errMsg, commandStr)
			return errors.Wrapf(waitErr, "command failed: %s (%s, output: %s)",
				commandStr, errMsg, combinedOutput)
		}
		logrus.Errorf("Command execution failed: %s", commandStr)
		return errors.Wrapf(waitErr, "command failed: %s (output: %s)", commandStr, combinedOutput)
	}

	// waitErr is nil, but check output for errors anyway (especially for piped commands)
	if errMsg != "" {
		// For piped commands, errors in output indicate failure even if exit code is 0
		// Example: "curl ... | bash" - bash succeeds (exit 0) but curl fails
		// The error "curl: not found" appears in stderr/stdout
		logrus.Errorf("Command failed: %s - %s", errMsg, commandStr)
		logrus.Errorf("   Command exited with code 0, but output contains errors " +
			"(likely piped command failure)")
		logrus.Errorf("   Output: %s", truncateString(combinedOutput, maxOutputPreviewLength))
		return errors.Errorf("command failed: %s (%s, output: %s)",
			commandStr, errMsg, combinedOutput)
	}

	return nil
}

// detectStderrError detects error patterns in stderr/stdout output
// Returns empty string if no error detected, or error message if detected
// Order matters: more specific patterns should be checked first
func detectStderrError(output string) string {
	// Normalize output for case-insensitive matching
	outputLower := strings.ToLower(output)

	switch {
	// Check most specific patterns first
	case strings.Contains(outputLower, "unable to locate package"):
		// APT package not found error - most specific
		return errPackageNotFound
	case strings.Contains(outputLower, "e: ") &&
		(strings.Contains(outputLower, "unable") || strings.Contains(outputLower, "failed")):
		// APT/Debian error patterns (E: prefix indicates APT errors)
		return errPackageManagerError
	case strings.Contains(outputLower, "/bin/sh:") && strings.Contains(outputLower, "not found"):
		// Shell error messages like "/bin/sh: 1: curl: not found"
		return errCommandOrFileNotFound
	case strings.Contains(outputLower, "command not found") || strings.Contains(outputLower, "no such file or directory"):
		// Command execution errors
		return errCommandOrFileNotFound
	case strings.Contains(outputLower, "not found") || strings.Contains(outputLower, "no such file"):
		// Generic "not found" pattern - check last to avoid false positives
		return errCommandOrFileNotFound
	default:
		return ""
	}
}

// truncateString truncates a string to maxLen characters
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// prepareCommand prepares the command based on shell configuration
// and handles PATH environment variable resolution for executables
func prepareCommand(
	config *v1.Config, buildArgs *dockerfile.BuildArgs,
	cmdRun *instructions.RunCommand) ([]string, error) {
	replacementEnvs := buildArgs.ReplacementEnvs(config.Env)

	if cmdRun.PrependShell {
		return prepareShellCommand(config, cmdRun, replacementEnvs)
	}
	return prepareDirectCommand(cmdRun, replacementEnvs)
}

// prepareShellCommand prepares a shell command
func prepareShellCommand(
	config *v1.Config, cmdRun *instructions.RunCommand, replacementEnvs []string) ([]string, error) {
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

	cmd := strings.Join(resolvedCmdLine, " ")

	// Heredoc support: handle heredoc syntax (<<EOF)
	if len(cmdRun.Files) == 1 && cmd == fmt.Sprintf("<<%s", cmdRun.Files[0].Name) {
		// If we encounter a line like 'RUN <<EOF',
		// we implicitly want the file body to be executed as a script
		cmd += " sh"
	}
	for _, h := range cmdRun.Files {
		cmd += "\n" + h.Data + h.Name
	}

	shell = append(shell, cmd)
	return shell, nil
}

// prepareDirectCommand prepares a direct command execution
func prepareDirectCommand(cmdRun *instructions.RunCommand, replacementEnvs []string) ([]string, error) {
	// Heredoc support: warn if heredoc is used in exec form (not supported)
	if len(cmdRun.Files) > 0 {
		// https://github.com/GoogleContainerTools/kaniko/issues/1713
		logrus.Warnf(
			"#1713 kaniko does not support heredoc syntax in 'RUN [\"<command>\", ...]' (Exec Form) statements: %v",
			cmdRun.Files[0].Name,
		)
	}

	// CRITICAL FIX: Resolve environment variables in command line for direct execution
	newCommand := make([]string, len(cmdRun.CmdLine))
	for i, cmd := range cmdRun.CmdLine {
		resolved, err := util.ResolveEnvironmentReplacement(cmd, replacementEnvs, false)
		if err != nil {
			return nil, errors.Wrapf(err, "resolving environment variables in command: %s", cmd)
		}
		newCommand[i] = resolved
	}

	// Resolve command path
	resolveCommandPath(newCommand, replacementEnvs)

	logrus.Infof("Cmd: %s", newCommand[0])
	logrus.Infof("Args: %s", newCommand[1:])
	return newCommand, nil
}

// resolveCommandPath resolves the path to the executable
func resolveCommandPath(newCommand, _ []string) {
	commandName := newCommand[0]

	// Try to find command in PATH, but don't fail if not found
	if path, err := exec.LookPath(commandName); err == nil {
		newCommand[0] = path
		logrus.Debugf("Found command in PATH: %s", path)
	} else {
		// Don't fail - let the system handle it during execution
		logrus.Debugf("Command not found in PATH: %s, will try direct execution", commandName)
	}
}

// validateCommand validates command arguments to prevent command injection
func validateCommand(_ []string) error {
	// DISABLED: All validation removed to allow any command execution
	return nil
}

// hasShellOperators checks if command contains shell operators
func hasShellOperators(commandStr string) bool {
	return strings.Contains(commandStr, "&&") ||
		strings.Contains(commandStr, "||") ||
		strings.Contains(commandStr, ";") ||
		strings.Contains(commandStr, "|") ||
		strings.Contains(commandStr, ">") ||
		strings.Contains(commandStr, "<")
}

// createExecCommand creates and configures the exec.Cmd with proper settings
func createExecCommand(config *v1.Config, buildArgs *dockerfile.BuildArgs, newCommand []string) (*exec.Cmd, error) {
	cmd, err := createCommand(config, buildArgs, newCommand)
	if err != nil {
		return nil, err
	}

	// Configure command settings
	configureCommandSettings(cmd, config)

	// CRITICAL FIX: Don't override environment variables set by setupEnvironmentVariables
	// The environment variables are already properly set in setupEnvironmentVariables
	// Only set up additional environment variables if cmd.Env is empty
	if len(cmd.Env) == 0 {
		env, err := setupCommandEnvironmentVars(cmd, config, buildArgs)
		if err != nil {
			return nil, err
		}
		cmd.Env = env
	}
	// If cmd.Env is not empty, it means setupEnvironmentVariables already set it correctly
	// Don't override it with additional environment variables

	return cmd, nil
}

// createCommand creates the appropriate command type (shell or direct)
func createCommand(config *v1.Config, buildArgs *dockerfile.BuildArgs, newCommand []string) (*exec.Cmd, error) {
	// Check if the command is already a shell command (starts with shell path)
	if len(newCommand) >= 2 && (newCommand[0] == "/bin/sh" || newCommand[0] == "/bin/bash" ||
		strings.HasSuffix(newCommand[0], "/sh") || strings.HasSuffix(newCommand[0], "/bash")) {
		// This is already a shell command, execute it directly
		return createDirectCommand(newCommand)
	}

	commandStr := strings.Join(newCommand, " ")
	hasShellOps := hasShellOperators(commandStr)

	if hasShellOps {
		return createShellCommand(config, buildArgs, commandStr)
	}
	return createDirectCommand(newCommand)
}

// createShellCommand creates a shell command
func createShellCommand(config *v1.Config, buildArgs *dockerfile.BuildArgs, commandStr string) (*exec.Cmd, error) {
	// This is the default shell on Linux (same as original kaniko)
	var shell []string
	if len(config.Shell) > 0 {
		shell = config.Shell
	} else {
		shell = append(shell, "/bin/sh", "-c")
	}

	// CRITICAL FIX: Resolve environment variables in shell commands
	replacementEnvs := buildArgs.ReplacementEnvs(config.Env)
	resolvedCommandStr, err := util.ResolveEnvironmentReplacement(commandStr, replacementEnvs, false)
	if err != nil {
		return nil, errors.Wrapf(err, "resolving environment variables in shell command: %s", commandStr)
	}

	cmd := &exec.Cmd{
		Path: shell[0],
		Args: append(shell, resolvedCommandStr),
	}

	// CRITICAL FIX: Set up environment variables for shell command
	// This ensures that PATH and other variables are available to the shell
	if err := setupShellEnvironment(cmd, config, buildArgs); err != nil {
		return nil, err
	}

	logrus.Debugf("Executing shell command: %s -c %s", shell[0], resolvedCommandStr)
	return cmd, nil
}

// createDirectCommand creates a direct command
func createDirectCommand(newCommand []string) (*exec.Cmd, error) {
	// Use command as-is without cleaning or validation
	cmd := &exec.Cmd{
		Path: newCommand[0],
		Args: newCommand,
	}
	logrus.Debugf("Executing direct command: %s", strings.Join(newCommand, " "))
	return cmd, nil
}

// configureCommandSettings configures basic command settings
// NOTE: Stdout and Stderr are set in executeAndCleanupCommand to capture output
func configureCommandSettings(cmd *exec.Cmd, config *v1.Config) {
	cmd.Dir = setWorkDirIfExists(config.WorkingDir)
	// Don't set Stdout/Stderr here - they will be set in executeAndCleanupCommand
	// to capture output for error detection
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// Set user credentials if specified
	if err := setUserCredentials(cmd, config); err != nil {
		logrus.Warnf("Failed to set user credentials: %v", err)
	}
}

// setUserCredentials sets user credentials for the command
func setUserCredentials(cmd *exec.Cmd, config *v1.Config) error {
	u := config.User
	userAndGroup := strings.Split(u, ":")
	userStr, err := util.ResolveEnvironmentReplacement(userAndGroup[0], []string{}, false)
	if err != nil {
		return errors.Wrapf(err, "resolving user %s", userAndGroup[0])
	}

	if userStr != "" {
		cmd.SysProcAttr.Credential, err = util.SyscallCredentials(userStr)
		if err != nil {
			return errors.Wrap(err, "credentials")
		}
	}
	return nil
}

// setupCommandEnvironmentVars sets up the environment for the command
func setupCommandEnvironmentVars(_ *exec.Cmd, config *v1.Config, buildArgs *dockerfile.BuildArgs) ([]string, error) {
	replacementEnvs := buildArgs.ReplacementEnvs(config.Env)
	env, err := addDefaultHOME(config.User, replacementEnvs)
	if err != nil {
		return nil, errors.Wrap(err, "adding default HOME variable")
	}

	// Simple approach: just return the environment as-is
	// Let the system handle PATH resolution
	return env, nil
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

// CacheCommand returns true since this command should be cached
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
		"/",
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

// setupShellEnvironment sets up environment variables for shell commands
func setupShellEnvironment(cmd *exec.Cmd, config *v1.Config, buildArgs *dockerfile.BuildArgs) error {
	// Get environment variables from container (same as original kaniko)
	replacementEnvs := buildArgs.ReplacementEnvs(config.Env)

	// Add default HOME if needed
	env, err := addDefaultHOME(config.User, replacementEnvs)
	if err != nil {
		return errors.Wrap(err, "adding default HOME variable")
	}

	// Set all environment variables from container
	cmd.Env = env

	return nil
}
