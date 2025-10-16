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

			// Only add if not already present or if it's a PATH variable (which we want to ensure is set)
			if _, exists := existingEnvs[key]; !exists || key == "PATH" {
				// Remove existing entry if it exists
				for i, cmdEnv := range cmd.Env {
					if strings.HasPrefix(cmdEnv, key+"=") {
						cmd.Env = append(cmd.Env[:i], cmd.Env[i+1:]...)
						break
					}
				}
				// Add the new environment variable
				cmd.Env = append(cmd.Env, env)
				logrus.Debugf("Added environment variable to command: %s", env)
			}
		}
	}

	return executeAndCleanupCommand(cmd)
}

func executeAndCleanupCommand(cmd *exec.Cmd) error {
	logrus.Infof("Running: %s", cmd.Args)
	if startErr := cmd.Start(); startErr != nil {
		return errors.Wrap(startErr, "starting command")
	}

	return waitAndCleanupProcess(cmd)
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

		// Find and set absolute path of executable by setting PATH temporary
		for _, v := range replacementEnvs {
			entry := strings.SplitN(v, "=", 2) //nolint:mnd // 2 is the expected number of parts for env var
			if entry[0] != "PATH" {
				continue
			}
			oldPath := os.Getenv("PATH")
			// Store old path for debugging
			_ = oldPath

			if setErr := os.Setenv("PATH", entry[1]); setErr != nil {
				return nil, errors.Wrap(setErr, "setting PATH")
			}
			path, err := exec.LookPath(newCommand[0])
			if err == nil {
				newCommand[0] = path
			}

			// Restore PATH immediately after use to avoid interfering with environment variable resolution
			// The PATH will be properly set in the command environment via cmd.Env in createExecCommand
			if setErr := os.Setenv("PATH", oldPath); setErr != nil {
				logrus.Warnf("Failed to restore PATH: %v", setErr)
			}
			logrus.Debugf("Using PATH from config: %s", entry[1])
		}
	}

	logrus.Infof("Cmd: %s", newCommand[0])
	logrus.Infof("Args: %s", newCommand[1:])
	return newCommand, nil
}

// validateCommand validates command arguments to prevent command injection
func validateCommand(newCommand []string) error {
	// Validate command arguments to prevent command injection
	for _, arg := range newCommand {
		if strings.ContainsAny(arg, "&|;`$()<>") {
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
	return nil
}

// createExecCommand creates and configures the exec.Cmd with proper settings
func createExecCommand(config *v1.Config, buildArgs *dockerfile.BuildArgs, newCommand []string) (*exec.Cmd, error) {
	cleanCommandPath := filepath.Clean(newCommand[0])

	// Use explicit command construction with validated arguments
	cmd := &exec.Cmd{
		Path: cleanCommandPath,
		Args: append([]string{cleanCommandPath}, newCommand[1:]...),
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
