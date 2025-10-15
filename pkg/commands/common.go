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
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/dockerfile"
	"github.com/Gosayram/kaniko/pkg/util"
)

// CommonCommandHelper provides common functionality for all commands
type CommonCommandHelper struct{}

// NewCommonCommandHelper creates a new common command helper
func NewCommonCommandHelper() *CommonCommandHelper {
	return &CommonCommandHelper{}
}

// SetupUserGroup sets up user and group from chown string with common error handling
func (h *CommonCommandHelper) SetupUserGroup(chown string, replacementEnvs []string) (uid, gid int64, err error) {
	uid, gid, err = getUserGroup(chown, replacementEnvs)
	if err != nil {
		return 0, 0, errors.Wrap(err, "getting user group from chown")
	}
	logrus.Debugf("found uid %v and gid %v for chown string %v", uid, gid, chown)
	return uid, gid, nil
}

// ResolveUserFromConfig resolves user from config with common error handling
func (h *CommonCommandHelper) ResolveUserFromConfig(
	cfg *v1.Config, buildArgs *dockerfile.BuildArgs) (userStr string, err error) {
	replacementEnvs := buildArgs.ReplacementEnvs(cfg.Env)
	u := cfg.User
	userAndGroup := strings.Split(u, ":")

	userStr, err = util.ResolveEnvironmentReplacement(userAndGroup[0], replacementEnvs, false)
	if err != nil {
		return "", errors.Wrapf(err, "resolving user %s", userAndGroup[0])
	}

	if len(userAndGroup) > 1 {
		groupStr, err := util.ResolveEnvironmentReplacement(userAndGroup[1], replacementEnvs, false)
		if err != nil {
			return "", errors.Wrapf(err, "resolving group %s", userAndGroup[1])
		}
		userStr = userStr + ":" + groupStr
	}

	return userStr, nil
}

// ResolveEnvironmentVariable resolves a single environment variable with common error handling
func (h *CommonCommandHelper) ResolveEnvironmentVariable(
	value string, replacementEnvs []string, allowEmpty bool) (string, error) {
	return util.ResolveEnvironmentReplacement(value, replacementEnvs, allowEmpty)
}

// CreateDirectoryWithPermissions creates a directory with proper permissions and user/group ownership
func (h *CommonCommandHelper) CreateDirectoryWithPermissions(path string, mode os.FileMode, uid, gid int64) error {
	return util.MkdirAllWithPermissions(path, mode, uid, gid)
}

// ValidatePath validates a path to prevent directory traversal and other security issues
func (h *CommonCommandHelper) ValidatePath(path string) error {
	return util.ValidateFilePath(path)
}

// ResolveWorkingDirectory resolves working directory path with proper handling of absolute/relative paths
func (h *CommonCommandHelper) ResolveWorkingDirectory(
	workdirPath, currentWorkingDir string, replacementEnvs []string) (string, error) {
	resolvedWorkingDir, err := util.ResolveEnvironmentReplacement(workdirPath, replacementEnvs, true)
	if err != nil {
		return "", err
	}

	if filepath.IsAbs(resolvedWorkingDir) {
		return resolvedWorkingDir, nil
	}

	if currentWorkingDir != "" {
		return filepath.Join(currentWorkingDir, resolvedWorkingDir), nil
	}

	return "/" + resolvedWorkingDir, nil
}

// GetUserGroupFromConfig gets user and group from config with common error handling
func (h *CommonCommandHelper) GetUserGroupFromConfig(
	cfg *v1.Config, replacementEnvs []string) (uid, gid int64, err error) {
	if cfg.User == "" {
		return -1, -1, nil
	}

	logrus.Debugf("Fetching uid and gid for USER '%s'", cfg.User)
	uid, gid, err = util.GetUserGroup(cfg.User, replacementEnvs)
	if err != nil {
		return 0, 0, errors.Wrapf(err, "identifying uid and gid for user %s", cfg.User)
	}

	return uid, gid, nil
}

// SetupFilePermissions sets up file permissions with common error handling
func (h *CommonCommandHelper) SetupFilePermissions(
	chmod string, replacementEnvs []string) (mode os.FileMode, useDefault bool, err error) {
	return util.GetChmod(chmod, replacementEnvs)
}

// LogCommandExecution logs command execution with common format
func (h *CommonCommandHelper) LogCommandExecution(cmdName string, details ...string) {
	logrus.Infof("Cmd: %s", cmdName)
	for i, detail := range details {
		if i == 0 {
			logrus.Infof("Details: %s", detail)
		} else {
			logrus.Debugf("Additional detail: %s", detail)
		}
	}
}

// HandleCommandError handles command errors with common error wrapping
func (h *CommonCommandHelper) HandleCommandError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return errors.Wrapf(err, "failed to %s", operation)
}

// ValidateCommandArguments validates command arguments for security
func (h *CommonCommandHelper) ValidateCommandArguments(args []string) error {
	for _, arg := range args {
		if strings.ContainsAny(arg, "&|;`$()<>") {
			return errors.Errorf("invalid character in command argument: %q", arg)
		}
		if strings.Contains(arg, "../") || strings.Contains(arg, "~/") {
			return errors.Errorf("potentially dangerous path pattern in command argument: %q", arg)
		}
	}
	return nil
}

// ResolveSourcesAndDestination resolves sources and destination with common error handling
func (h *CommonCommandHelper) ResolveSourcesAndDestination(
	cmd *instructions.CopyCommand,
	fileContext util.FileContext,
	replacementEnvs []string) (sources []string, destination string, err error) {
	sources, destination, err = util.ResolveEnvAndWildcards(cmd.SourcesAndDest, fileContext, replacementEnvs)
	if err != nil {
		return nil, "", errors.Wrap(err, "resolving src")
	}
	return sources, destination, nil
}

// SetupFileContext sets up file context for commands that need it
func (h *CommonCommandHelper) SetupFileContext(
	cmd *instructions.CopyCommand, fileContext util.FileContext) util.FileContext {
	if cmd.From != "" {
		return util.FileContext{Root: filepath.Join(config.KanikoDir, cmd.From)}
	}
	return fileContext
}

// CommonCommandInterface defines common interface for all commands
type CommonCommandInterface interface {
	ExecuteCommand(config *v1.Config, buildArgs *dockerfile.BuildArgs) error
	String() string
	FilesToSnapshot() []string
	FilesUsedFromContext(config *v1.Config, buildArgs *dockerfile.BuildArgs) ([]string, error)
	MetadataOnly() bool
	RequiresUnpackedFS() bool
}

// BaseCommandExecutor provides common execution patterns for commands
type BaseCommandExecutor struct {
	helper *CommonCommandHelper
}

// NewBaseCommandExecutor creates a new base command executor
func NewBaseCommandExecutor() *BaseCommandExecutor {
	return &BaseCommandExecutor{
		helper: NewCommonCommandHelper(),
	}
}

// GetHelper returns the common command helper
func (e *BaseCommandExecutor) GetHelper() *CommonCommandHelper {
	return e.helper
}

// ExecuteWithErrorHandling executes a function with common error handling
func (e *BaseCommandExecutor) ExecuteWithErrorHandling(operation string, fn func() error) error {
	if err := fn(); err != nil {
		return e.helper.HandleCommandError(operation, err)
	}
	return nil
}

// LogExecution logs command execution with common format
func (e *BaseCommandExecutor) LogExecution(cmdName string, details ...string) {
	e.helper.LogCommandExecution(cmdName, details...)
}
