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
	"os"

	"github.com/pkg/errors"

	"github.com/Gosayram/kaniko/pkg/dockerfile"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/util"
)

// WorkdirCommand represents the WORKDIR Dockerfile instruction
// which sets the working directory for subsequent instructions
type WorkdirCommand struct {
	BaseCommand
	cmd           *instructions.WorkdirCommand
	snapshotFiles []string
}

// For testing
var mkdirAllWithPermissions = util.MkdirAllWithPermissions

// ExecuteCommand processes the WORKDIR instruction by setting the working directory
// and creating the directory if it doesn't exist with appropriate permissions
func (w *WorkdirCommand) ExecuteCommand(config *v1.Config, buildArgs *dockerfile.BuildArgs) error {
	// Use common helper for setup
	helper := NewCommonCommandHelper()
	helper.LogCommandExecution("workdir")

	workdirPath := w.cmd.Path
	replacementEnvs := buildArgs.ReplacementEnvs(config.Env)

	// Resolve working directory using common helper
	resolvedWorkingDir, err := helper.ResolveWorkingDirectory(workdirPath, config.WorkingDir, replacementEnvs)
	if err != nil {
		return err
	}

	config.WorkingDir = resolvedWorkingDir
	logrus.Infof("Changed working directory to %s", config.WorkingDir)

	// Only create and snapshot the dir if it didn't exist already
	w.snapshotFiles = []string{}
	if _, err := os.Stat(config.WorkingDir); os.IsNotExist(err) {
		// Get user and group using common helper
		uid, gid, err := helper.GetUserGroupFromConfig(config, replacementEnvs)
		if err != nil {
			return err
		}

		logrus.Infof("Creating directory %s with uid %d and gid %d", config.WorkingDir, uid, gid)
		w.snapshotFiles = append(w.snapshotFiles, config.WorkingDir)

		// Create directory using common helper
		if err := helper.CreateDirectoryWithPermissions(config.WorkingDir, 0o755, uid, gid); err != nil {
			return errors.Wrapf(err, "creating workdir %s", config.WorkingDir)
		}
	}
	return nil
}

// FilesToSnapshot returns the workingdir, which should have been created if it didn't already exist
func (w *WorkdirCommand) FilesToSnapshot() []string {
	return w.snapshotFiles
}

// String returns some information about the command for the image config history
func (w *WorkdirCommand) String() string {
	return w.cmd.String()
}

// MetadataOnly indicates whether this command only affects metadata without
// modifying the filesystem contents
func (w *WorkdirCommand) MetadataOnly() bool {
	return false
}
