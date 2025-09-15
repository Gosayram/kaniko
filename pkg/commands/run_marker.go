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

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/dockerfile"
	"github.com/Gosayram/kaniko/pkg/util"
)

// RunMarkerCommand represents a specialized RUN command that tracks file system changes
// by creating markers and detecting modified files during execution
type RunMarkerCommand struct {
	BaseCommand
	cmd      *instructions.RunCommand
	Files    []string
	shdCache bool
}

// ExecuteCommand runs the RUN command and tracks file system changes by comparing
// the state before and after command execution
func (r *RunMarkerCommand) ExecuteCommand(config *v1.Config, buildArgs *dockerfile.BuildArgs) error {
	// run command `touch filemarker`
	logrus.Debugf("Using new RunMarker command")
	prevFilesMap, _ := util.GetFSInfoMap("/", map[string]os.FileInfo{})
	if err := runCommandInExec(config, buildArgs, r.cmd); err != nil {
		return err
	}
	_, r.Files = util.GetFSInfoMap("/", prevFilesMap)

	logrus.Debugf("Files changed %s", r.Files)
	return nil
}

// String returns some information about the command for the image config
func (r *RunMarkerCommand) String() string {
	return r.cmd.String()
}

// FilesToSnapshot returns the list of files that were modified during command execution
// and should be included in the filesystem snapshot
func (r *RunMarkerCommand) FilesToSnapshot() []string {
	return r.Files
}

// ProvidesFilesToSnapshot indicates whether this command provides files for snapshotting
func (r *RunMarkerCommand) ProvidesFilesToSnapshot() bool {
	return true
}

// IsArgsEnvsRequiredInCache indicates whether command arguments and environment variables
// should be considered for cache key generation
func (r *RunMarkerCommand) IsArgsEnvsRequiredInCache() bool {
	return true
}

// CacheCommand creates a caching version of this RUN command for efficient
// layer caching and reuse in subsequent builds
func (r *RunMarkerCommand) CacheCommand(img v1.Image) DockerCommand {
	return &CachingRunCommand{
		img:       img,
		cmd:       r.cmd,
		extractFn: util.ExtractFile,
	}
}

// MetadataOnly indicates whether this command only affects metadata without
// modifying the filesystem contents
func (r *RunMarkerCommand) MetadataOnly() bool {
	return false
}

// RequiresUnpackedFS indicates whether this command requires an unpacked
// filesystem to execute properly
func (r *RunMarkerCommand) RequiresUnpackedFS() bool {
	return true
}

// ShouldCacheOutput indicates whether the output of this command should be cached
func (r *RunMarkerCommand) ShouldCacheOutput() bool {
	return r.shdCache
}

// ShouldDetectDeletedFiles indicates whether this command should detect and track
// files that were deleted during execution
func (r *RunMarkerCommand) ShouldDetectDeletedFiles() bool {
	return true
}
