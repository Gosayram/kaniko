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
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/Gosayram/kaniko/pkg/dockerfile"
)

// BaseCommand provides the base implementation for all Docker command types
// with default implementations for common methods used by specific commands
type BaseCommand struct {
}

// IsArgsEnvsRequiredInCache indicates whether command arguments and environment
// variables should be considered for cache key generation (default: false)
func (b *BaseCommand) IsArgsEnvsRequiredInCache() bool {
	return false
}

// CacheCommand creates a caching version of the command for efficient
// layer caching and reuse in subsequent builds (default: nil)
func (b *BaseCommand) CacheCommand(v1.Image) DockerCommand {
	return nil
}

// FilesToSnapshot returns the list of files that were modified during
// command execution and should be included in the filesystem snapshot (default: empty)
func (b *BaseCommand) FilesToSnapshot() []string {
	return []string{}
}

// ProvidesFilesToSnapshot indicates whether this command provides files
// for snapshotting (default: true)
func (b *BaseCommand) ProvidesFilesToSnapshot() bool {
	return true
}

// FilesUsedFromContext returns the list of files from the build context
// that are used by this command (default: empty)
func (b *BaseCommand) FilesUsedFromContext(_ *v1.Config, _ *dockerfile.BuildArgs) ([]string, error) {
	return []string{}, nil
}

// MetadataOnly indicates whether this command only affects metadata
// without modifying the filesystem contents (default: true)
func (b *BaseCommand) MetadataOnly() bool {
	return true
}

// RequiresUnpackedFS indicates whether this command requires an unpacked
// filesystem to execute properly (default: false)
func (b *BaseCommand) RequiresUnpackedFS() bool {
	return false
}

// ShouldCacheOutput indicates whether the output of this command
// should be cached (default: false)
func (b *BaseCommand) ShouldCacheOutput() bool {
	return false
}

// ShouldDetectDeletedFiles indicates whether this command should detect
// and track files that were deleted during execution (default: false)
func (b *BaseCommand) ShouldDetectDeletedFiles() bool {
	return false
}
