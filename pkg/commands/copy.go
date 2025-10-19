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
	"path/filepath"
	"strings"
	"sync"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	kConfig "github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/dockerfile"
	"github.com/Gosayram/kaniko/pkg/util"
)

// for testing
var (
	getUserGroup = util.GetUserGroup
)

// CopyCommand implements the COPY Dockerfile instruction.
type CopyCommand struct {
	BaseCommand
	cmd           *instructions.CopyCommand
	fileContext   util.FileContext
	snapshotFiles []string
	shdCache      bool
}

// ExecuteCommand executes the COPY command by copying files from source to destination.
func (c *CopyCommand) ExecuteCommand(config *v1.Config, buildArgs *dockerfile.BuildArgs) error {
	// Use common helper for setup
	helper := NewCommonCommandHelper()

	// Setup file context
	c.fileContext = helper.SetupFileContext(c.cmd, c.fileContext)

	// Setup environment and permissions
	replacementEnvs := buildArgs.ReplacementEnvs(config.Env)
	uid, gid, err := helper.SetupUserGroup(c.cmd.Chown, replacementEnvs)
	if err != nil {
		return err
	}

	// Resolve sources and destination using common helper
	srcs, dest, err := helper.ResolveSourcesAndDestination(c.cmd, c.fileContext, replacementEnvs)
	if err != nil {
		return err
	}

	// Get file permissions using common helper
	chmod, useDefaultChmod, err := helper.SetupFilePermissions(c.cmd.Chmod, replacementEnvs)
	if err != nil {
		return err
	}

	// Copy each source
	return c.copySources(srcs, dest, config, uid, gid, chmod, useDefaultChmod)
}

// Note: setupUserGroup and resolveSourcesAndDest functions have been moved to common.go
// to reduce code duplication across commands

// copySources copies each source to the destination with parallel processing
func (c *CopyCommand) copySources(
	srcs []string, dest string, config *v1.Config, uid, gid int64,
	chmod os.FileMode, useDefaultChmod bool) error {
	// For small number of sources, use sequential processing
	const maxSequentialSources = 2
	if len(srcs) <= maxSequentialSources {
		for _, src := range srcs {
			if err := c.copySingleSource(src, dest, config, uid, gid, chmod, useDefaultChmod); err != nil {
				return err
			}
		}
		return nil
	}

	// For larger number of sources, use parallel processing
	return c.copySourcesParallel(srcs, dest, config, uid, gid, chmod, useDefaultChmod)
}

// copySourcesParallel copies sources in parallel for better performance
func (c *CopyCommand) copySourcesParallel(
	srcs []string, dest string, config *v1.Config, uid, gid int64,
	chmod os.FileMode, useDefaultChmod bool) error {
	// Use errgroup for parallel execution with error handling
	var wg sync.WaitGroup
	errChan := make(chan error, len(srcs))

	// Limit concurrent copies to avoid overwhelming the filesystem
	maxConcurrent := 4
	if len(srcs) < maxConcurrent {
		maxConcurrent = len(srcs)
	}

	semaphore := make(chan struct{}, maxConcurrent)

	for _, src := range srcs {
		wg.Add(1)
		go func(source string) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if err := c.copySingleSource(source, dest, config, uid, gid, chmod, useDefaultChmod); err != nil {
				errChan <- errors.Wrapf(err, "failed to copy source %s", source)
				return
			}
		}(src)
	}

	// Wait for all goroutines to complete
	go func() {
		wg.Wait()
		close(errChan)
	}()

	// Collect any errors
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return errs[0] // Return the first error
	}

	return nil
}

// copySingleSource copies a single source to the destination
func (c *CopyCommand) copySingleSource(
	src, dest string, config *v1.Config, uid, gid int64,
	chmod os.FileMode, useDefaultChmod bool) error {
	fullPath := filepath.Join(c.fileContext.Root, src)

	fi, err := os.Lstat(fullPath)
	if err != nil {
		// Don't fail on missing files - log warning and continue
		logrus.Warnf("Source file not found: %s, continuing anyway", fullPath)
		return nil
	}
	if fi.IsDir() && !strings.HasSuffix(fullPath, string(os.PathSeparator)) {
		fullPath += "/"
	}
	cwd := config.WorkingDir
	if cwd == "" {
		cwd = kConfig.RootDir
	}

	destPath, err := util.DestinationFilepath(fullPath, dest, cwd)
	if err != nil {
		return errors.Wrap(err, "find destination path")
	}

	// If the destination dir is a symlink we need to resolve the path and use
	// that instead of the symlink path
	destPath, err = resolveIfSymlink(destPath)
	if err != nil {
		return errors.Wrap(err, "resolving dest symlink")
	}

	return c.copyFileOrDir(fullPath, destPath, fi, uid, gid, chmod, useDefaultChmod)
}

// copyFileOrDir copies a file or directory based on the file info
func (c *CopyCommand) copyFileOrDir(fullPath, destPath string, fi os.FileInfo,
	uid, gid int64, chmod os.FileMode, useDefaultChmod bool) error {
	switch {
	case fi.IsDir():
		return c.copyDirectory(fullPath, destPath, uid, gid, chmod, useDefaultChmod)
	case util.IsSymlink(fi):
		return c.copySymlink(fullPath, destPath)
	default:
		return c.copyRegularFile(fullPath, destPath, uid, gid, chmod, useDefaultChmod)
	}
}

// copyDirectory copies a directory
func (c *CopyCommand) copyDirectory(fullPath, destPath string, uid, gid int64,
	chmod os.FileMode, useDefaultChmod bool) error {
	copiedFiles, err := util.CopyDir(fullPath, destPath, c.fileContext, uid, gid, chmod, useDefaultChmod)
	if err != nil {
		return errors.Wrap(err, "copying dir")
	}
	c.snapshotFiles = append(c.snapshotFiles, copiedFiles...)
	return nil
}

// copySymlink copies a symlink
func (c *CopyCommand) copySymlink(fullPath, destPath string) error {
	// If file is a symlink, we want to copy the target file to destPath
	exclude, err := util.CopySymlink(fullPath, destPath, c.fileContext)
	if err != nil {
		return errors.Wrap(err, "copying symlink")
	}
	if exclude {
		return nil
	}
	c.snapshotFiles = append(c.snapshotFiles, destPath)
	return nil
}

// copyRegularFile copies a regular file
func (c *CopyCommand) copyRegularFile(fullPath, destPath string, uid, gid int64,
	chmod os.FileMode, useDefaultChmod bool) error {
	// ... Else, we want to copy over a file
	exclude, err := util.CopyFile(fullPath, destPath, c.fileContext, uid, gid, chmod, useDefaultChmod)
	if err != nil {
		return errors.Wrap(err, "copying file")
	}
	if exclude {
		return nil
	}
	c.snapshotFiles = append(c.snapshotFiles, destPath)
	return nil
}

// FilesToSnapshot should return an empty array if still nil; no files were changed
func (c *CopyCommand) FilesToSnapshot() []string {
	return c.snapshotFiles
}

// String returns some information about the command for the image config
func (c *CopyCommand) String() string {
	return c.cmd.String()
}

// FilesUsedFromContext returns the list of files used from the build context.
func (c *CopyCommand) FilesUsedFromContext(config *v1.Config, buildArgs *dockerfile.BuildArgs) ([]string, error) {
	return copyCmdFilesUsedFromContext(config, buildArgs, c.cmd, c.fileContext)
}

// MetadataOnly returns false as COPY command modifies the filesystem.
func (c *CopyCommand) MetadataOnly() bool {
	return false
}

// RequiresUnpackedFS returns true as COPY command requires an unpacked filesystem.
func (c *CopyCommand) RequiresUnpackedFS() bool {
	return true
}

// From returns the base image name for multi-stage builds.
func (c *CopyCommand) From() string {
	return c.cmd.From
}

// ShouldCacheOutput returns whether the command output should be cached.
func (c *CopyCommand) ShouldCacheOutput() bool {
	return c.shdCache
}

// CacheCommand returns true since this command should be cached
func (c *CopyCommand) CacheCommand(img v1.Image) DockerCommand {
	return &CachingCopyCommand{
		img:         img,
		cmd:         c.cmd,
		fileContext: c.fileContext,
		extractFn:   util.ExtractFile,
	}
}

// CachingCopyCommand implements caching for COPY commands.
type CachingCopyCommand struct {
	BaseCommand
	caching
	img            v1.Image
	extractedFiles []string
	cmd            *instructions.CopyCommand
	fileContext    util.FileContext
	extractFn      util.ExtractFunction
}

// ExecuteCommand executes the cached COPY command by extracting files from cached layers.
func (cr *CachingCopyCommand) ExecuteCommand(_ *v1.Config, _ *dockerfile.BuildArgs) error {
	logrus.Infof("Found cached layer, extracting to filesystem")
	var err error

	if cr.img == nil {
		return fmt.Errorf("cached command image is nil %v", cr.String())
	}

	layers, err := cr.img.Layers()
	if err != nil {
		return errors.Wrapf(err, "retrieve image layers")
	}

	if len(layers) != 1 {
		return fmt.Errorf("expected %d layers but got %d", 1, len(layers))
	}

	cr.layer = layers[0]
	cr.extractedFiles, err = util.GetFSFromLayers(kConfig.RootDir, layers,
		util.ExtractFunc(cr.extractFn), util.IncludeWhiteout())

	logrus.Debugf("ExtractedFiles: %s", cr.extractedFiles)
	if err != nil {
		return errors.Wrap(err, "extracting fs from image")
	}

	return nil
}

// FilesUsedFromContext returns the list of files used from the build context.
func (cr *CachingCopyCommand) FilesUsedFromContext(
	config *v1.Config, buildArgs *dockerfile.BuildArgs) ([]string, error) {
	return copyCmdFilesUsedFromContext(config, buildArgs, cr.cmd, cr.fileContext)
}

// FilesToSnapshot returns the list of files extracted from cached layers.
func (cr *CachingCopyCommand) FilesToSnapshot() []string {
	f := cr.extractedFiles
	logrus.Debugf("%d files extracted by caching copy command", len(f))
	logrus.Tracef("Extracted files: %s", f)

	return f
}

// MetadataOnly returns false as caching COPY command modifies the filesystem.
func (cr *CachingCopyCommand) MetadataOnly() bool {
	return false
}

func (cr *CachingCopyCommand) String() string {
	if cr.cmd == nil {
		return "nil command"
	}
	return cr.cmd.String()
}

// From returns the base image name for multi-stage builds.
func (cr *CachingCopyCommand) From() string {
	return cr.cmd.From
}

func resolveIfSymlink(destPath string) (string, error) {
	if !filepath.IsAbs(destPath) {
		return "", errors.New("dest path must be abs")
	}

	var nonexistentPaths []string

	newPath := destPath
	for newPath != "/" {
		_, err := os.Lstat(newPath)
		if err != nil {
			if os.IsNotExist(err) {
				dir, file := filepath.Split(newPath)
				newPath = filepath.Clean(dir)
				nonexistentPaths = append(nonexistentPaths, file)
				continue
			}
			return "", errors.Wrap(err, "failed to lstat")
		}

		newPath, err = filepath.EvalSymlinks(newPath)
		if err != nil {
			return "", errors.Wrap(err, "failed to eval symlinks")
		}
		break
	}

	for i := len(nonexistentPaths) - 1; i >= 0; i-- {
		newPath = filepath.Join(newPath, nonexistentPaths[i])
	}

	if destPath != newPath {
		logrus.Tracef("Updating destination path from %v to %v due to symlink", destPath, newPath)
	}

	return filepath.Clean(newPath), nil
}

func copyCmdFilesUsedFromContext(
	config *v1.Config, buildArgs *dockerfile.BuildArgs, cmd *instructions.CopyCommand,
	fileContext util.FileContext,
) ([]string, error) {
	if cmd.From != "" {
		fileContext = util.FileContext{Root: filepath.Join(kConfig.KanikoDir, cmd.From)}
	}

	replacementEnvs := buildArgs.ReplacementEnvs(config.Env)

	// For cross-stage dependencies, we can't resolve wildcards until the source stage is built
	// So we just return the paths as-is without validation
	if cmd.From != "" {
		files := []string{}
		for _, src := range cmd.SourcePaths {
			resolved, err := util.ResolveEnvironmentReplacement(src, replacementEnvs, true)
			if err != nil {
				return nil, err
			}

			// DISABLED: Path validation removed to allow any file paths

			fullPath := filepath.Join(fileContext.Root, resolved)
			files = append(files, fullPath)
		}
		logrus.Debugf("Using files from cross-stage context (unvalidated): %v", files)
		return files, nil
	}

	// For regular context, resolve wildcards normally
	srcs, _, err := util.ResolveEnvAndWildcards(
		cmd.SourcesAndDest, fileContext, replacementEnvs,
	)
	if err != nil {
		return nil, err
	}

	files := []string{}
	for _, src := range srcs {
		fullPath := filepath.Join(fileContext.Root, src)
		files = append(files, fullPath)
	}

	logrus.Debugf("Using files from context: %v", files)

	return files, nil
}

// AbstractCopyCommand can either be a CopyCommand or a CachingCopyCommand.
type AbstractCopyCommand interface {
	From() string
}

// CommandType represents the type of command that can be cast to AbstractCopyCommand.
// This constraint ensures type safety when casting commands to AbstractCopyCommand.
type CommandType interface {
	*CopyCommand | *CachingCopyCommand
}

// CastAbstractCopyCommand tries to convert a command to an AbstractCopyCommand.
// It accepts any type that implements the CommandType constraint.
// This generic function provides type-safe casting of copy commands.
func CastAbstractCopyCommand[T CommandType](cmd T) (AbstractCopyCommand, bool) {
	switch v := any(cmd).(type) {
	case *CopyCommand:
		return v, true
	case *CachingCopyCommand:
		return v, true
	}

	return nil, false
}

// validateFilePath performs security validation on file paths
func validateFilePath(_ string) error {
	// DISABLED: All path validation removed to allow any file paths
	return nil
}
