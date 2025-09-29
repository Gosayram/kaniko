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
	// Resolve from
	if c.cmd.From != "" {
		c.fileContext = util.FileContext{Root: filepath.Join(kConfig.KanikoDir, c.cmd.From)}
	}

	// Setup environment and permissions
	replacementEnvs := buildArgs.ReplacementEnvs(config.Env)
	uid, gid, err := c.setupUserGroup(replacementEnvs)
	if err != nil {
		return err
	}

	// Resolve sources and destination
	srcs, dest, err := c.resolveSourcesAndDest(replacementEnvs)
	if err != nil {
		return err
	}

	// Get file permissions
	chmod, useDefaultChmod, err := util.GetChmod(c.cmd.Chmod, replacementEnvs)
	if err != nil {
		return errors.Wrap(err, "getting permissions from chmod")
	}

	// Copy each source
	return c.copySources(srcs, dest, config, uid, gid, chmod, useDefaultChmod)
}

// setupUserGroup sets up the user and group for the copy operation
func (c *CopyCommand) setupUserGroup(replacementEnvs []string) (uid, gid int64, err error) {
	uid, gid, err = getUserGroup(c.cmd.Chown, replacementEnvs)
	logrus.Debugf("found uid %v and gid %v for chown string %v", uid, gid, c.cmd.Chown)
	if err != nil {
		return 0, 0, errors.Wrap(err, "getting user group from chown")
	}
	return uid, gid, nil
}

// resolveSourcesAndDest resolves sources and destination paths
func (c *CopyCommand) resolveSourcesAndDest(
	replacementEnvs []string) (sources []string, destination string, err error) {
	// sources from the Copy command are resolved with wildcards {*?[}
	sources, destination, err = util.ResolveEnvAndWildcards(c.cmd.SourcesAndDest, c.fileContext, replacementEnvs)
	if err != nil {
		return nil, "", errors.Wrap(err, "resolving src")
	}
	return sources, destination, nil
}

// copySources copies each source to the destination
func (c *CopyCommand) copySources(
	srcs []string, dest string, config *v1.Config, uid, gid int64,
	chmod os.FileMode, useDefaultChmod bool) error {
	for _, src := range srcs {
		if err := c.copySingleSource(src, dest, config, uid, gid, chmod, useDefaultChmod); err != nil {
			return err
		}
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
		return errors.Wrap(err, "could not copy source")
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

// CastAbstractCopyCommand tries to convert a command to an AbstractCopyCommand.
func CastAbstractCopyCommand(cmd interface{}) (AbstractCopyCommand, bool) {
	switch v := cmd.(type) {
	case *CopyCommand:
		return v, true
	case *CachingCopyCommand:
		return v, true
	}

	return nil, false
}
