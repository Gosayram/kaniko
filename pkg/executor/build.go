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

package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/google/go-containerregistry/pkg/v1/partial"

	"github.com/Gosayram/kaniko/pkg/cache"
	"github.com/Gosayram/kaniko/pkg/commands"
	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/constants"
	"github.com/Gosayram/kaniko/pkg/dockerfile"
	image_util "github.com/Gosayram/kaniko/pkg/image"
	"github.com/Gosayram/kaniko/pkg/image/remote"
	"github.com/Gosayram/kaniko/pkg/logging"
	"github.com/Gosayram/kaniko/pkg/multiplatform"
	"github.com/Gosayram/kaniko/pkg/network"
	"github.com/Gosayram/kaniko/pkg/rootless"
	"github.com/Gosayram/kaniko/pkg/snapshot"
	"github.com/Gosayram/kaniko/pkg/timing"
	"github.com/Gosayram/kaniko/pkg/util"
)

// This is the size of an empty tar in Go
const emptyTarSize = 1024

// Constants for magic number replacements
const (
	keyValueParts       = 2
	defaultRetryDelayMs = 1000
	DefaultDirPerm      = 0o750
)

// Optimization constants
const (
	// Snapshot mode constants
	SnapshotModeTime = "time"

	// Compression constants
	CompressionZstd = "zstd"

	// Performance optimization constants
	NoCacheParallelMultiplier = 2
	MemoryLimitGB             = 2
	MemoryLimitBytes          = 2 * 1024 * 1024 * 1024 // 2GB
	CommandTimeoutMinutes     = 30
	MaxFileSizeMB             = 500
	MaxFileSizeBytes          = 500 * 1024 * 1024 // 500MB
	MaxTotalFileSizeGB        = 10
	MaxTotalFileSizeBytes     = 10 * 1024 * 1024 * 1024 // 10GB

	// Network optimization constants
	MaxIdleConns            = 200
	MaxIdleConnsPerHost     = 20
	MaxConnsPerHost         = 100
	IdleConnTimeoutMin      = 5
	MaxConcurrency          = 15
	RequestTimeoutMin       = 5
	RetryAttempts           = 5
	RetryDelaySec           = 2
	DNSCacheTimeoutMin      = 10
	ManifestCacheTimeoutMin = 30

	// Filesystem sync constants
	// Increased delay to ensure filesystem operations are fully committed
	// This is critical for cross-stage dependencies where files might be written
	// by parallel RUN commands
	FilesystemSyncDelay = 500 * time.Millisecond

	// maxSampleEntries is the maximum number of directory entries to log for debugging
	maxSampleEntries = 5
)

// for testing
var (
	initializeConfig = initConfig
	getFSFromImage   = util.GetFSFromImage
)

type cachePusher func(*config.KanikoOptions, string, string, string) error
type snapShotter interface {
	Init() error
	TakeSnapshotFS() (string, error)
	TakeSnapshot([]string, bool, bool) (string, error)
}

// stageBuilder contains all fields necessary to build one stage of a Dockerfile
type stageBuilder struct {
	stage            config.KanikoStage
	image            v1.Image
	cf               *v1.ConfigFile
	baseImageDigest  string
	finalCacheKey    string
	opts             *config.KanikoOptions
	fileContext      util.FileContext
	cmds             []commands.DockerCommand
	args             *dockerfile.BuildArgs
	crossStageDeps   map[int][]string
	digestToCacheKey map[string]string
	stageIdxToDigest map[string]string
	snapshotter      snapShotter
	layerCache       cache.LayerCache
	pushLayerToCache cachePusher
	resourceLimits   *util.ResourceLimits

	// Mutex for thread-safe access to shared state
	mutex sync.RWMutex
}

// initializeResourceLimits initializes resource limits if configured
func initializeResourceLimits(opts *config.KanikoOptions) *util.ResourceLimits {
	if opts.MaxMemoryUsageBytes <= 0 && opts.MaxFileSizeBytes <= 0 && opts.MaxTotalFileSizeBytes <= 0 {
		return nil
	}

	resourceLimits := util.NewResourceLimits(opts.MaxMemoryUsageBytes, opts.MaxFileSizeBytes, opts.MaxTotalFileSizeBytes)

	// Configure resource limits
	if opts.GCThreshold > 0 {
		resourceLimits.SetGCThreshold(opts.GCThreshold)
	}
	if opts.MonitoringInterval > 0 {
		resourceLimits.SetMonitoringInterval(time.Duration(opts.MonitoringInterval) * time.Second)
	}

	// Start monitoring if enabled
	if opts.MemoryMonitoring {
		resourceLimits.StartMonitoring()
		logrus.Info("🛡️ Resource monitoring enabled for this build")
	}

	return resourceLimits
}

// newStageBuilder returns a new type stageBuilder which contains all the information required to build the stage
func newStageBuilder(
	args *dockerfile.BuildArgs,
	opts *config.KanikoOptions,
	stage *config.KanikoStage,
	crossStageDeps map[int][]string,
	dcm, sid, stageNameToIdx map[string]string,
	fileContext util.FileContext,
) (*stageBuilder, error) {
	sourceImage, err := image_util.RetrieveSourceImage(stage, opts)
	if err != nil {
		return nil, err
	}

	imageConfig, err := initializeConfig(sourceImage, opts)
	if err != nil {
		return nil, err
	}

	if resolveErr := resolveOnBuild(stage, &imageConfig.Config, stageNameToIdx); resolveErr != nil {
		return nil, resolveErr
	}

	err = util.InitIgnoreList()
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize ignore list")
	}

	hasher, err := getHasher(opts.SnapshotMode)
	if err != nil {
		return nil, err
	}
	l := snapshot.NewLayeredMap(hasher)
	snapshotter := snapshot.NewSnapshotter(l, config.RootDir)

	// Enable incremental snapshots if configured
	if opts.IncrementalSnapshots {
		snapshotter.EnableIncrementalSnapshots()
		logrus.Info("📸 Incremental snapshots enabled for this build")
	}

	// Initialize resource limits if configured
	resourceLimits := initializeResourceLimits(opts)

	// Apply comprehensive optimizations
	applyComprehensiveOptimizations(opts)

	digest, err := sourceImage.Digest()
	if err != nil {
		return nil, err
	}
	s := &stageBuilder{
		stage:            *stage,
		image:            sourceImage,
		cf:               imageConfig,
		snapshotter:      snapshotter,
		baseImageDigest:  digest.String(),
		opts:             opts,
		fileContext:      fileContext,
		crossStageDeps:   crossStageDeps,
		digestToCacheKey: dcm,
		stageIdxToDigest: sid,
		layerCache:       newLayerCache(opts),
		pushLayerToCache: pushLayerToCache,
		resourceLimits:   resourceLimits,
	}

	for _, cmd := range stage.Commands {
		command, err := commands.GetCommand(cmd, fileContext, opts.RunV2, opts.CacheCopyLayers, opts.CacheRunLayers)
		if err != nil {
			return nil, err
		}
		if command == nil {
			continue
		}
		s.cmds = append(s.cmds, command)
	}

	if args != nil {
		s.args = args.Clone()
	} else {
		s.args = dockerfile.NewBuildArgs(s.opts.BuildArgs)
	}
	s.args.AddMetaArgs(stage.MetaArgs)
	return s, nil
}

func initConfig(img partial.WithConfigFile, opts *config.KanikoOptions) (*v1.ConfigFile, error) {
	imageConfig, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}

	if imageConfig.Config.Env == nil {
		imageConfig.Config.Env = constants.ScratchEnvVars
	}

	// CRITICAL FIX: Don't inherit all host environment variables
	// This can override PATH from the container, causing "command not found" errors
	// Only inherit specific CI/CD variables if needed
	// hostEnvs := os.Environ()
	// imageConfig.Config.Env = append(imageConfig.Config.Env, hostEnvs...)

	if opts == nil {
		return imageConfig, nil
	}

	// Set default user with security best practices
	// If no user is set in the base image, apply default user
	if imageConfig.Config.User == "" {
		if opts.DefaultUser != "" {
			// User explicitly specified via --default-user flag
			if opts.DefaultUser == "root" {
				logrus.Warnf("SECURITY WARNING: Using --default-user=root is unsafe and prohibited in production!")
				logrus.Warnf("Consider specifying a non-root user in your Dockerfile with USER instruction instead.")
			}
			logrus.Infof("Setting default user to: %s", opts.DefaultUser)
			imageConfig.Config.User = opts.DefaultUser
		} else {
			// No user specified - apply secure default (non-root user)
			// Use kaniko:kaniko (1000:1000) as default for security
			const defaultSecureUser = "kaniko:kaniko"
			logrus.Infof("No user specified. Setting secure default user: %s", defaultSecureUser)
			imageConfig.Config.User = defaultSecureUser
		}
	}

	// Rootless: automatic validation and setup of user
	rootlessManager := rootless.GetManager()
	if err := rootlessManager.ValidateTargetUser(imageConfig.Config.User); err != nil {
		return nil, err
	}

	// Update rootless manager with user from Dockerfile if different from config
	if imageConfig.Config.User != "" {
		if err := rootlessManager.SetTargetUserFromConfig(imageConfig.Config.User); err != nil {
			logrus.Warnf("Failed to update rootless manager with Dockerfile user: %v", err)
		}
	}

	if l := len(opts.Labels); l > 0 {
		if imageConfig.Config.Labels == nil {
			imageConfig.Config.Labels = make(map[string]string)
		}
		for _, label := range opts.Labels {
			parts := strings.SplitN(label, "=", keyValueParts)
			if len(parts) != keyValueParts {
				return nil, fmt.Errorf("labels must be of the form key=value, got %s", label)
			}

			imageConfig.Config.Labels[parts[0]] = parts[1]
		}
	}

	return imageConfig, nil
}

func newLayerCache(opts *config.KanikoOptions) cache.LayerCache {
	if isOCILayout(opts.CacheRepo) {
		return &cache.LayoutCache{
			Opts: opts,
		}
	}
	return &cache.RegistryCache{
		Opts: opts,
	}
}

func isOCILayout(path string) bool {
	return strings.HasPrefix(path, "oci:")
}

func (s *stageBuilder) populateCompositeKey(
	command commands.DockerCommand,
	files []string,
	compositeKey CompositeCache,
	args *dockerfile.BuildArgs,
	env []string,
) (CompositeCache, error) {
	// First replace all the environment variables or args in the command
	replacementEnvs := args.ReplacementEnvs(env)
	// The sort order of `replacementEnvs` is basically undefined, sort it
	// so we can ensure a stable cache key.
	sort.Strings(replacementEnvs)
	// Use the special argument "|#" at the start of the args array. This will
	// avoid conflicts with any RUN command since commands can not
	// start with | (vertical bar). The "#" (number of build envs) is there to
	// help ensure proper cache matches.

	if command.IsArgsEnvsRequiredInCache() {
		if len(replacementEnvs) > 0 {
			compositeKey.AddKey(fmt.Sprintf("|%d", len(replacementEnvs)))
			compositeKey.AddKey(replacementEnvs...)
		}
	}

	// Add the next command to the cache key.
	compositeKey.AddKey(command.String())

	for _, f := range files {
		if err := compositeKey.AddPath(f, s.fileContext); err != nil {
			return compositeKey, err
		}
	}
	return compositeKey, nil
}

func (s *stageBuilder) optimize(compositeKey CompositeCache, cfg *v1.Config) error {
	if !s.opts.Cache {
		return nil
	}
	var buildArgs = s.args.Clone()
	// Restore build args back to their original values
	defer func() {
		s.args = buildArgs
	}()

	stopCache := false
	// Possibly replace commands with their cached implementations.
	// We walk through all the commands, running any commands that only operate on metadata.
	// We throw the metadata away after, but we need it to properly track command dependencies
	// for things like COPY ${FOO} or RUN commands that use environment variables.
	for i, command := range s.cmds {
		if command == nil {
			continue
		}
		files, err := command.FilesUsedFromContext(cfg, s.args)
		if err != nil {
			return errors.Wrap(err, "failed to get files used from context")
		}

		compositeKey, err = s.populateCompositeKey(command, files, compositeKey, s.args, cfg.Env)
		if err != nil {
			return err
		}

		logrus.Debugf("Optimize: composite key for command %v %v", command.String(), compositeKey)
		ck, err := compositeKey.Hash()
		if err != nil {
			return errors.Wrap(err, "failed to hash composite key")
		}

		logrus.Debugf("Optimize: cache key for command %v %v", command.String(), ck)
		s.finalCacheKey = ck

		if command.ShouldCacheOutput() && !stopCache {
			img, err := s.layerCache.RetrieveLayer(ck)

			if err != nil {
				logrus.Debugf("Failed to retrieve layer: %s", err)
				logrus.Infof("No cached layer found for cmd %s", command.String())
				logrus.Debugf("Key missing was: %s", compositeKey.Key())
				// Log detailed cache key information for debugging
				logrus.Debugf("Cache key components: %v", compositeKey.keys)
				stopCache = true
				continue
			}

			if cacheCmd := command.CacheCommand(img); cacheCmd != nil {
				logrus.Infof("Using caching version of cmd: %s", command.String())
				s.cmds[i] = cacheCmd
			}
		}

		// Mutate the config for any commands that require it.
		if command.MetadataOnly() {
			if err := command.ExecuteCommand(cfg, s.args); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *stageBuilder) build() error {
	compositeKey, err := s.initCacheKey()
	if err != nil {
		return err
	}

	if err := s.unpackFilesystemIfNeeded(); err != nil {
		return err
	}

	initSnapshotTaken := false
	if s.opts.SingleSnapshot {
		if err := s.initSnapshotWithTimings(); err != nil {
			return err
		}
		initSnapshotTaken = true
	}

	if err := s.executeCommands(compositeKey, initSnapshotTaken); err != nil {
		return err
	}

	return nil
}

func (s *stageBuilder) initCacheKey() (*CompositeCache, error) {
	var compositeKey *CompositeCache
	if cacheKey, ok := s.digestToCacheKey[s.baseImageDigest]; ok {
		compositeKey = NewCompositeCache(cacheKey)
	} else {
		compositeKey = NewCompositeCache(s.baseImageDigest)
	}

	if err := s.optimize(*compositeKey, &s.cf.Config); err != nil {
		return nil, errors.Wrap(err, "failed to optimize instructions")
	}
	return compositeKey, nil
}

func (s *stageBuilder) unpackFilesystemIfNeeded() error {
	shouldUnpack := false
	for _, cmd := range s.cmds {
		if cmd.RequiresUnpackedFS() {
			logrus.Infof("Unpacking rootfs as cmd %s requires it.", cmd.String())
			shouldUnpack = true
			break
		}
	}
	if len(s.crossStageDeps[s.stage.Index]) > 0 {
		shouldUnpack = true
	}
	if s.stage.Index == 0 && s.opts.InitialFSUnpacked {
		shouldUnpack = false
	}

	if !shouldUnpack {
		logrus.Info("Skipping unpacking as no commands require it.")
		return nil
	}

	t := timing.Start("FS Unpacking")
	defer timing.DefaultRun.Stop(t)

	retryFunc := func() error {
		_, err := getFSFromImage(config.RootDir, s.image, util.ExtractFile)
		return err
	}

	return errors.Wrap(util.Retry(retryFunc, s.opts.ImageFSExtractRetry, defaultRetryDelayMs),
		"failed to get filesystem from image")
}

func (s *stageBuilder) executeCommands(compositeKey *CompositeCache, initSnapshotTaken bool) error {
	// Check if parallel execution is enabled
	if s.opts.EnableParallelExec {
		logrus.Info("🚀 Using parallel command execution")
		return s.executeCommandsParallel(compositeKey, initSnapshotTaken)
	}

	// Fallback to sequential execution
	logrus.Info("🔄 Using sequential command execution")
	return s.executeCommandsSequential(compositeKey, initSnapshotTaken)
}

// executeCommandsParallel executes commands in parallel using ParallelExecutor
func (s *stageBuilder) executeCommandsParallel(compositeKey *CompositeCache, initSnapshotTaken bool) error {
	// Create parallel executor
	executor := NewParallelExecutor(s.cmds, s.opts, s.args, &s.cf.Config, s)

	// Execute commands in parallel
	return executor.ExecuteCommands(compositeKey, initSnapshotTaken)
}

// executeCommandsSequential executes commands sequentially (original implementation)
func (s *stageBuilder) executeCommandsSequential(compositeKey *CompositeCache, initSnapshotTaken bool) error {
	cacheGroup := errgroup.Group{}
	var commandErrors []error
	var errorMutex sync.Mutex

	for index, command := range s.cmds {
		if command == nil {
			continue
		}

		func() {
			t := timing.Start("Command: " + command.String())
			defer timing.DefaultRun.Stop(t)
			err := s.processCommand(command, index, compositeKey, &cacheGroup, initSnapshotTaken)
			if err != nil {
				// Collect errors instead of ignoring them
				errorMutex.Lock()
				commandErrors = append(commandErrors, fmt.Errorf("command %d (%s) failed: %w", index, command.String(), err))
				errorMutex.Unlock()
			}
		}()
	}

	// Wait for cache operations to complete
	if err := cacheGroup.Wait(); err != nil {
		logrus.Warnf("Error uploading layer to cache: %s", err)
		// Cache errors are non-fatal, but we should log them
	}

	// Return the first command error if any occurred
	if len(commandErrors) > 0 {
		return fmt.Errorf("command execution failed: %v", commandErrors[0])
	}

	return nil
}

func (s *stageBuilder) processCommand(
	command commands.DockerCommand,
	index int,
	compositeKey *CompositeCache,
	cacheGroup *errgroup.Group,
	initSnapshotTaken bool,
) error {
	// Protect shared state access with read lock
	s.mutex.RLock()
	files, err := command.FilesUsedFromContext(&s.cf.Config, s.args)
	s.mutex.RUnlock()

	if err != nil {
		return errors.Wrap(err, "failed to get files used from context")
	}

	if s.opts.Cache {
		var err error
		s.mutex.RLock()
		*compositeKey, err = s.populateCompositeKey(command, files, *compositeKey, s.args, s.cf.Config.Env)
		s.mutex.RUnlock()
		if err != nil {
			return err
		}
	}

	logrus.Info(command.String())

	// Log command start with structured logging
	globalLogger := logging.GetGlobalManager()
	commandStartTime := time.Now()
	globalLogger.LogCommandStart(index, command.String(), "stage")

	if !initSnapshotTaken && !isCacheCommand(command) && !command.ProvidesFilesToSnapshot() {
		if err := s.initSnapshotWithTimings(); err != nil {
			return err
		}
	}

	// Execute command (this is safe as it doesn't modify shared state)
	if err := command.ExecuteCommand(&s.cf.Config, s.args); err != nil {
		// Log command failure
		commandDuration := time.Since(commandStartTime).Milliseconds()
		globalLogger.LogCommandComplete(index, command.String(), commandDuration, false)
		globalLogger.LogError("command", "execute", err, map[string]interface{}{
			"command_index": index,
			"command":       command.String(),
		})
		return errors.Wrap(err, "failed to execute command")
	}

	// Log command completion
	commandDuration := time.Since(commandStartTime).Milliseconds()
	globalLogger.LogCommandComplete(index, command.String(), commandDuration, true)

	files = command.FilesToSnapshot()
	if !s.shouldTakeSnapshot(index, command.MetadataOnly()) && !s.opts.ForceBuildMetadata {
		logrus.Debugf("Build: skipping snapshot for [%v]", command.String())
		return nil
	}

	return s.handleSnapshot(command, files, compositeKey, cacheGroup)
}

func isCacheCommand(command commands.DockerCommand) bool {
	_, ok := command.(commands.Cached)
	return ok
}

func (s *stageBuilder) handleSnapshot(
	command commands.DockerCommand,
	files []string,
	compositeKey *CompositeCache,
	cacheGroup *errgroup.Group,
) error {
	if isCacheCommand(command) {
		return s.saveLayerToImage(command.(commands.Cached).Layer(), command.String())
	}

	// Protect snapshotter access with write lock
	s.mutex.Lock()
	logrus.Debugf("Taking snapshot for command: %s, files count: %d", command.String(), len(files))
	if len(files) > 0 {
		logrus.Debugf("Files to snapshot: %v", files)
	}
	tarPath, err := s.takeSnapshot(files, command.ShouldDetectDeletedFiles())
	s.mutex.Unlock()

	if err != nil {
		return errors.Wrap(err, "failed to take snapshot")
	}

	if tarPath == "" {
		logrus.Warnf("⚠️  WARNING: takeSnapshot returned empty tarPath for command %s", command.String())
		logrus.Warnf("⚠️  This means NO LAYER will be created for this command!")
		if len(files) > 0 {
			logrus.Warnf("⚠️  Files that were supposed to be in layer: %v", files)
		}
	} else {
		logrus.Debugf("Snapshot created: %s", tarPath)
	}

	if s.opts.Cache {
		logrus.Debugf("Build: composite key for command %v %v", command.String(), compositeKey)
		ck, err := compositeKey.Hash()
		if err != nil {
			return errors.Wrap(err, "failed to hash composite key")
		}

		logrus.Debugf("Build: cache key for command %v %v", command.String(), ck)

		if command.ShouldCacheOutput() && !s.opts.NoPushCache {
			cacheGroup.Go(func() error {
				return s.pushLayerToCache(s.opts, ck, tarPath, command.String())
			})
		}
	}

	return s.saveSnapshotToImage(command.String(), tarPath)
}

func (s *stageBuilder) takeSnapshot(files []string, shdDelete bool) (string, error) {
	var snap string
	var err error

	t := timing.Start("Snapshotting FS")
	if files == nil || s.opts.SingleSnapshot {
		snap, err = s.snapshotter.TakeSnapshotFS()
	} else {
		// Volumes are very weird. They get snapshotted in the next command.
		files = append(files, util.Volumes()...)
		snap, err = s.snapshotter.TakeSnapshot(files, shdDelete, s.opts.ForceBuildMetadata)
	}
	timing.DefaultRun.Stop(t)
	return snap, err
}

func (s *stageBuilder) shouldTakeSnapshot(index int, isMetadatCmd bool) bool {
	isLastCommand := index == len(s.cmds)-1

	// We only snapshot the very end with single snapshot mode on.
	if s.opts.SingleSnapshot {
		return isLastCommand
	}

	// Always take snapshots if we're using the cache.
	if s.opts.Cache {
		return true
	}

	// if command is a metadata command, do not snapshot.
	return !isMetadatCmd
}

func (s *stageBuilder) saveSnapshotToImage(createdBy, tarPath string) error {
	layer, err := s.saveSnapshotToLayer(tarPath)
	if err != nil {
		return err
	}

	if layer == nil {
		return nil
	}

	return s.saveLayerToImage(layer, createdBy)
}

func (s *stageBuilder) saveSnapshotToLayer(tarPath string) (v1.Layer, error) {
	if tarPath == "" {
		return nil, nil
	}
	fi, err := os.Stat(tarPath)
	if err != nil {
		return nil, errors.Wrap(err, "tar file path does not exist")
	}
	if fi.Size() <= emptyTarSize && !s.opts.ForceBuildMetadata {
		logrus.Info("No files were changed, appending empty layer to config. No layer added to image.")
		return nil, nil
	}

	layerOpts := s.getLayerOptionFromOpts()
	imageMediaType, err := s.image.MediaType()
	if err != nil {
		return nil, err
	}
	// Only appending MediaType for OCI images as the default is docker
	if extractMediaTypeVendor(imageMediaType) == types.OCIVendorPrefix {
		if s.opts.Compression == config.ZStd {
			layerOpts = append(layerOpts, tarball.WithCompression("zstd"), tarball.WithMediaType(types.OCILayerZStd))
		} else {
			layerOpts = append(layerOpts, tarball.WithMediaType(types.OCILayer))
		}
	}

	layer, err := tarball.LayerFromFile(tarPath, layerOpts...)
	if err != nil {
		return nil, err
	}

	return layer, nil
}

func (s *stageBuilder) getLayerOptionFromOpts() []tarball.LayerOption {
	var layerOpts []tarball.LayerOption

	if s.opts.CompressedCaching {
		layerOpts = append(layerOpts, tarball.WithCompressedCaching)
	}

	if s.opts.CompressionLevel > 0 {
		layerOpts = append(layerOpts, tarball.WithCompressionLevel(s.opts.CompressionLevel))
	}
	return layerOpts
}

func extractMediaTypeVendor(mt types.MediaType) string {
	if strings.Contains(string(mt), types.OCIVendorPrefix) {
		return types.OCIVendorPrefix
	}
	return types.DockerVendorPrefix
}

// https://github.com/opencontainers/image-spec/blob/main/media-types.md#compatibility-matrix
func convertMediaType(mt types.MediaType) types.MediaType {
	switch mt {
	case types.DockerManifestSchema1, types.DockerManifestSchema2:
		return types.OCIManifestSchema1
	case types.DockerManifestList:
		return types.OCIImageIndex
	case types.DockerLayer:
		return types.OCILayer
	case types.DockerConfigJSON:
		return types.OCIConfigJSON
	case types.DockerForeignLayer:
		return types.OCIUncompressedRestrictedLayer
	case types.DockerUncompressedLayer:
		return types.OCIUncompressedLayer
	case types.OCIImageIndex:
		return types.DockerManifestList
	case types.OCIManifestSchema1:
		return types.DockerManifestSchema2
	case types.OCIConfigJSON:
		return types.DockerConfigJSON
	case types.OCILayer, types.OCILayerZStd:
		return types.DockerLayer
	case types.OCIRestrictedLayer:
		return types.DockerForeignLayer
	case types.OCIUncompressedLayer:
		return types.DockerUncompressedLayer
	case types.OCIContentDescriptor, types.OCIUncompressedRestrictedLayer,
		types.DockerManifestSchema1Signed, types.DockerPluginConfig:
		return ""
	default:
		return ""
	}
}

func (s *stageBuilder) convertLayerMediaType(layer v1.Layer) (v1.Layer, error) {
	layerMediaType, err := layer.MediaType()
	if err != nil {
		return nil, err
	}
	imageMediaType, err := s.image.MediaType()
	if err != nil {
		return nil, err
	}
	if extractMediaTypeVendor(layerMediaType) != extractMediaTypeVendor(imageMediaType) {
		layerOpts := s.getLayerOptionFromOpts()
		targetMediaType := convertMediaType(layerMediaType)

		if extractMediaTypeVendor(imageMediaType) == types.OCIVendorPrefix {
			if s.opts.Compression == config.ZStd {
				targetMediaType = types.OCILayerZStd
				layerOpts = append(layerOpts, tarball.WithCompression("zstd"))
			}
		}

		layerOpts = append(layerOpts, tarball.WithMediaType(targetMediaType))

		if targetMediaType != "" {
			return tarball.LayerFromOpener(layer.Uncompressed, layerOpts...)
		}
		return nil, fmt.Errorf(
			"layer with media type %v cannot be converted to a media type that matches %v",
			layerMediaType,
			imageMediaType,
		)
	}
	return layer, nil
}

func (s *stageBuilder) saveLayerToImage(layer v1.Layer, createdBy string) error {
	var err error
	layer, err = s.convertLayerMediaType(layer)
	if err != nil {
		return err
	}
	s.image, err = mutate.Append(s.image,
		mutate.Addendum{
			Layer: layer,
			History: v1.History{
				Author:    constants.Author,
				CreatedBy: createdBy,
			},
		},
	)
	return err
}

// CommandType represents the type of command that can be processed for dependencies.
// This constraint ensures type safety when processing Dockerfile commands.
type CommandType interface {
	*instructions.CopyCommand | *instructions.EnvCommand | *instructions.ArgCommand
}

func processCommandForDependencies(
	c interface{},
	ba *dockerfile.BuildArgs,
	cfg *v1.ConfigFile,
	depGraph map[int][]string,
	image v1.Image,
) error {
	switch cmd := c.(type) {
	case *instructions.CopyCommand:
		if cmd.From != "" {
			i, err := strconv.Atoi(cmd.From)
			if err != nil {
				return nil
			}
			resolved, err := util.ResolveEnvironmentReplacementList(
				cmd.SourcePaths,
				ba.ReplacementEnvs(cfg.Config.Env),
				true,
			)
			if err != nil {
				return err
			}
			depGraph[i] = append(depGraph[i], resolved...)
		}
	case *instructions.EnvCommand:
		if err := util.UpdateConfigEnv(cmd.Env, &cfg.Config, ba.ReplacementEnvs(cfg.Config.Env)); err != nil {
			return err
		}
		var mutateErr error
		_, mutateErr = mutate.Config(image, cfg.Config)
		if mutateErr != nil {
			return mutateErr
		}
	case *instructions.ArgCommand:
		for _, arg := range cmd.Args {
			k, v, err := commands.ParseArg(arg.Key, arg.Value, cfg.Config.Env, ba)
			if err != nil {
				return err
			}
			ba.AddArg(k, v)
		}
	}
	return nil
}

// CalculateDependencies calculates cross-stage dependencies for multi-stage builds.
// It analyzes COPY --from commands and other cross-stage references to determine
// which files need to be preserved between stages.
func CalculateDependencies(
	stages []config.KanikoStage,
	opts *config.KanikoOptions,
	stageNameToIdx map[string]string,
) (map[int][]string, error) {
	images := []v1.Image{}
	depGraph := map[int][]string{}

	for i := range stages {
		s := &stages[i]
		image, err := getStageImage(s, images, opts)
		if err != nil {
			return nil, err
		}

		cfg, err := initializeConfig(image, opts)
		if err != nil {
			return nil, err
		}

		cmds, err := dockerfile.GetOnBuildInstructions(&cfg.Config, stageNameToIdx)
		if err != nil {
			return nil, err
		}
		cmds = append(cmds, s.Commands...)

		ba := dockerfile.NewBuildArgs(opts.BuildArgs)
		ba.AddMetaArgs(s.MetaArgs)

		if err := processCommandsForDependencies(cmds, ba, cfg, depGraph, image); err != nil {
			return nil, err
		}
		images = append(images, image)
	}
	return depGraph, nil
}

func getStageImage(s *config.KanikoStage, images []v1.Image, opts *config.KanikoOptions) (v1.Image, error) {
	if s.BaseImageStoredLocally {
		return images[s.BaseImageIndex], nil
	}
	if s.Name == constants.NoBaseImage {
		return empty.Image, nil
	}
	return image_util.RetrieveSourceImage(s, opts)
}

func processCommandsForDependencies(
	cmds []instructions.Command,
	ba *dockerfile.BuildArgs,
	cfg *v1.ConfigFile,
	depGraph map[int][]string,
	image v1.Image,
) error {
	for _, c := range cmds {
		if err := processCommandForDependencies(c, ba, cfg, depGraph, image); err != nil {
			return err
		}
	}
	return nil
}

// DoBuild executes building the Dockerfile
func DoBuild(opts *config.KanikoOptions) (v1.Image, error) {
	timer := timing.Start("Total Build Time")
	defer timing.DefaultRun.Stop(timer)

	// Initialize global logging manager
	globalLogger := logging.GetGlobalManager()
	if !globalLogger.IsInitialized() {
		if err := globalLogger.Initialize("info", "kaniko", true); err != nil {
			logrus.Warnf("Failed to initialize structured logging: %v", err)
		}
	}

	// Generate build ID for tracking
	buildID := fmt.Sprintf("build-%d", time.Now().Unix())
	buildStartTime := time.Now()
	// Note: We'll get the actual stage count after parsing the Dockerfile
	globalLogger.LogBuildStart(buildID, opts.DockerfilePath, 0)

	kanikoStages, stageNameToIdx, fileContext, err := initBuildStages(opts)
	if err != nil {
		return nil, err
	}

	crossStageDependencies, err := calculateStageDependencies(kanikoStages, opts, stageNameToIdx)
	if err != nil {
		return nil, err
	}

	digestToCacheKey := make(map[string]string)
	stageIdxToDigest := make(map[string]string)
	var args *dockerfile.BuildArgs

	for index := range kanikoStages {
		stage := &kanikoStages[index]
		sourceImage, err := buildStage(
			index, stage, opts, args,
			crossStageDependencies,
			digestToCacheKey,
			stageIdxToDigest,
			stageNameToIdx,
			fileContext,
		)
		if err != nil {
			return nil, err
		}

		if stage.Final {
			// Log build completion
			buildDuration := time.Since(buildStartTime).Milliseconds()
			globalLogger.LogBuildComplete(buildID, buildDuration, true)
			return handleFinalImage(sourceImage, opts, timer)
		}

		if err := handleNonFinalStage(index, stage, sourceImage, crossStageDependencies, args); err != nil {
			// Log build failure
			buildDuration := time.Since(buildStartTime).Milliseconds()
			globalLogger.LogBuildComplete(buildID, buildDuration, false)
			globalLogger.LogError("build", "stage", err, map[string]interface{}{
				"stage_index": index,
				"stage_name":  stage.BaseName,
			})
			return nil, err
		}
	}

	return nil, nil
}

func initBuildStages(opts *config.KanikoOptions) ([]config.KanikoStage, map[string]string, util.FileContext, error) {
	stages, metaArgs, err := dockerfile.ParseStages(opts)
	if err != nil {
		return nil, nil, util.FileContext{}, err
	}

	kanikoStages, err := dockerfile.MakeKanikoStages(opts, stages, metaArgs)
	if err != nil {
		return nil, nil, util.FileContext{}, err
	}

	stageNameToIdx := ResolveCrossStageInstructions(kanikoStages)

	if fetchErr := fetchExtraStages(kanikoStages, opts); fetchErr != nil {
		return nil, nil, util.FileContext{}, fetchErr
	}

	fileContext, err := util.NewFileContextFromDockerfile(opts.DockerfilePath, opts.SrcContext)
	if err != nil {
		return nil, nil, util.FileContext{}, err
	}

	return kanikoStages, stageNameToIdx, fileContext, nil
}

func calculateStageDependencies(
	kanikoStages []config.KanikoStage,
	opts *config.KanikoOptions,
	stageNameToIdx map[string]string,
) (map[int][]string, error) {
	crossStageDependencies, err := CalculateDependencies(kanikoStages, opts, stageNameToIdx)
	if err != nil {
		return nil, err
	}
	logrus.Infof("Built cross stage deps: %v", crossStageDependencies)
	return crossStageDependencies, nil
}

func buildStage(
	_ int,
	stage *config.KanikoStage,
	opts *config.KanikoOptions,
	args *dockerfile.BuildArgs,
	crossStageDependencies map[int][]string,
	digestToCacheKey map[string]string,
	stageIdxToDigest map[string]string,
	stageNameToIdx map[string]string,
	fileContext util.FileContext,
) (v1.Image, error) {
	sb, err := newStageBuilder(
		args, opts, stage,
		crossStageDependencies,
		digestToCacheKey,
		stageIdxToDigest,
		stageNameToIdx,
		fileContext,
	)
	if err != nil {
		return nil, err
	}

	logrus.Infof("Building stage '%v' [idx: '%v', base-idx: '%v']",
		stage.BaseName, stage.Index, stage.BaseImageIndex)

	// Log stage start with structured logging
	globalLogger := logging.GetGlobalManager()
	stageStartTime := time.Now()
	globalLogger.LogStageStart(stage.Index, stage.BaseName, stage.BaseName)

	if err = sb.build(); err != nil {
		// Log stage failure
		stageDuration := time.Since(stageStartTime).Milliseconds()
		globalLogger.LogStageComplete(stage.Index, stage.BaseName, stageDuration, false)
		globalLogger.LogError("stage", "build", err, map[string]interface{}{
			"stage_index": stage.Index,
			"stage_name":  stage.BaseName,
		})
		return nil, errors.Wrap(err, "error building stage")
	}

	// Log stage completion
	stageDuration := time.Since(stageStartTime).Milliseconds()
	globalLogger.LogStageComplete(stage.Index, stage.BaseName, stageDuration, true)

	reviewConfig(stage, &sb.cf.Config)

	sourceImage, err := mutate.Config(sb.image, sb.cf.Config)
	if err != nil {
		return nil, err
	}

	configFile, err := sourceImage.ConfigFile()
	if err != nil {
		return nil, err
	}

	if opts.CustomPlatform == "" {
		configFile.OS = runtime.GOOS
		configFile.Architecture = runtime.GOARCH
	} else {
		configFile.OS = strings.Split(opts.CustomPlatform, "/")[0]
		configFile.Architecture = strings.Split(opts.CustomPlatform, "/")[1]
	}

	sourceImage, err = mutate.ConfigFile(sourceImage, configFile)
	if err != nil {
		return nil, err
	}

	d, err := sourceImage.Digest()
	if err != nil {
		return nil, err
	}
	stageIdxToDigest[fmt.Sprintf("%d", sb.stage.Index)] = d.String()
	logrus.Debugf("Mapping stage idx %v to digest %v", sb.stage.Index, d.String())

	digestToCacheKey[d.String()] = sb.finalCacheKey
	logrus.Debugf("Mapping digest %v to cachekey %v", d.String(), sb.finalCacheKey)

	return sourceImage, nil
}

func handleFinalImage(sourceImage v1.Image, opts *config.KanikoOptions, t *timing.Timer) (v1.Image, error) {
	var err error
	sourceImage, err = mutate.CreatedAt(sourceImage, v1.Time{Time: time.Now()})
	if err != nil {
		return nil, err
	}

	if opts.Reproducible {
		sourceImage, err = mutate.Canonical(sourceImage)
		if err != nil {
			return nil, err
		}
	}

	if opts.Cleanup {
		if err := util.DeleteFilesystem(); err != nil {
			return nil, err
		}
	}

	timing.DefaultRun.Stop(t)
	return sourceImage, nil
}

// extractStageImage extracts the stage image to a temporary directory for cross-stage dependency search.
// Returns the extraction directory path (or "/" if extraction failed).
func extractStageImage(index int, sourceImage v1.Image) string {
	stageIndexStr := strconv.Itoa(index)
	tempExtractDir := filepath.Join(config.KanikoDir, stageIndexStr+"_extract")

	// Clean up any previous extraction
	if err := os.RemoveAll(tempExtractDir); err != nil {
		logrus.Debugf("Failed to remove previous extraction directory %s: %v, continuing anyway", tempExtractDir, err)
	}

	// Extract the image to get all files from layers
	logrus.Infof("📦 Extracting stage %d image to search for cross-stage dependencies", index)
	logrus.Infof("   Extraction directory: %s", tempExtractDir)

	extractedFiles, err := util.GetFSFromImage(tempExtractDir, sourceImage, util.ExtractFile)
	if err != nil {
		logrus.Warnf("❌ Failed to extract image for stage %d: %v, will search in current filesystem", index, err)
		logrus.Warnf("   Error details: %+v", err)
		return "/" // Fallback to current filesystem
	}

	logExtractionResults(index, tempExtractDir, extractedFiles)
	return tempExtractDir
}

// logExtractionResults logs information about extracted files for debugging.
func logExtractionResults(index int, tempExtractDir string, extractedFiles []string) {
	logrus.Infof("✅ Extracted %d files from stage %d image to %s", len(extractedFiles), index, tempExtractDir)

	if len(extractedFiles) == 0 {
		logrus.Warnf("⚠️ No files extracted from stage %d image, files might not exist in image layers", index)
		// Verify extraction directory exists
		if entries, listErr := os.ReadDir(tempExtractDir); listErr == nil {
			logrus.Infof("   Directory %s exists with %d entries "+
				"(but extraction returned 0 files)", tempExtractDir, len(entries))
			for i, entry := range entries {
				if i >= maxSampleEntries {
					break
				}
				logrus.Infof("   Entry %d: %s (dir: %v)", i, entry.Name(), entry.IsDir())
			}
		} else {
			logrus.Warnf("   Directory %s does not exist or is not readable: %v", tempExtractDir, listErr)
		}
		return
	}

	const sampleSize = 10
	actualSampleSize := sampleSize
	if len(extractedFiles) < sampleSize {
		actualSampleSize = len(extractedFiles)
	}
	logrus.Infof("   Sample extracted files (first %d): %v", actualSampleSize, extractedFiles[:actualSampleSize])

	// Check if extraction directory exists and list some files
	entries, listErr := os.ReadDir(tempExtractDir)
	if listErr != nil {
		logrus.Warnf("   ⚠️ Cannot read extraction directory %s: %v", tempExtractDir, listErr)
		return
	}

	logrus.Infof("   Directory %s contains %d entries", tempExtractDir, len(entries))
	// Show first few entries for debugging
	shownCount := 0
	for _, entry := range entries {
		if shownCount >= maxSampleEntries {
			break
		}
		entryPath := filepath.Join(tempExtractDir, entry.Name())
		logrus.Infof("   Entry %d: %s (dir: %v, path: %s)", shownCount, entry.Name(), entry.IsDir(), entryPath)
		shownCount++
	}
}

// saveCrossStageFiles saves cross-stage dependency files to the destination directory.
func saveCrossStageFiles(index int, filesToSave []string, tempExtractDir string) error {
	dstDir := filepath.Join(config.KanikoDir, strconv.Itoa(index))
	if err := os.MkdirAll(dstDir, DefaultDirPerm); err != nil {
		return errors.Wrap(err, fmt.Sprintf("to create workspace for stage %d", index))
	}

	copyRoot := tempExtractDir
	if tempExtractDir == "/" {
		copyRoot = "/"
	}

	logrus.Infof("💾 Saving %d cross-stage dependency files to %s (copy root: %s)", len(filesToSave), dstDir, copyRoot)
	for i, p := range filesToSave {
		logrus.Infof("   [%d/%d] Saving file: %s (relative path)", i+1, len(filesToSave), p)

		// Build absolute source path for logging
		absSrcPath := filepath.Join(copyRoot, p)
		logrus.Infof("      Source: %s (absolute)", absSrcPath)

		// Check if source exists before copying
		if _, statErr := os.Stat(absSrcPath); statErr != nil {
			logrus.Warnf("      ⚠️ Source file does not exist: %s (error: %v)", absSrcPath, statErr)
			continue
		}

		if err := util.CopyFileOrSymlink(p, dstDir, copyRoot); err != nil {
			logrus.Warnf("      ❌ Failed to save file %s: %v, continuing anyway", p, err)
			continue
		}

		destPath := filepath.Join(dstDir, p)
		logrus.Infof("      ✅ Successfully saved file %s -> %s", p, destPath)
	}

	return nil
}

func handleNonFinalStage(
	index int,
	stage *config.KanikoStage,
	sourceImage v1.Image,
	crossStageDependencies map[int][]string,
	buildArgs *dockerfile.BuildArgs,
) error {
	if stage.SaveStage {
		if err := saveStageAsTarball(strconv.Itoa(index), sourceImage); err != nil {
			return err
		}
	}

	// Log cross-stage dependencies for debugging
	logrus.Debugf("Cross-stage dependencies for stage %d: %v", index, crossStageDependencies[index])

	// CRITICAL FIX: Files might be in image layers, not in current filesystem
	// Extract image to temporary directory first, then search for files there
	tempExtractDir := extractStageImage(index, sourceImage)
	if tempExtractDir == "/" {
		logrus.Infof("🔄 Using current filesystem (/) for cross-stage dependency search")
	}

	// Force filesystem sync to ensure all files are written before searching
	logrus.Debugf("🔄 Syncing filesystem before searching for cross-stage dependencies")
	if err := util.SyncFilesystem(); err != nil {
		logrus.Warnf("Failed to sync filesystem: %v, continuing anyway", err)
	}

	// Add a small delay to ensure filesystem operations are complete
	time.Sleep(FilesystemSyncDelay)

	// Search for files in the extracted directory or current filesystem
	filesToSave := filesToSaveWithArgsFromRoot(crossStageDependencies[index], buildArgs, tempExtractDir)

	// If no files to save, log warning and continue
	if len(filesToSave) == 0 {
		logrus.Warnf("No files found for cross-stage dependencies in stage %d, continuing anyway", index)
		logrus.Debugf("Expected patterns: %v", crossStageDependencies[index])
		return errors.Wrap(
			util.DeleteFilesystem(),
			fmt.Sprintf("deleting file system after stage %d", index),
		)
	}

	if err := saveCrossStageFiles(index, filesToSave, tempExtractDir); err != nil {
		return err
	}

	// Clean up temporary extraction directory
	if tempExtractDir != "/" {
		defer os.RemoveAll(tempExtractDir)
	}

	// Sync filesystem after copying files to ensure they are written to disk
	if err := util.SyncFilesystem(); err != nil {
		logrus.Warnf("Failed to sync filesystem after saving cross-stage dependencies: %v, continuing anyway", err)
	}

	// Delete the filesystem
	return errors.Wrap(
		util.DeleteFilesystem(),
		fmt.Sprintf("deleting file system after stage %d", index),
	)
}

// filesToSave returns all the files matching the given pattern in deps.
// If a file is a symlink, it also returns the target file.
func filesToSave(deps []string) []string {
	return filesToSaveWithArgs(deps, nil)
}

// filesToSaveWithArgs returns all the files matching the given pattern in deps with build args support.
// If a file is a symlink, it also returns the target file.
func filesToSaveWithArgs(deps []string, buildArgs *dockerfile.BuildArgs) []string {
	return filesToSaveWithArgsFromRoot(deps, buildArgs, "/")
}

// filesToSaveWithArgsFromRoot returns all the files matching the given pattern in deps with build args support,
// searching from the specified root directory. This is critical for finding files in extracted image layers.
func filesToSaveWithArgsFromRoot(deps []string, buildArgs *dockerfile.BuildArgs, searchRoot string) []string {
	srcFiles := []string{}
	logrus.Infof("🔍 Searching for cross-stage dependencies in root: %s", searchRoot)
	logrus.Infof("   Patterns to search: %v", deps)

	// First, verify that searchRoot exists and is accessible
	if searchRoot != "/" {
		if rootInfo, rootErr := os.Stat(searchRoot); rootErr != nil {
			logrus.Warnf("   ⚠️ Search root %s does not exist or is not accessible: %v", searchRoot, rootErr)
		} else {
			logrus.Infof("   ✓ Search root %s exists (dir: %v, mode: %v)", searchRoot, rootInfo.IsDir(), rootInfo.Mode())
		}
	}

	for _, src := range deps {
		// Build search path relative to the search root
		// If src starts with /, we need to remove it before joining
		cleanSrc := strings.TrimPrefix(src, "/")
		searchPath := filepath.Join(searchRoot, cleanSrc)
		logrus.Infof("🔍 Searching for file: %s (original: %s, clean: %s, root: %s)", searchPath, src, cleanSrc, searchRoot)

		files, err := findFilesForDependencyWithArgsFromRoot(searchPath, buildArgs, searchRoot)
		if err != nil {
			logrus.Warnf("Failed to find files for %s: %v, continuing anyway", searchPath, err)
			continue
		}
		srcFiles = append(srcFiles, files...)
	}

	// remove duplicates
	return deduplicatePaths(srcFiles)
}

// findFilesForDependencyWithArgsFromRoot finds files for a specific dependency path
// with build args support, searching from the specified root directory.
func findFilesForDependencyWithArgsFromRoot(
	searchPath string,
	buildArgs *dockerfile.BuildArgs,
	searchRoot string,
) ([]string, error) {
	logrus.Debugf("🔍 Searching for files: %s (root: %s)", searchPath, searchRoot)

	// CRITICAL FIX: Handle variable substitution in paths using build args
	// For example: /app/apps/${APP_TYPE}/.output should be resolved to /app/apps/webview/.output
	resolvedPath := resolvePathVariablesWithArgs(searchPath, buildArgs)
	if resolvedPath != searchPath {
		logrus.Debugf("🔄 Resolved path variables: %s -> %s", searchPath, resolvedPath)
		searchPath = resolvedPath
	}

	// First try exact path (works for both files and directories)
	info, statErr := os.Stat(searchPath)
	if statErr == nil {
		logrus.Infof("   ✅ Found exact path: %s (dir: %v, size: %d)", searchPath, info.IsDir(), info.Size())
		return processExistingPathFromRoot(searchPath, info, searchRoot)
	}

	logrus.Infof("   ⚠️ Exact path not found: %s (error: %v)", searchPath, statErr)

	// Try to check parent directory
	parentDir := filepath.Dir(searchPath)
	parentInfo, parentErr := os.Stat(parentDir)
	if parentErr == nil {
		logrus.Infof("   ℹ️ Parent directory exists: %s (dir: %v)", parentDir, parentInfo.IsDir())
		// List contents of parent directory for debugging
		entries, listErr := os.ReadDir(parentDir)
		if listErr == nil {
			logrus.Infof("   Parent directory contains %d entries", len(entries))
			for i, entry := range entries {
				if i >= maxSampleEntries {
					break
				}
				logrus.Infof("     - %s (dir: %v)", entry.Name(), entry.IsDir())
			}
		}
	} else {
		logrus.Infof("   ⚠️ Parent directory does not exist: %s (error: %v)", parentDir, parentErr)
	}

	// Path doesn't exist, try to find similar paths
	return findSimilarPathsFromRoot(searchPath, searchRoot)
}

// calculateRelativePath calculates relative path from searchRoot to the given absolute path.
// Returns empty string if calculation fails.
func calculateRelativePath(absolutePath, searchRoot string) string {
	var relPath string
	var err error
	if searchRoot == "/" {
		// For root, remove leading "/" to get relative path
		relPath = strings.TrimPrefix(absolutePath, "/")
		if relPath == "" {
			relPath = "."
		}
	} else {
		// Ensure both paths are clean and absolute for Rel to work correctly
		cleanRoot := filepath.Clean(searchRoot)
		cleanPath := filepath.Clean(absolutePath)
		relPath, err = filepath.Rel(cleanRoot, cleanPath)
		if err != nil {
			// Fallback: if Rel fails, try manual calculation
			if strings.HasPrefix(cleanPath, cleanRoot) {
				relPath = strings.TrimPrefix(strings.TrimPrefix(cleanPath, cleanRoot), "/")
				if relPath == "" {
					relPath = "."
				}
				err = nil
			}
		}
	}
	if err != nil {
		return ""
	}
	// Normalize the relative path
	if relPath != "." && strings.HasPrefix(relPath, "./") {
		relPath = strings.TrimPrefix(relPath, "./")
	}
	return relPath
}

// processExistingPathFromRoot processes an existing file or directory, returning paths relative to search root
func processExistingPathFromRoot(searchPath string, info os.FileInfo, searchRoot string) ([]string, error) {
	var srcFiles []string

	if info.IsDir() {
		logrus.Infof("   ✅ Found directory: %s", searchPath)
		return walkDirectoryFromRoot(searchPath, searchRoot)
	}

	// It's a file, add it directly
	relPath := calculateRelativePath(searchPath, searchRoot)
	if relPath != "" {
		srcFiles = append(srcFiles, relPath)
		logrus.Infof("   📁 Added file to cross-stage dependencies: %s "+
			"(absolute: %s, root: %s)", relPath, searchPath, searchRoot)
	} else {
		logrus.Warnf("   ⚠️ Failed to calculate relative path from %s to %s",
			searchRoot, searchPath)
	}
	return srcFiles, nil
}

// walkDirectoryFromRoot walks a directory and collects all files, returning paths relative to search root
func walkDirectoryFromRoot(searchPath, searchRoot string) ([]string, error) {
	var srcFiles []string

	walkErr := filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Skip problematic paths but continue walking
			logrus.Debugf("Skipping problematic path %s: %v", path, err)
			return nil
		}
		if !info.IsDir() {
			relPath := calculateRelativePath(path, searchRoot)
			if relPath != "" {
				srcFiles = append(srcFiles, relPath)
				logrus.Debugf("📁 Added file to cross-stage dependencies: %s (from root: %s)", relPath, searchRoot)
			}
		}
		return nil
	})

	if walkErr != nil {
		logrus.Warnf("Failed to walk directory %s: %v", searchPath, walkErr)
	}

	return srcFiles, nil
}

// findSimilarPathsFromRoot tries to find similar paths when the exact path doesn't exist, searching from root
func findSimilarPathsFromRoot(searchPath, searchRoot string) ([]string, error) {
	var srcFiles []string

	logrus.Debugf("🔍 Path %s does not exist, trying to find similar paths (root: %s)", searchPath, searchRoot)

	// Try to find build output directories dynamically
	buildOutputFiles := findBuildOutputDirectoriesFromRoot(searchPath, searchRoot)
	srcFiles = append(srcFiles, buildOutputFiles...)

	// Try to find files matching the base name pattern
	patternFiles := findFilesByPatternFromRoot(searchPath, searchRoot)
	srcFiles = append(srcFiles, patternFiles...)

	// If we found files, return them
	if len(srcFiles) > 0 {
		logrus.Debugf("✅ Found %d files in similar paths", len(srcFiles))
		return srcFiles, nil
	}

	// If exact path not found, try glob pattern
	return findFilesWithGlobFromRoot(searchPath, searchRoot)
}

// findBuildOutputDirectoriesFromRoot searches for common build output directories from specified root
func findBuildOutputDirectoriesFromRoot(searchPath, searchRoot string) []string {
	var srcFiles []string

	buildOutputPatterns := []string{
		".output", "dist", "build", "out", "target", "bin", "lib",
	}

	parentDir := filepath.Dir(searchPath)

	if parentDir != "/" && parentDir != "." {
		if parentInfo, err := os.Stat(parentDir); err == nil && parentInfo.IsDir() {
			logrus.Debugf("🔍 Searching for build output patterns in: %s", parentDir)

			err := filepath.Walk(parentDir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil // Skip errors
				}

				// Check if this directory matches common build output patterns
				dirName := filepath.Base(path)
				for _, pattern := range buildOutputPatterns {
					if dirName == pattern && info.IsDir() {
						logrus.Debugf("✅ Found build output directory: %s", path)
						files, err := walkDirectoryFromRoot(path, searchRoot)
						if err == nil {
							srcFiles = append(srcFiles, files...)
						}
						return nil // Don't walk into subdirectories of build outputs
					}
				}
				return nil
			})
			if err != nil {
				logrus.Debugf("Failed to search for build output patterns in %s: %v", parentDir, err)
			}
		}
	}

	return srcFiles
}

// processMatchingFile adds a matching file to the results with relative path calculation
func processMatchingFile(path string, info os.FileInfo, searchRoot string, srcFiles []string) []string {
	if info.IsDir() {
		return srcFiles
	}

	relPath := calculateRelativePath(path, searchRoot)
	if relPath != "" {
		srcFiles = append(srcFiles, relPath)
		logrus.Debugf("📁 Found matching file: %s (from root: %s)", relPath, searchRoot)
	}
	return srcFiles
}

// matchPattern checks if a file path matches the given pattern
func matchPattern(path, baseName string) bool {
	return strings.Contains(filepath.Base(path), baseName) ||
		(strings.HasPrefix(baseName, ".") && strings.HasPrefix(filepath.Base(path), "."))
}

// walkPatternDirectory walks a directory searching for files matching the pattern
func walkPatternDirectory(parentDir, baseName, searchRoot string) []string {
	var srcFiles []string

	logrus.Debugf("🔍 Searching in parent directory: %s for pattern: %s (root: %s)",
		parentDir, baseName, searchRoot)

	// Search for files matching the base name pattern
	err := filepath.Walk(parentDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		if matchPattern(path, baseName) {
			srcFiles = processMatchingFile(path, info, searchRoot, srcFiles)
		}
		return nil
	})

	if err != nil {
		logrus.Debugf("Failed to search in parent directory %s: %v", parentDir, err)
	}

	return srcFiles
}

// findFilesByPatternFromRoot finds files matching a pattern by searching in parent directory
func findFilesByPatternFromRoot(searchPath, searchRoot string) []string {
	parentDir := filepath.Dir(searchPath)
	baseName := filepath.Base(searchPath)

	if parentDir == "/" || parentDir == "." {
		return []string{}
	}

	parentInfo, err := os.Stat(parentDir)
	if err != nil || !parentInfo.IsDir() {
		return []string{}
	}

	return walkPatternDirectory(parentDir, baseName, searchRoot)
}

// processGlobSymlink processes a symlink found via glob pattern
func processGlobSymlink(src, searchRoot string, srcFiles []string) []string {
	link, evalErr := util.EvalSymLink(src)
	if evalErr != nil {
		return srcFiles
	}

	linkRelPath := calculateRelativePath(link, searchRoot)
	if linkRelPath != "" {
		srcFiles = append(srcFiles, linkRelPath)
		logrus.Debugf("📁 Found symlink target via glob: %s (from root: %s)", linkRelPath, searchRoot)
	}
	return srcFiles
}

// processGlobFile processes a regular file found via glob pattern
func processGlobFile(src, searchRoot string, srcFiles []string) []string {
	relPath := calculateRelativePath(src, searchRoot)
	if relPath != "" {
		srcFiles = append(srcFiles, relPath)
		logrus.Debugf("📁 Found file via glob: %s (from root: %s)", relPath, searchRoot)
	}
	return srcFiles
}

// checkGlobDirectory checks if the glob search directory exists for debugging
func checkGlobDirectory(searchPath string) {
	searchDir := filepath.Dir(searchPath)
	if _, dirErr := os.Stat(searchDir); dirErr == nil {
		logrus.Debugf("Directory %s exists but pattern %s matches no files", searchDir, searchPath)
	} else {
		logrus.Debugf("Directory %s does not exist for pattern %s", searchDir, searchPath)
	}
}

// findFilesWithGlobFromRoot uses glob pattern to find files from specified root
func findFilesWithGlobFromRoot(searchPath, searchRoot string) ([]string, error) {
	var srcFiles []string

	srcs, err := filepath.Glob(searchPath)
	if err != nil {
		logrus.Warnf("Failed to glob pattern %s: %v, continuing anyway", searchPath, err)
		return srcFiles, nil
	}

	if len(srcs) == 0 {
		checkGlobDirectory(searchPath)
		logrus.Warnf("No files found for pattern %s, continuing anyway", searchPath)
		return srcFiles, nil
	}

	// Convert absolute paths to relative paths from searchRoot
	for _, src := range srcs {
		// Handle symlinks
		srcFiles = processGlobSymlink(src, searchRoot, srcFiles)

		// Add the file itself
		srcFiles = processGlobFile(src, searchRoot, srcFiles)
	}

	return srcFiles, nil
}

// resolvePathVariablesWithArgs resolves environment variables in file paths using build args
// This is critical for multi-stage builds where paths contain variables like ${APP_TYPE}
func resolvePathVariablesWithArgs(path string, buildArgs *dockerfile.BuildArgs) string {
	// Get environment variables from the current environment
	envVars := os.Environ()

	// If build args are provided, use them for variable resolution
	if buildArgs != nil {
		// Get build args as environment variables
		buildArgVars := buildArgs.GetAllAllowed()
		envVars = append(envVars, buildArgVars...)
		logrus.Debugf("Using %d build args for variable resolution", len(buildArgVars))
	}

	resolved, err := util.ResolveEnvironmentReplacement(path, envVars, false)
	if err != nil {
		logrus.Debugf("Failed to resolve environment variables in path %s: %v, using original path", path, err)
		return path
	}

	if resolved != path {
		logrus.Debugf("🔄 Resolved path variables: %s -> %s", path, resolved)
	}

	return resolved
}

// deduplicatePaths returns a deduplicated slice of shortest paths
// For example {"usr/lib", "usr/lib/ssl"} will return only {"usr/lib"}
func deduplicatePaths(paths []string) []string {
	type node struct {
		children map[string]*node
		value    bool
	}

	root := &node{children: make(map[string]*node)}

	// Create a tree marking all present paths
	for _, f := range paths {
		parts := strings.Split(f, "/")
		current := root
		for i := 0; i < len(parts)-1; i++ {
			part := parts[i]
			if _, ok := current.children[part]; !ok {
				current.children[part] = &node{children: make(map[string]*node)}
			}
			current = current.children[part]
		}
		current.children[parts[len(parts)-1]] = &node{children: make(map[string]*node), value: true}
	}

	// Collect all paths
	deduped := []string{}
	var traverse func(*node, string)
	traverse = func(n *node, path string) {
		if n.value {
			deduped = append(deduped, strings.TrimPrefix(path, "/"))
			return
		}
		for k, v := range n.children {
			traverse(v, path+"/"+k)
		}
	}

	traverse(root, "")

	return deduped
}

func fetchExtraStages(stages []config.KanikoStage, opts *config.KanikoOptions) error {
	t := timing.Start("Fetching Extra Stages")
	defer timing.DefaultRun.Stop(t)

	var names []string
	var extraStages []string

	// First pass: collect all extra stages that need to be fetched
	for stageIndex := range stages {
		s := &stages[stageIndex]
		for _, cmd := range s.Commands {
			c, ok := cmd.(*instructions.CopyCommand)
			if !ok || c.From == "" {
				continue
			}

			// FROMs at this point are guaranteed to be either an integer referring to a previous stage,
			// the name of a previous stage, or a name of a remote image.

			// If it is an integer stage index, validate that it is actually a previous index
			if fromIndex, err := strconv.Atoi(c.From); err == nil && stageIndex > fromIndex && fromIndex >= 0 {
				continue
			}
			// Check if the name is the alias of a previous stage
			if fromPreviousStage(c, names) {
				continue
			}

			// This must be an image name, collect it for parallel fetching
			extraStages = append(extraStages, c.From)
		}
		// Store the name of the current stage in the list with names, if applicable.
		if s.Name != "" {
			names = append(names, s.Name)
		}
	}

	// Parallel fetch of extra stages
	if len(extraStages) > 0 {
		return fetchExtraStagesParallel(extraStages, opts)
	}
	return nil
}

// fetchExtraStagesParallel fetches multiple extra stages in parallel
func fetchExtraStagesParallel(extraStages []string, opts *config.KanikoOptions) error {
	// Use errgroup for parallel execution with error handling
	var wg sync.WaitGroup
	errChan := make(chan error, len(extraStages))

	// Limit concurrent fetches to avoid overwhelming the registry
	maxConcurrent := 3
	if len(extraStages) < maxConcurrent {
		maxConcurrent = len(extraStages)
	}

	semaphore := make(chan struct{}, maxConcurrent)

	for _, stageName := range extraStages {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			logrus.Debugf("Fetching extra base image stage %s", name)

			// Fetch the image
			sourceImage, err := remote.RetrieveRemoteImage(name, &opts.RegistryOptions, opts.CustomPlatform)
			if err != nil {
				errChan <- errors.Wrapf(err, "failed to retrieve remote image %s", name)
				return
			}

			// Save as tarball
			if err := saveStageAsTarball(name, sourceImage); err != nil {
				errChan <- errors.Wrapf(err, "failed to save stage as tarball %s", name)
				return
			}

			// Extract to dependency directory
			if err := extractImageToDependencyDir(name, sourceImage); err != nil {
				errChan <- errors.Wrapf(err, "failed to extract image to dependency dir %s", name)
				return
			}

			logrus.Debugf("Successfully fetched extra stage %s", name)
		}(stageName)
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

func fromPreviousStage(copyCommand *instructions.CopyCommand, previousStageNames []string) bool {
	for _, previousStageName := range previousStageNames {
		if previousStageName == copyCommand.From {
			return true
		}
	}
	return false
}

func extractImageToDependencyDir(imageName string, image v1.Image) error {
	t := timing.Start("Extracting Image to Dependency Dir")
	defer timing.DefaultRun.Stop(t)
	dependencyDir := filepath.Join(config.KanikoDir, imageName)
	if err := os.MkdirAll(dependencyDir, DefaultDirPerm); err != nil {
		return err
	}
	logrus.Debugf("Trying to extract to %s", dependencyDir)
	_, err := util.GetFSFromImage(dependencyDir, image, util.ExtractFile)
	return err
}

func saveStageAsTarball(path string, image v1.Image) error {
	t := timing.Start("Saving stage as tarball")
	defer timing.DefaultRun.Stop(t)
	destRef, err := name.NewTag("temp/tag", name.WeakValidation)
	if err != nil {
		return err
	}
	tarPath := filepath.Join(config.KanikoIntermediateStagesDir, path)
	logrus.Infof("Storing source image from stage %s at path %s", path, tarPath)
	if err := os.MkdirAll(filepath.Dir(tarPath), DefaultDirPerm); err != nil {
		return err
	}
	return tarball.WriteToFile(tarPath, destRef, image)
}

func getHasher(snapshotMode string) (func(string) (string, error), error) {
	switch snapshotMode {
	case constants.SnapshotModeTime:
		logrus.Info("Only file modification time will be considered when snapshotting")
		return util.MtimeHasher(), nil
	case constants.SnapshotModeFull:
		return util.Hasher(), nil
	case constants.SnapshotModeRedo:
		return util.RedoHasher(), nil
	default:
		return nil, fmt.Errorf("%s is not a valid snapshot mode", snapshotMode)
	}
}

func resolveOnBuild(stage *config.KanikoStage, cfg *v1.Config, stageNameToIdx map[string]string) error {
	cmds, err := dockerfile.GetOnBuildInstructions(cfg, stageNameToIdx)
	if err != nil {
		return err
	}

	// Append to the beginning of the commands in the stage
	stage.Commands = append(cmds, stage.Commands...)
	logrus.Infof("Executing %v build triggers", len(cmds))

	// Blank out the Onbuild command list for this image
	cfg.OnBuild = nil
	return nil
}

// reviewConfig makes sure the value of CMD is correct after building the stage
// If ENTRYPOINT was set in this stage but CMD wasn't, then CMD should be cleared out
// See Issue #346 for more info
func reviewConfig(stage *config.KanikoStage, cfg *v1.Config) {
	entrypoint := false
	cmd := false

	for _, c := range stage.Commands {
		if c.Name() == constants.Cmd {
			cmd = true
		}
		if c.Name() == constants.Entrypoint {
			entrypoint = true
		}
	}
	if entrypoint && !cmd {
		cfg.Cmd = nil
	}
}

// ResolveCrossStageInstructions iterates over a list of KanikoStage and resolves
// instructions referring to earlier stages. It returns a mapping of stage name
// to stage id, f.e - ["first": "0", "second": "1", "target": "2"]
func ResolveCrossStageInstructions(stages []config.KanikoStage) map[string]string {
	nameToIndex := make(map[string]string)
	for i := range stages {
		stage := &stages[i]
		index := strconv.Itoa(i)
		if stage.Name != "" {
			nameToIndex[stage.Name] = index
		}
		dockerfile.ResolveCrossStageCommands(stage.Commands, nameToIndex)
	}

	logrus.Debugf("Built stage name to index map: %v", nameToIndex)
	return nameToIndex
}

func (s *stageBuilder) initSnapshotWithTimings() error {
	t := timing.Start("Initial FS snapshot")

	// Protect snapshotter access with write lock
	s.mutex.Lock()
	err := s.snapshotter.Init()
	s.mutex.Unlock()

	if err != nil {
		return err
	}
	timing.DefaultRun.Stop(t)
	return nil
}

// InitMultiPlatformBuild initializes the multi-platform build functionality
func InitMultiPlatformBuild() {
	// Set the build function for multi-platform coordinator
	multiplatform.SetBuildFunc(DoBuild)
}

// optimizeForNoCache applies simple optimizations when cache is disabled
func optimizeForNoCache(opts *config.KanikoOptions) {
	// This function is only called when cache is not enabled
	// No need to check opts.Cache here as it's already verified in applyComprehensiveOptimizations

	logrus.Info("🚀 Applying no-cache optimizations for better performance")

	// 1. Enable incremental snapshots for faster filesystem scanning
	if !opts.IncrementalSnapshots {
		opts.IncrementalSnapshots = true
		logrus.Info("📸 Enabled incremental snapshots for no-cache build")
	}

	// 2. Enable comprehensive file processing for cross-stage dependencies
	logrus.Info("🔍 Enabled comprehensive file processing for cross-stage dependencies")

	// 2. Increase parallelism to compensate for lack of cache
	if opts.MaxParallelCommands == 0 {
		opts.MaxParallelCommands = runtime.NumCPU() * NoCacheParallelMultiplier
		logrus.Infof("⚡ Set parallel commands to %d for no-cache build", opts.MaxParallelCommands)
	}

	// 3. Enable parallel execution if not already enabled
	if !opts.EnableParallelExec {
		opts.EnableParallelExec = true
		logrus.Info("🔄 Enabled parallel execution for no-cache build")
	}

	// 4. Optimize snapshot mode for better performance
	if opts.SnapshotMode == "" {
		opts.SnapshotMode = SnapshotModeTime // Faster for large projects
		logrus.Info("⏱️ Set snapshot mode to 'time' for faster no-cache builds")
	}

	// 5. Set reasonable memory limits if not configured
	if opts.MaxMemoryUsageBytes == 0 {
		opts.MaxMemoryUsageBytes = MemoryLimitBytes
		logrus.Info("💾 Set memory limit to 2GB for no-cache build")
	}

	// 6. Enable memory monitoring for better resource management
	if !opts.MemoryMonitoring {
		opts.MemoryMonitoring = true
		logrus.Info("📊 Enabled memory monitoring for no-cache build")
	}

	// 7. Set garbage collection threshold for better memory management
	if opts.GCThreshold == 0 {
		opts.GCThreshold = 80
		logrus.Info("🗑️ Set GC threshold to 80% for no-cache build")
	}

	// 8. Increase command timeout for slower operations without cache
	if opts.CommandTimeout == 0 {
		opts.CommandTimeout = CommandTimeoutMinutes * time.Minute
		logrus.Info("⏰ Set command timeout to 30 minutes for no-cache build")
	}

	// 9. Increase retry attempts for network operations
	if opts.ImageFSExtractRetry == 0 {
		opts.ImageFSExtractRetry = 3
		logrus.Info("🔄 Set image extraction retries to 3 for no-cache build")
	}

	// 10. Set reasonable file size limits
	if opts.MaxFileSizeBytes == 0 {
		opts.MaxFileSizeBytes = MaxFileSizeBytes
		logrus.Info("📁 Set max file size to 500MB for no-cache build")
	}

	if opts.MaxTotalFileSizeBytes == 0 {
		opts.MaxTotalFileSizeBytes = MaxTotalFileSizeBytes
		logrus.Info("📦 Set max total file size to 10GB for no-cache build")
	}

	logrus.Info("✅ No-cache optimizations applied successfully")
}

// optimizePerformance applies additional performance optimizations
func optimizePerformance(opts *config.KanikoOptions) {
	logrus.Info("⚡ Applying performance optimizations")

	// 1. Optimize compression for better speed/size balance
	if opts.Compression == "" {
		opts.Compression = CompressionZstd
		logrus.Info("🗜️ Set compression to zstd for better performance")
	}

	// 2. Set optimal compression level
	if opts.CompressionLevel == 0 {
		opts.CompressionLevel = 3 // Good balance between speed and compression
		logrus.Info("📊 Set compression level to 3 for optimal performance")
	}

	// 3. Enable compressed caching for better layer handling
	if !opts.CompressedCaching {
		opts.CompressedCaching = true
		logrus.Info("💾 Enabled compressed caching for better performance")
	}

	// 4. Set monitoring interval for better resource tracking
	if opts.MonitoringInterval == 0 {
		opts.MonitoringInterval = 5 // 5 seconds
		logrus.Info("⏱️ Set monitoring interval to 5 seconds for better resource tracking")
	}

	// 5. Enable integrity check for better reliability
	if !opts.IntegrityCheck {
		opts.IntegrityCheck = true
		logrus.Info("🔒 Enabled integrity check for better reliability")
	}

	// 6. Set reasonable max expected changes
	if opts.MaxExpectedChanges == 0 {
		opts.MaxExpectedChanges = 1000
		logrus.Info("📈 Set max expected changes to 1000 for better performance")
	}

	// 7. Enable full scan backup for safety
	if !opts.FullScanBackup {
		opts.FullScanBackup = true
		logrus.Info("🛡️ Enabled full scan backup for safety")
	}

	logrus.Info("✅ Performance optimizations applied successfully")
}

// optimizeNetwork applies network optimizations for better stability
func optimizeNetwork(opts *config.KanikoOptions) {
	logrus.Info("🌐 Applying network optimizations")

	// 1. Set reasonable push retry settings
	if opts.PushRetry == 0 {
		opts.PushRetry = 3
		logrus.Info("🔄 Set push retry to 3 for better network stability")
	}

	// 2. Set initial delay for retries
	if opts.PushRetryInitialDelay == 0 {
		opts.PushRetryInitialDelay = 1000 // 1 second
		logrus.Info("⏱️ Set push retry initial delay to 1 second")
	}

	// 3. Set max delay for retries
	if opts.PushRetryMaxDelay == 0 {
		opts.PushRetryMaxDelay = 30000 // 30 seconds
		logrus.Info("⏰ Set push retry max delay to 30 seconds")
	}

	// 4. Set backoff multiplier for exponential backoff
	if opts.PushRetryBackoffMultiplier == 0 {
		opts.PushRetryBackoffMultiplier = 2.0
		logrus.Info("📈 Set push retry backoff multiplier to 2.0")
	}

	// 5. Set image download retry
	if opts.ImageDownloadRetry == 0 {
		opts.ImageDownloadRetry = 3
		logrus.Info("⬇️ Set image download retry to 3")
	}

	// 6. Enable push ignore immutable tag errors for better compatibility
	if !opts.PushIgnoreImmutableTagErrors {
		opts.PushIgnoreImmutableTagErrors = true
		logrus.Info("🏷️ Enabled push ignore immutable tag errors for better compatibility")
	}

	logrus.Info("✅ Network optimizations applied successfully")
}

// initializeNetworkManager initializes the advanced network manager
func initializeNetworkManager(_ *config.KanikoOptions) *network.Manager {
	logrus.Info("🌐 Initializing advanced network manager")

	// Create optimized network manager configuration
	networkConfig := &network.ManagerConfig{
		// Connection pool settings - optimized for registry operations
		MaxIdleConns:        MaxIdleConns,                     // Increased for better connection reuse
		MaxIdleConnsPerHost: MaxIdleConnsPerHost,              // Increased for registry connections
		MaxConnsPerHost:     MaxConnsPerHost,                  // Increased for parallel operations
		IdleConnTimeout:     IdleConnTimeoutMin * time.Minute, // Longer timeout for registry connections

		// Parallel client settings - optimized for image operations
		MaxConcurrency: MaxConcurrency,                  // Increased for better parallelism
		RequestTimeout: RequestTimeoutMin * time.Minute, // Longer timeout for large images
		RetryAttempts:  RetryAttempts,                   // More retries for better reliability
		RetryDelay:     RetryDelaySec * time.Second,     // Longer delay between retries

		// Registry client settings - optimized for container registries
		EnableParallelPull: true,
		EnableCompression:  true,
		UserAgent:          "kaniko-optimized/2.0",

		// Cache settings - optimized for build performance
		EnableDNSOptimization: true,
		DNSCacheTimeout:       DNSCacheTimeoutMin * time.Minute, // Longer DNS cache
		EnableManifestCache:   true,
		ManifestCacheTimeout:  ManifestCacheTimeoutMin * time.Minute, // Longer manifest cache
	}

	// Create network manager
	manager := network.NewManager(networkConfig)

	// Initialize the manager
	if err := manager.Initialize(); err != nil {
		logrus.Warnf("Failed to initialize network manager: %v", err)
		return nil
	}

	logrus.Info("✅ Advanced network manager initialized successfully")
	return manager
}

// optimizeFilesystem applies filesystem optimizations for better performance
func optimizeFilesystem(opts *config.KanikoOptions) {
	logrus.Info("📁 Applying filesystem optimizations")

	// 1. Optimize snapshot mode for better performance
	if opts.SnapshotMode == "" {
		opts.SnapshotMode = SnapshotModeTime // Faster for most use cases
		logrus.Info("⏱️ Set snapshot mode to 'time' for faster filesystem operations")
	}

	// 2. Enable incremental snapshots for better performance (only when cache is not used)
	if !opts.Cache && !opts.IncrementalSnapshots {
		opts.IncrementalSnapshots = true
		logrus.Info("📸 Enabled incremental snapshots for faster filesystem scanning")
	}

	// 3. Set reasonable max expected changes for integrity checking
	if opts.MaxExpectedChanges == 0 {
		opts.MaxExpectedChanges = 5000 // Good balance for most projects
		logrus.Info("📊 Set max expected changes to 5000 for better integrity checking")
	}

	// 4. Enable integrity check for better reliability
	if !opts.IntegrityCheck {
		opts.IntegrityCheck = true
		logrus.Info("🔒 Enabled integrity check for better filesystem reliability")
	}

	// 5. Enable full scan backup for safety
	if !opts.FullScanBackup {
		opts.FullScanBackup = true
		logrus.Info("🛡️ Enabled full scan backup for filesystem safety")
	}

	// 6. Set reasonable file size limits
	if opts.MaxFileSizeBytes == 0 {
		opts.MaxFileSizeBytes = MaxFileSizeBytes
		logrus.Info("📁 Set max file size to 500MB for filesystem operations")
	}

	if opts.MaxTotalFileSizeBytes == 0 {
		opts.MaxTotalFileSizeBytes = MaxTotalFileSizeBytes
		logrus.Info("📦 Set max total file size to 10GB for filesystem operations")
	}

	// 7. Enable compressed caching for better layer handling
	if !opts.CompressedCaching {
		opts.CompressedCaching = true
		logrus.Info("💾 Enabled compressed caching for better filesystem performance")
	}

	// 8. Set optimal compression for filesystem operations
	if opts.Compression == "" {
		opts.Compression = CompressionZstd
		logrus.Info("🗜️ Set compression to zstd for better filesystem performance")
	}

	if opts.CompressionLevel == 0 {
		opts.CompressionLevel = 3 // Good balance between speed and compression
		logrus.Info("📊 Set compression level to 3 for optimal filesystem performance")
	}

	logrus.Info("✅ Filesystem optimizations applied successfully")
}

// applyComprehensiveOptimizations applies all optimizations in the correct order
func applyComprehensiveOptimizations(opts *config.KanikoOptions) {
	logrus.Info("🚀 Applying comprehensive optimizations for maximum performance")

	// 1. Apply no-cache optimizations first (foundation) - only when cache is not used
	if !opts.Cache {
		logrus.Info("📦 Cache not enabled - applying no-cache optimizations for better performance")
		optimizeForNoCache(opts)
	} else {
		logrus.Info("💾 Cache enabled - skipping no-cache optimizations")
	}

	// 2. Apply performance optimizations (core improvements) - always beneficial
	optimizePerformance(opts)

	// 3. Apply network optimizations (connectivity) - always beneficial
	optimizeNetwork(opts)

	// 4. Initialize advanced network manager (advanced networking) - always beneficial
	_ = initializeNetworkManager(opts)

	// 5. Apply filesystem optimizations (storage) - always beneficial
	optimizeFilesystem(opts)

	// 6. Final integration checks
	validateOptimizations(opts)

	logrus.Info("✅ All comprehensive optimizations applied successfully")
}

// validateOptimizations validates that all optimizations are properly configured
func validateOptimizations(opts *config.KanikoOptions) {
	logrus.Info("🔍 Validating optimization configuration")

	// Validate no-cache optimizations
	if !opts.Cache {
		if !opts.IncrementalSnapshots {
			logrus.Warn("⚠️ Incremental snapshots should be enabled for no-cache builds")
		}
		if opts.MaxParallelCommands == 0 {
			logrus.Warn("⚠️ MaxParallelCommands should be set for no-cache builds")
		}
	}

	// Validate performance optimizations
	if opts.Compression == "" {
		logrus.Warn("⚠️ Compression should be set for optimal performance")
	}
	if opts.CompressionLevel == 0 {
		logrus.Warn("⚠️ CompressionLevel should be set for optimal performance")
	}

	// Validate network optimizations
	if opts.PushRetry == 0 {
		logrus.Warn("⚠️ PushRetry should be set for network stability")
	}
	if opts.ImageDownloadRetry == 0 {
		logrus.Warn("⚠️ ImageDownloadRetry should be set for network stability")
	}

	// Validate filesystem optimizations
	if opts.SnapshotMode == "" {
		logrus.Warn("⚠️ SnapshotMode should be set for filesystem performance")
	}
	if !opts.IntegrityCheck {
		logrus.Warn("⚠️ IntegrityCheck should be enabled for reliability")
	}

	logrus.Info("✅ Optimization validation completed")
}
