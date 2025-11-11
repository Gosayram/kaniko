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

// Package cmd provides the command-line interface for the kaniko executor.
package cmd

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/containerd/platforms"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/Gosayram/kaniko/pkg/buildcontext"
	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/constants"
	"github.com/Gosayram/kaniko/pkg/debug"
	"github.com/Gosayram/kaniko/pkg/executor"
	"github.com/Gosayram/kaniko/pkg/logging"
	"github.com/Gosayram/kaniko/pkg/multiplatform"
	"github.com/Gosayram/kaniko/pkg/oci"
	"github.com/Gosayram/kaniko/pkg/policy"
	"github.com/Gosayram/kaniko/pkg/rootless"
	"github.com/Gosayram/kaniko/pkg/timing"
	"github.com/Gosayram/kaniko/pkg/util"
	"github.com/Gosayram/kaniko/pkg/util/proc"
)

var (
	opts                                                           = &config.KanikoOptions{}
	ctxSubPath                                                     string
	force                                                          bool
	logLevel                                                       string
	logFormat                                                      string
	logTimestamp                                                   bool
	allowedRegistries, deniedRegistries, allowedRepos, deniedRepos []string
	requireSignature                                               bool
)

// Cache timeout and file permission constants
const (
	defaultCacheTTL = time.Hour * 336 // 2 weeks
	filePermission  = 0o600

	// Push retry configuration constants
	defaultPushRetryInitialDelay      = 1000  // milliseconds
	defaultPushRetryMaxDelay          = 30000 // milliseconds
	defaultPushRetryBackoffMultiplier = 2.0
)

// Resource limit constants
const (
	// Memory limits
	maxMemoryUsageBytes   = 2 * 1024 * 1024 * 1024  // 2GB
	maxFileSizeBytes      = 500 * 1024 * 1024       // 500MB
	maxTotalFileSizeBytes = 10 * 1024 * 1024 * 1024 // 10GB

	// Performance optimization constants
	maxExpectedChanges = 5000 // Maximum expected changes for incremental snapshots (optimized per plan)
	gcThreshold        = 80   // Memory usage percentage threshold for GC
	monitoringInterval = 5    // Memory monitoring interval in seconds

	// Parallel execution constants
	defaultCommandTimeout  = 30   // Default command timeout in minutes
	defaultMaxCacheEntries = 2000 // Default cache entries (optimized for 1GB)
	defaultMaxPreloadSize  = 100  // Default preload size
	defaultPreloadTimeout  = 10   // Default preload timeout in minutes

	// Compression constants
	// Conservative default: 1-2 for speed and lower CPU usage (especially with multiple parallel builds)
	// Level 3 was too CPU-intensive for multiple parallel builds
	defaultCompressionLevel = 2 // Conservative default for lower CPU usage

	// Cache optimization constants
	// Conservative default: 3-5 instead of higher values to avoid excessive CPU usage
	defaultMaxConcurrentCacheChecks   = 3
	defaultCacheMaxConns              = 10
	defaultCacheMaxConnsPerHost       = 5
	defaultCacheMaxConcurrentRequests = 5
	defaultCacheRequestTimeout        = 30 * time.Second
	defaultPrefetchWindow             = 10
	defaultCacheResultMaxEntries      = 1000
	defaultCacheResultMaxMemoryMB     = 100
	defaultCacheResultTTL             = 5 * time.Minute
	defaultFileHashCacheMaxEntries    = 10000
	defaultFileHashCacheMaxMemoryMB   = 200
	defaultLayerLoadMaxConcurrent     = 3
	defaultPredictiveCacheMaxLayers   = 20
	defaultPredictiveCacheMaxMemoryMB = 50
)

func init() {
	RootCmd.PersistentFlags().StringVarP(&logLevel, "verbosity", "v", logging.DefaultLevel,
		"Log level (trace, debug, info, warn, error, fatal, panic)")
	RootCmd.PersistentFlags().StringVar(&logFormat, "log-format", logging.FormatColor,
		"Log format (text, color, json)")
	RootCmd.PersistentFlags().BoolVar(&logTimestamp, "log-timestamp",
		logging.DefaultLogTimestamp, "Timestamp in log output")
	RootCmd.PersistentFlags().BoolVarP(&force, "force", "", false, "Force building outside of a container")

	addKanikoOptionsFlags()
	addHiddenFlags(RootCmd)
	RootCmd.PersistentFlags().BoolVarP(&opts.IgnoreVarRun, "whitelist-var-run", "", true,
		"Ignore /var/run directory when taking image snapshot. "+
			"Set it to false to preserve /var/run/ in destination image.")
	if err := RootCmd.PersistentFlags().MarkDeprecated("whitelist-var-run",
		"Please use ignore-var-run instead."); err != nil {
		logrus.Warnf("Failed to mark flag as deprecated: %v", err)
	}
}

func validateFlags() {
	checkNoDeprecatedFlags()

	// Allow setting --registry-mirror using an environment variable.
	if val, ok := os.LookupEnv("KANIKO_REGISTRY_MIRROR"); ok {
		if err := opts.RegistryMirrors.Set(val); err != nil {
			logrus.Warnf("Failed to set registry mirror from environment: %v", err)
		}
	}

	// Allow setting --no-push using an environment variable.
	if val, ok := os.LookupEnv("KANIKO_NO_PUSH"); ok {
		valBoolean, err := strconv.ParseBool(val)
		if err != nil {
			logrus.Warnf("invalid value (true/false) for KANIKO_NO_PUSH environment variable: %v", val)
		}
		opts.NoPush = valBoolean
	}

	// Allow setting --registry-maps using an environment variable.
	if val, ok := os.LookupEnv("KANIKO_REGISTRY_MAP"); ok {
		if err := opts.RegistryMaps.Set(val); err != nil {
			logrus.Warnf("Failed to set registry map: %v", err)
		}
	}

	// Allow setting network optimization parameters via environment variables (per performance plan)
	configureNetworkFromEnvironment()

	for _, target := range opts.RegistryMirrors {
		if err := opts.RegistryMaps.Set(fmt.Sprintf("%s=%s", name.DefaultRegistry, target)); err != nil {
			logrus.Warnf("Failed to set registry map for mirror: %v", err)
		}
	}

	if len(opts.RegistryMaps) > 0 {
		for src, dsts := range opts.RegistryMaps {
			logrus.Debugf("registry-map remaps %s to %s.", src, strings.Join(dsts, ", "))
		}
	}

	// Default the custom platform flag to our current platform, and validate it.
	if opts.CustomPlatform == "" {
		opts.CustomPlatform = platforms.DefaultString()
	}
	if _, err := v1.ParsePlatform(opts.CustomPlatform); err != nil {
		logrus.Fatalf("Invalid platform %q: %v", opts.CustomPlatform, err)
	}
}

// configureDebugFromEnvironment sets debug options from environment variables
func configureDebugFromEnvironment() {
	// Enable debug mode if environment variable is set
	if os.Getenv("KANIKO_DEBUG") == "true" {
		opts.EnableFullDebug = true
		opts.DebugLogLevel = "trace"
		opts.OutputDebugFiles = true
		logrus.Info("Debug mode enabled via environment variable")
	}

	// Set debug level from environment
	if level := os.Getenv("KANIKO_DEBUG_LEVEL"); level != "" {
		opts.DebugLogLevel = level
	}

	// Set debug components from environment
	if components := os.Getenv("KANIKO_DEBUG_COMPONENTS"); components != "" {
		opts.DebugComponents = strings.Split(components, ",")
	}
}

// configureNetworkFromEnvironment sets network optimization parameters from environment variables
// Per performance plan: allows configuration via KANIKO_MAX_CONCURRENCY, KANIKO_MAX_IDLE_CONNS, etc.
func configureNetworkFromEnvironment() {
	configureNetworkConcurrency()
	configureNetworkIdleConns()
	configureNetworkTimeout()
	configurePushRetry()
	configureImageDownloadRetry()
}

// configureNetworkConcurrency configures max concurrency from environment
func configureNetworkConcurrency() {
	if val := os.Getenv("KANIKO_MAX_CONCURRENCY"); val != "" {
		if intVal, err := strconv.Atoi(val); err == nil && intVal > 0 {
			logrus.Debugf("KANIKO_MAX_CONCURRENCY set to %d (used by network manager)", intVal)
		}
	}
}

// configureNetworkIdleConns configures max idle connections from environment
func configureNetworkIdleConns() {
	if val := os.Getenv("KANIKO_MAX_IDLE_CONNS"); val != "" {
		if intVal, err := strconv.Atoi(val); err == nil && intVal > 0 {
			logrus.Debugf("KANIKO_MAX_IDLE_CONNS set to %d (used by network manager)", intVal)
		}
	}
}

// configureNetworkTimeout configures request timeout from environment
func configureNetworkTimeout() {
	if val := os.Getenv("KANIKO_REQUEST_TIMEOUT"); val != "" {
		if duration, err := time.ParseDuration(val); err == nil && duration > 0 {
			logrus.Debugf("KANIKO_REQUEST_TIMEOUT set to %v (used by network manager)", duration)
		}
	}
}

// configurePushRetry configures push retry from environment
func configurePushRetry() {
	if val := os.Getenv("KANIKO_PUSH_RETRY"); val != "" {
		if intVal, err := strconv.Atoi(val); err == nil && intVal >= 0 {
			if opts.PushRetry == 0 {
				opts.PushRetry = intVal
				logrus.Infof("Set push retry to %d from KANIKO_PUSH_RETRY", intVal)
			}
		}
	}
}

// configureImageDownloadRetry configures image download retry from environment
func configureImageDownloadRetry() {
	if val := os.Getenv("KANIKO_IMAGE_DOWNLOAD_RETRY"); val != "" {
		if intVal, err := strconv.Atoi(val); err == nil && intVal >= 0 {
			if opts.ImageDownloadRetry == 0 {
				opts.ImageDownloadRetry = intVal
				logrus.Infof("Set image download retry to %d from KANIKO_IMAGE_DOWNLOAD_RETRY", intVal)
			}
		}
	}
}

// initializeSourcePolicy initializes source policy from command line flags
func initializeSourcePolicy() {
	// Only create policy if at least one flag is set
	if len(allowedRegistries) == 0 && len(deniedRegistries) == 0 &&
		len(allowedRepos) == 0 && len(deniedRepos) == 0 && !requireSignature {
		return // No policy configured
	}

	// Create new source policy
	sourcePolicy := policy.NewSourcePolicy()

	// Set policy values
	if len(allowedRegistries) > 0 {
		sourcePolicy.SetAllowedRegistries(allowedRegistries)
	}
	if len(deniedRegistries) > 0 {
		sourcePolicy.SetDeniedRegistries(deniedRegistries)
	}
	if len(allowedRepos) > 0 {
		sourcePolicy.SetAllowedRepos(allowedRepos)
	}
	if len(deniedRepos) > 0 {
		sourcePolicy.SetDeniedRepos(deniedRepos)
	}
	if requireSignature {
		sourcePolicy.SetRequireSignature(true)
	}

	opts.SourcePolicy = sourcePolicy
	logrus.Infof("Source policy initialized: allowed-registries=%v, denied-registries=%v, require-signature=%v",
		allowedRegistries, deniedRegistries, requireSignature)
}

// RootCmd is the kaniko command that is run
var RootCmd = &cobra.Command{
	Use: "executor",
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		if cmd.Use == "executor" {

			if err := logging.Configure(logLevel, logFormat, logTimestamp); err != nil {
				return err
			}

			// Configure debug from environment variables
			configureDebugFromEnvironment()

			// Initialize debug system
			if _, err := debug.Init(&opts.DebugOptions); err != nil {
				logrus.Warnf("Failed to initialize debug system: %v", err)
			}

			// Initialize performance tracker
			debug.InitPerformanceTracker()

			validateFlags()

			// Command line flag takes precedence over the KANIKO_DIR environment variable.
			dir := config.KanikoDir
			if opts.KanikoDir != constants.DefaultKanikoPath {
				dir = opts.KanikoDir
			}

			if err := checkKanikoDir(dir); err != nil {
				return err
			}

			resolveEnvironmentBuildArgs(opts.BuildArgs, os.Getenv)

			// Set CLI size limits for the util package
			util.SetCLISizeLimits(opts.MaxFileSize, opts.MaxTarFileSize, opts.MaxTotalArchiveSize)

			// Initialize source policy if any policy flags are set
			initializeSourcePolicy()

			if !opts.NoPush && len(opts.Destinations) == 0 {
				return errors.New("you must provide --destination, or use --no-push")
			}
			if err := cacheFlagsValid(); err != nil {
				return errors.Wrap(err, "cache flags invalid")
			}
			if err := resolveSourceContext(); err != nil {
				return errors.Wrap(err, "error resolving source context")
			}
			if err := resolveDockerfilePath(); err != nil {
				return errors.Wrap(err, "error resolving dockerfile path")
			}
			if len(opts.Destinations) == 0 && opts.ImageNameDigestFile != "" {
				return errors.New("you must provide --destination if setting ImageNameDigestFile")
			}
			if len(opts.Destinations) == 0 && opts.ImageNameTagDigestFile != "" {
				return errors.New("you must provide --destination if setting ImageNameTagDigestFile")
			}
			// Update ignored paths
			if opts.IgnoreVarRun {
				// /var/run is a special case. It's common to mount in /var/run/docker.sock
				// or something similar which leads to a special mount on the /var/run/docker.sock
				// file itself, but the directory to exist in the image with no way to tell if it came
				// from the base image or not.
				logrus.Trace("Adding /var/run to default ignore list")
				util.AddToDefaultIgnoreList(util.IgnoreListEntry{
					Path:            "/var/run",
					PrefixMatchOnly: false,
				})
			}
			for _, p := range opts.IgnorePaths {
				util.AddToDefaultIgnoreList(util.IgnoreListEntry{
					Path:            p,
					PrefixMatchOnly: false,
				})
			}
		}
		return nil
	},
	Run: func(_ *cobra.Command, _ []string) {
		if !checkContained() {
			if !force {
				exit(errors.New("kaniko should only be run inside of a container, " +
					"run with the --force flag if you are sure you want to continue"))
			}
			logrus.Warn("Kaniko is being run outside of a container. This can have dangerous effects on your system")
		}

		// Initialize rootless manager (enabled by default)
		logrus.Infof("Initializing rootless mode...")
		rootlessManager := rootless.NewManager()

		// Set target user from configuration
		if err := rootlessManager.SetTargetUserFromConfig(opts.DefaultUser); err != nil {
			exit(errors.Wrap(err, "failed to set target user from config"))
		}

		// Phase 1: Automatic mode determination and setup under root
		if err := rootlessManager.Initialize(); err != nil {
			exit(errors.Wrap(err, "failed to initialize rootless manager"))
		}

		// Automatic determination of security mode based on target user
		if err := rootlessManager.DetermineMode(); err != nil {
			exit(errors.Wrap(err, "failed to determine security mode"))
		}

		// Log security warnings
		if err := rootlessManager.LogSecurityWarnings(); err != nil {
			exit(errors.Wrap(err, "failed to log security warnings"))
		}

		// Phase 2: Switch to target user (only in secure mode)
		if rootlessManager.IsSecureMode() {
			if err := rootlessManager.SwitchToTargetUser(); err != nil {
				exit(errors.Wrap(err, "failed to switch to target user"))
			}
		}

		if !opts.NoPush || opts.CacheRepo != "" {
			if err := executor.CheckPushPermissions(opts); err != nil {
				exit(errors.Wrap(err, "error checking push permissions -- "+
					"make sure you entered the correct tag name, and that you are authenticated correctly, and try again"))
			}
		}
		if err := resolveRelativePaths(); err != nil {
			exit(errors.Wrap(err, "error resolving relative paths to absolute paths"))
		}
		if err := os.Chdir("/"); err != nil {
			exit(errors.Wrap(err, "error changing to root dir"))
		}
		// Handle multi-platform builds
		if len(opts.MultiPlatform) > 0 {
			if err := executeMultiPlatformBuild(opts); err != nil {
				exit(errors.Wrap(err, "error executing multi-platform build"))
			}
		} else {
			// Single platform build (legacy behavior)
			image, err := executor.DoBuild(opts)
			if err != nil {
				exit(errors.Wrap(err, "error building image"))
			}
			if err := executor.DoPush(image, opts); err != nil {
				exit(errors.Wrap(err, "error pushing image"))
			}
		}

		// Cleanup debug system
		defer func() {
			if err := debug.Close(); err != nil {
				logrus.Warnf("Failed to close debug system: %v", err)
			}
		}()

		benchmarkFile := os.Getenv("BENCHMARK_FILE")
		// false is a keyword for integration tests to turn off benchmarking
		if benchmarkFile != "" && benchmarkFile != "false" {
			s, err := timing.JSON()
			if err != nil {
				logrus.Warnf("Unable to write benchmark file: %s", err)
				return
			}
			if strings.HasPrefix(benchmarkFile, "gs://") {
				logrus.Info("Uploading to gcs")
				if err := buildcontext.UploadToBucket(strings.NewReader(s), benchmarkFile); err != nil {
					logrus.Infof("Unable to upload %s due to %v", benchmarkFile, err)
				}
				logrus.Infof("Benchmark file written at %s", benchmarkFile)
			} else {
				// Sanitize path to prevent directory traversal
				cleanPath := filepath.Clean(benchmarkFile)
				if filepath.IsAbs(cleanPath) {
					cleanPath = filepath.Base(cleanPath) // Only allow writing to current directory
				}
				f, err := os.Create(cleanPath)
				if err != nil {
					logrus.Warnf("Unable to create benchmarking file %s: %s", benchmarkFile, err)
					return
				}
				if _, err := f.WriteString(s); err != nil {
					logrus.Warnf("Failed to write benchmark data: %v", err)
				}
				logrus.Infof("Benchmark file written at %s", benchmarkFile)
			}
		}
	},
}

// addKanikoOptionsFlags configures opts
func addKanikoOptionsFlags() {
	addBasicFlags()
	addRegistryFlags()
	addCacheFlags()
	addBuildFlags()
	addMultiPlatformFlags()
	addDeprecatedFlags()
}

// addBasicFlags adds basic build configuration flags
func addBasicFlags() {
	RootCmd.PersistentFlags().StringVarP(&opts.DockerfilePath, "dockerfile", "f", "Dockerfile",
		"Path to the dockerfile to be built.")
	RootCmd.PersistentFlags().StringVarP(&opts.SrcContext, "context", "c", "/workspace/",
		"Path to the dockerfile build context.")
	RootCmd.PersistentFlags().StringVarP(&ctxSubPath, "context-sub-path", "", "", "Sub path within the given context.")
	RootCmd.PersistentFlags().StringVarP(&opts.Bucket, "bucket", "b", "",
		"Name of the GCS bucket from which to access build context as tarball.")
	RootCmd.PersistentFlags().VarP(&opts.Destinations, "destination", "d",
		"Registry the final image should be pushed to. Set it repeatedly for multiple destinations.")
	RootCmd.PersistentFlags().StringVarP(&opts.SnapshotMode, "snapshot-mode", "", "time",
		"Change the file attributes inspected during snapshotting (default: time for better performance)")
	RootCmd.PersistentFlags().StringVarP(&opts.CustomPlatform, "custom-platform", "", "",
		"Specify the build platform if different from the current host")
	RootCmd.PersistentFlags().VarP(&opts.BuildArgs, "build-arg", "",
		"This flag allows you to pass in ARG values at build time. Set it repeatedly for multiple values.")
	RootCmd.PersistentFlags().StringVarP(&opts.Target, "target", "", "",
		"Set the target build stage to build")
	RootCmd.PersistentFlags().Var(&opts.Git, "git",
		"Branch to clone if build context is a git repository")

	// Add debug flags
	addDebugFlags()
}

// addDebugFlags adds debug configuration flags
func addDebugFlags() {
	RootCmd.PersistentFlags().BoolVar(&opts.EnableFullDebug, "debug-full", false,
		"Enable comprehensive debug logging for all components")
	RootCmd.PersistentFlags().BoolVar(&opts.DebugBuildSteps, "debug-build-steps", false,
		"Debug individual build steps and commands")
	RootCmd.PersistentFlags().BoolVar(&opts.DebugMultiPlatform, "debug-multi-platform", false,
		"Debug multi-platform build coordination")
	RootCmd.PersistentFlags().BoolVar(&opts.DebugOCIOperations, "debug-oci", false,
		"Debug OCI index and manifest operations")
	RootCmd.PersistentFlags().BoolVar(&opts.DebugDriverOperations, "debug-drivers", false,
		"Debug driver operations (local, k8s, ci)")
	RootCmd.PersistentFlags().BoolVar(&opts.DebugFilesystem, "debug-filesystem", false,
		"Debug filesystem operations and snapshots")
	RootCmd.PersistentFlags().BoolVar(&opts.DebugCacheOperations, "debug-cache", false,
		"Debug cache operations and layer management")
	RootCmd.PersistentFlags().BoolVar(&opts.DebugRegistry, "debug-registry", false,
		"Debug registry push/pull operations")
	RootCmd.PersistentFlags().BoolVar(&opts.DebugSigning, "debug-signing", false,
		"Debug image signing operations")
	RootCmd.PersistentFlags().BoolVar(&opts.OutputDebugFiles, "debug-output-files", false,
		"Output debug information to files")
	RootCmd.PersistentFlags().StringVar(&opts.DebugLogLevel, "debug-level", "debug",
		"Debug log level (trace, debug, info)")
	RootCmd.PersistentFlags().StringSliceVar(&opts.DebugComponents, "debug-components", []string{},
		"Specific components to debug (comma-separated)")
}

// addRegistryFlags adds registry-related flags
func addRegistryFlags() {
	RootCmd.PersistentFlags().BoolVarP(&opts.Insecure, "insecure", "", false,
		"Push to insecure registry using plain HTTP")
	RootCmd.PersistentFlags().BoolVarP(&opts.SkipTLSVerify, "skip-tls-verify", "", false,
		"Push to insecure registry ignoring TLS verify")
	RootCmd.PersistentFlags().BoolVarP(&opts.InsecurePull, "insecure-pull", "", false,
		"Pull from insecure registry using plain HTTP")
	RootCmd.PersistentFlags().BoolVarP(&opts.SkipTLSVerifyPull, "skip-tls-verify-pull", "", false,
		"Pull from insecure registry ignoring TLS verify")
	RootCmd.PersistentFlags().IntVar(&opts.PushRetry, "push-retry", 0,
		"Number of retries for the push operation")
	RootCmd.PersistentFlags().IntVar(&opts.PushRetryInitialDelay, "push-retry-initial-delay", defaultPushRetryInitialDelay,
		"Initial delay in milliseconds between push retry attempts")
	RootCmd.PersistentFlags().IntVar(&opts.PushRetryMaxDelay, "push-retry-max-delay", defaultPushRetryMaxDelay,
		"Maximum delay in milliseconds between push retry attempts")
	RootCmd.PersistentFlags().Float64Var(&opts.PushRetryBackoffMultiplier,
		"push-retry-backoff-multiplier", defaultPushRetryBackoffMultiplier,
		"Exponential backoff multiplier for push retry delays")
	RootCmd.PersistentFlags().BoolVar(&opts.PushIgnoreImmutableTagErrors,
		"push-ignore-immutable-tag-errors", false,
		"If true, known tag immutability errors are ignored and the push finishes with success.")
	RootCmd.PersistentFlags().VarP(&opts.InsecureRegistries, "insecure-registry", "",
		"Insecure registry using plain HTTP to push and pull. Set it repeatedly for multiple registries.")
	RootCmd.PersistentFlags().VarP(&opts.SkipTLSVerifyRegistries, "skip-tls-verify-registry", "",
		"Insecure registry ignoring TLS verify to push and pull. Set it repeatedly for multiple registries.")
	opts.RegistriesCertificates = make(map[string]string)
	RootCmd.PersistentFlags().VarP(&opts.RegistriesCertificates, "registry-certificate", "",
		"Use the provided certificate for TLS communication with the given registry. "+
			"Expected format is 'my.registry.url=/path/to/the/server/certificate'.")
	opts.RegistriesClientCertificates = make(map[string]string)
	RootCmd.PersistentFlags().VarP(&opts.RegistriesClientCertificates, "registry-client-cert", "",
		"Use the provided client certificate for mutual TLS (mTLS) communication with the given registry. "+
			"Expected format is 'my.registry.url=/path/to/client/cert,/path/to/client/key'.")
	opts.RegistryMaps = make(map[string][]string)
	RootCmd.PersistentFlags().VarP(&opts.RegistryMaps, "registry-map", "",
		"Registry map of mirror to use as pull-through cache instead. "+
			"Expected format is 'orignal.registry=new.registry;other-original.registry=other-remap.registry'")
	RootCmd.PersistentFlags().VarP(&opts.RegistryMirrors, "registry-mirror", "",
		"Registry mirror to use as pull-through cache instead of docker.io. "+
			"Set it repeatedly for multiple mirrors.")
	RootCmd.PersistentFlags().BoolVarP(&opts.SkipDefaultRegistryFallback,
		"skip-default-registry-fallback", "", false,
		"If an image is not found on any mirrors (defined with registry-mirror) "+
			"do not fallback to the default registry. "+
			"If registry-mirror is not defined, this flag is ignored.")
	RootCmd.PersistentFlags().VarP(&opts.CredentialHelpers, "credential-helpers", "",
		"Use these credential helpers automatically, select from (env, google, ecr, acr, gitlab). "+
			"Set it repeatedly for multiple helpers, defaults to all, set it to empty string to deactivate.")
}

// addCacheFlags adds caching-related flags
func addCacheFlags() {
	RootCmd.PersistentFlags().BoolVarP(&opts.NoPushCache, "no-push-cache", "", false,
		"Do not push the cache layers to the registry")
	RootCmd.PersistentFlags().StringVarP(&opts.CacheRepo, "cache-repo", "", "",
		"Specify a repository to use as a cache, otherwise one will be inferred from the destination provided; "+
			"when prefixed with 'oci:' the repository will be written in OCI image layout format at the path provided")
	RootCmd.PersistentFlags().StringVarP(&opts.CacheDir, "cache-dir", "", "/cache",
		"Specify a local directory to use as a cache.")
	RootCmd.PersistentFlags().BoolVarP(&opts.Cache, "cache", "", false,
		"Use cache when building image")
	RootCmd.PersistentFlags().BoolVarP(&opts.CompressedCaching, "compressed-caching", "", true,
		"Compress the cached layers. Decreases build time, but increases memory usage.")
	RootCmd.PersistentFlags().DurationVarP(&opts.CacheTTL, "cache-ttl", "", defaultCacheTTL,
		"Cache timeout, requires value and unit of duration -> ex: 6h. Defaults to two weeks.")
	RootCmd.PersistentFlags().IntVar(&opts.ImageFSExtractRetry, "image-fs-extract-retry", 0,
		"Number of retries for image FS extraction")
	RootCmd.PersistentFlags().IntVar(&opts.ImageDownloadRetry, "image-download-retry", 0,
		"Number of retries for downloading the remote image")
	RootCmd.PersistentFlags().BoolVarP(&opts.CacheCopyLayers, "cache-copy-layers", "", false,
		"Caches copy layers")
	RootCmd.PersistentFlags().BoolVarP(&opts.CacheRunLayers, "cache-run-layers", "", true,
		"Caches run layers")

	// Local cache optimization flags (experimental)
	RootCmd.PersistentFlags().BoolVarP(&opts.LocalCacheUseMMap, "local-cache-use-mmap", "", false,
		"Use memory-mapped files for faster local cache access (experimental). Default: false")
	RootCmd.PersistentFlags().BoolVarP(&opts.LocalCacheCompress, "local-cache-compress", "", false,
		"Compress local cache files to save disk space (experimental). Default: false")
	// Set default value before registering the flag
	opts.LocalCacheCompression = config.ZStd
	RootCmd.PersistentFlags().VarP(&opts.LocalCacheCompression, "local-cache-compression", "",
		"Compression algorithm for local cache (gzip, zstd). Default: zstd (experimental)")
}

// addBuildFlags adds build-related flags
func addBuildFlags() {
	addBasicBuildFlags()
	addOutputFlags()
	addSnapshotFlags()
	addUserConfigFlags()
	addFileSizeLimitFlags()
	addPerformanceFlags()
	addResourceControlFlags()
	addParallelExecutionFlags()
	addSecurityFlags()
	addUnifiedCacheFlags()
}

func addBasicBuildFlags() {
	RootCmd.PersistentFlags().StringVarP(&opts.KanikoDir, "kaniko-dir", "", constants.DefaultKanikoPath,
		"Path to the kaniko directory, this takes precedence over the KANIKO_DIR environment variable.")
	RootCmd.PersistentFlags().StringVarP(&opts.TarPath, "tar-path", "", "",
		"Path to save the image in as a tarball instead of pushing")
	RootCmd.PersistentFlags().BoolVarP(&opts.Reproducible, "reproducible", "", false,
		"Strip timestamps out of the image to make it reproducible")
	RootCmd.PersistentFlags().BoolVarP(&opts.NoPush, "no-push", "", false,
		"Do not push the image to the registry")
	// Set default value before registering the flag
	opts.Compression = config.ZStd
	RootCmd.PersistentFlags().VarP(&opts.Compression, "compression", "",
		"Compression algorithm (gzip, zstd). Default: zstd for better performance")
	RootCmd.PersistentFlags().IntVarP(&opts.CompressionLevel, "compression-level", "", defaultCompressionLevel,
		"Compression level (default: 2 for zstd, balance between speed and CPU usage)")
	RootCmd.PersistentFlags().BoolVarP(&opts.Cleanup, "cleanup", "", false,
		"Clean the filesystem at the end")
	RootCmd.PersistentFlags().VarP(&opts.Labels, "label", "",
		"Set metadata for an image. Set it repeatedly for multiple labels.")
	RootCmd.PersistentFlags().BoolVarP(&opts.SkipUnusedStages, "skip-unused-stages", "", false,
		"Build only used stages if defined to true. Otherwise it builds by default all stages, "+
			"even the unnecessaries ones until it reaches the target stage / end of Dockerfile")
	RootCmd.PersistentFlags().BoolVarP(&opts.RunV2, "use-new-run", "", false,
		"Use the experimental run implementation for detecting changes without requiring file system snapshots.")
	RootCmd.PersistentFlags().BoolVarP(&opts.PreserveContext, "preserve-context", "", false,
		"Preserve build context across build stages by taking a snapshot of the full filesystem "+
			"before build and restore it after we switch stages. Restores in the end too if passed together with 'cleanup'")
	RootCmd.PersistentFlags().BoolVarP(&opts.UseOCIStages, "use-oci-stages", "", false,
		"Use OCI image layout for intermediate stages instead of tarballs. "+
			"Improves performance and OCI compatibility. Can also be enabled via FF_KANIKO_OCI_STAGES environment variable.")
	RootCmd.PersistentFlags().BoolVarP(&opts.Materialize, "materialize", "", false,
		"Guarantee that the final state of the file system corresponds to what was specified "+
			"as the build target, even if we have 100% cache hitrate and wouldn't need to unpack any layers")
	RootCmd.PersistentFlags().BoolVarP(&opts.PreCleanup, "pre-cleanup", "", false,
		"Clean the filesystem prior to build, allowing customized kaniko images to work properly")
}

func addOutputFlags() {
	RootCmd.PersistentFlags().StringVarP(&opts.DigestFile, "digest-file", "", "",
		"Specify a file to save the digest of the built image to.")
	RootCmd.PersistentFlags().StringVarP(&opts.ImageNameDigestFile, "image-name-with-digest-file", "", "",
		"Specify a file to save the image name w/ digest of the built image to.")
	RootCmd.PersistentFlags().StringVarP(&opts.ImageNameTagDigestFile, "image-name-tag-with-digest-file", "", "",
		"Specify a file to save the image name w/ image tag w/ digest of the built image to.")
	RootCmd.PersistentFlags().StringVarP(&opts.OCILayoutPath, "oci-layout-path", "", "",
		"Path to save the OCI image layout of the built image.")
}

func addSnapshotFlags() {
	RootCmd.PersistentFlags().BoolVarP(&opts.SingleSnapshot, "single-snapshot", "", false,
		"Take a single snapshot at the end of the build.")
	RootCmd.PersistentFlags().BoolVarP(&opts.IgnoreVarRun, "ignore-var-run", "", true,
		"Ignore /var/run directory when taking image snapshot. "+
			"Set it to false to preserve /var/run/ in destination image.")
	RootCmd.PersistentFlags().VarP(&opts.IgnorePaths, "ignore-path", "",
		"Ignore these paths when taking a snapshot. Set it repeatedly for multiple paths.")
	RootCmd.PersistentFlags().BoolVarP(&opts.ForceBuildMetadata, "force-build-metadata", "", false,
		"Force add metadata layers to build image")
}

func addUserConfigFlags() {
	RootCmd.PersistentFlags().StringVarP(&opts.DefaultUser, "default-user", "", "",
		"Default user to use when no USER instruction is present (default: root, Docker-compatible). "+
			"Examples: --default-user=appuser, --default-user=nobody. "+
			"⚠️ SECURITY: For production, specify non-root users in your Dockerfile with USER instruction.")
}

func addFileSizeLimitFlags() {
	RootCmd.PersistentFlags().StringVarP(&opts.MaxFileSize, "max-file-size", "", "",
		"Maximum size for individual files (e.g., 500MB, 1GB). Default: 500MB")
	RootCmd.PersistentFlags().StringVarP(&opts.MaxTarFileSize, "max-tar-file-size", "", "",
		"Maximum size for files in tar archives (e.g., 5GB, 10GB). Default: 5GB")
	RootCmd.PersistentFlags().StringVarP(&opts.MaxTotalArchiveSize, "max-total-archive-size", "", "",
		"Maximum total size for all files in an archive (e.g., 10GB, 20GB). Default: 10GB")
}

func addPerformanceFlags() {
	RootCmd.PersistentFlags().BoolVarP(&opts.IncrementalSnapshots, "incremental-snapshots", "", true,
		"Enable incremental snapshots for better performance (enabled by default per plan)")
	RootCmd.PersistentFlags().IntVarP(&opts.MaxExpectedChanges, "max-expected-changes", "", maxExpectedChanges,
		"Maximum expected changes before triggering full scan (incremental snapshots)")
	RootCmd.PersistentFlags().BoolVarP(&opts.IntegrityCheck, "integrity-check", "", true,
		"Enable integrity checks for incremental snapshots")
	RootCmd.PersistentFlags().BoolVarP(&opts.FullScanBackup, "full-scan-backup", "", true,
		"Enable full scan backup when integrity concerns are detected")
}

func addResourceControlFlags() {
	RootCmd.PersistentFlags().Int64VarP(&opts.MaxMemoryUsageBytes, "max-memory-usage-bytes", "", maxMemoryUsageBytes,
		"Maximum memory usage in bytes (e.g., 2GB, 4GB). Default: 2GB")
	RootCmd.PersistentFlags().Int64VarP(&opts.MaxFileSizeBytes, "max-file-size-bytes", "", maxFileSizeBytes,
		"Maximum single file size in bytes (e.g., 500MB, 1GB). Default: 500MB")
	RootCmd.PersistentFlags().Int64VarP(&opts.MaxTotalFileSizeBytes, "max-total-file-size-bytes", "",
		maxTotalFileSizeBytes, "Maximum total file size in bytes (e.g., 10GB, 20GB). Default: 10GB")
	RootCmd.PersistentFlags().BoolVarP(&opts.MemoryMonitoring, "memory-monitoring", "", true,
		"Enable memory monitoring and automatic garbage collection")
	RootCmd.PersistentFlags().IntVarP(&opts.GCThreshold, "gc-threshold", "", gcThreshold,
		"Memory usage percentage threshold for triggering garbage collection (1-100). Default: 80")
	RootCmd.PersistentFlags().IntVarP(&opts.MonitoringInterval, "monitoring-interval", "", monitoringInterval,
		"Memory monitoring interval in seconds. Default: 5")
}

func addParallelExecutionFlags() {
	RootCmd.PersistentFlags().IntVarP(&opts.MaxParallelCommands, "max-parallel-commands", "", 0,
		"Maximum number of commands to execute in parallel (0 = auto-detect based on CPU cores). Default: auto-detect")
	RootCmd.PersistentFlags().DurationVarP(&opts.CommandTimeout, "command-timeout", "", defaultCommandTimeout*time.Minute,
		"Timeout for command execution (e.g., 30m, 1h). Default: 30m")
	RootCmd.PersistentFlags().BoolVarP(&opts.EnableParallelExec, "enable-parallel-exec", "", false,
		"Enable parallel execution of independent commands (experimental). Default: false (sequential execution is default)")
	RootCmd.PersistentFlags().BoolVarP(&opts.OptimizeExecutionOrder, "optimize-execution-order", "", true,
		"Use dependency graph to optimize command execution order. Default: true (enabled per plan)")
	RootCmd.PersistentFlags().BoolVarP(&opts.EnableLazyImageLoading, "enable-lazy-image-loading", "", true,
		"Load image layers on demand for memory optimization. Default: true (enabled per plan)")

	// CPU resource limits (for optimization and multiple parallel builds)
	RootCmd.PersistentFlags().IntVarP(&opts.MaxWorkers, "max-workers", "", 0,
		"Maximum number of workers for parallel operations (0 = auto: min(6, NumCPU), max: 8). "+
			"Conservative default to avoid excessive CPU usage with multiple parallel builds. Default: auto")
	RootCmd.PersistentFlags().IntVarP(&opts.MaxParallelHashing, "max-parallel-hashing", "", 0,
		"Maximum number of parallel file hashing operations (0 = auto: 4). "+
			"Conservative default for CPU-intensive hashing. Default: 4")
	RootCmd.PersistentFlags().IntVarP(&opts.MaxParallelCopy, "max-parallel-copy", "", 0,
		"Maximum number of parallel file copy operations (0 = auto: 2). "+
			"Conservative default for I/O-bound operations. Default: 2")
	RootCmd.PersistentFlags().BoolVar(&opts.DisableCompression, "disable-compression", false,
		"Disable layer compression for maximum speed (increases layer size but reduces CPU usage)")

	// Default max file hash size: 10MB (10 * 1024 * 1024 bytes)
	const defaultMaxFileHashSizeBytes = 10 * 1024 * 1024
	RootCmd.PersistentFlags().Int64VarP(&opts.MaxFileHashSize, "max-file-hash-size", "", defaultMaxFileHashSizeBytes,
		"Maximum file size for full hashing in bytes (files larger use partial hashing: first+last 64KB + size). "+
			"Default: 10MB (10485760 bytes)")
}

func addSecurityFlags() {
	RootCmd.PersistentFlags().BoolVarP(&opts.GenerateProvenance, "generate-provenance", "", false,
		"Generate SLSA provenance attestation for supply chain security. Default: false")
	RootCmd.PersistentFlags().BoolVarP(&opts.SkipPushPermissionCheck, "skip-push-permission-check", "", false,
		"Skip check of the push permission")
	RootCmd.PersistentFlags().StringSliceVar(&allowedRegistries, "allowed-registries", []string{},
		"List of allowed registry patterns (wildcards supported). Example: --allowed-registries=gcr.io/*,docker.io/*")
	RootCmd.PersistentFlags().StringSliceVar(&deniedRegistries, "denied-registries", []string{},
		"List of denied registry patterns (wildcards supported). Example: --denied-registries=untrusted.io/*")
	RootCmd.PersistentFlags().StringSliceVar(&allowedRepos, "allowed-repos", []string{},
		"List of allowed repository patterns (wildcards supported)")
	RootCmd.PersistentFlags().StringSliceVar(&deniedRepos, "denied-repos", []string{},
		"List of denied repository patterns (wildcards supported)")
	RootCmd.PersistentFlags().BoolVar(&requireSignature, "require-signature", false,
		"Require images to be signed (source policy validation)")
}

func addUnifiedCacheFlags() {
	RootCmd.PersistentFlags().BoolVarP(&opts.EnableUnifiedCache, "enable-unified-cache", "", true,
		"Enable unified cache for combining multiple cache sources (local, registry, S3, etc.). "+
			"Default: true for better performance")
	RootCmd.PersistentFlags().IntVarP(&opts.MaxCacheEntries, "max-cache-entries", "", defaultMaxCacheEntries,
		"Maximum number of entries in the LRU cache. Default: 2000 (optimized for 1GB cache)")
	RootCmd.PersistentFlags().IntVarP(&opts.MaxPreloadSize, "max-preload-size", "", defaultMaxPreloadSize,
		"Maximum number of images to preload. Default: 100 (increased for better performance)")
	RootCmd.PersistentFlags().DurationVarP(&opts.PreloadTimeout, "preload-timeout", "", defaultPreloadTimeout*time.Minute,
		"Timeout for preload operations (e.g., 5m, 10m). Default: 10m (increased for large cache)")
	RootCmd.PersistentFlags().BoolVarP(&opts.EnableSmartCache, "enable-smart-cache", "", true,
		"Enable smart cache with LRU and preloading capabilities. Default: enabled for better performance")
	RootCmd.PersistentFlags().IntVarP(&opts.MaxConcurrentCacheChecks,
		"max-concurrent-cache-checks", "", defaultMaxConcurrentCacheChecks,
		"Maximum number of concurrent cache checks. Default: 5 for optimal balance between speed and resource usage")

	// Network concurrency limits
	RootCmd.PersistentFlags().IntVarP(&opts.MaxNetworkConcurrency, "max-network-concurrency", "", 0,
		"Maximum number of parallel network requests (0 = auto: 5). "+
			"Conservative default for I/O-bound network operations. Default: 5")

	// Connection pooling flags for registry cache
	RootCmd.PersistentFlags().IntVarP(&opts.CacheMaxConns, "cache-max-conns", "", defaultCacheMaxConns,
		"Maximum number of idle connections in the connection pool. Default: 10")
	RootCmd.PersistentFlags().IntVarP(&opts.CacheMaxConnsPerHost,
		"cache-max-conns-per-host", "", defaultCacheMaxConnsPerHost,
		"Maximum number of idle connections per host. Default: 5")
	RootCmd.PersistentFlags().IntVarP(&opts.CacheMaxConcurrentRequests,
		"cache-max-concurrent-requests", "", defaultCacheMaxConcurrentRequests,
		"Maximum number of concurrent requests to registry. Default: 5")
	RootCmd.PersistentFlags().BoolVarP(&opts.CacheDisableHTTP2, "cache-disable-http2", "", false,
		"Disable HTTP/2 for cache requests (use HTTP/1.1). Default: false (HTTP/2 enabled)")
	RootCmd.PersistentFlags().DurationVarP(
		&opts.CacheRequestTimeout, "cache-request-timeout", "", defaultCacheRequestTimeout,
		"Timeout for cache requests to registry. Default: 30s")

	// Aggressive prefetching flags
	RootCmd.PersistentFlags().IntVarP(&opts.PrefetchWindow, "prefetch-window", "", defaultPrefetchWindow,
		"Number of next commands to prefetch cache keys for. Default: 10 (increased from 3 for better cache hit rate)")

	// Cache result caching flags
	RootCmd.PersistentFlags().DurationVarP(&opts.CacheResultTTL, "cache-result-ttl", "", defaultCacheResultTTL,
		"TTL for cached cache check results. Default: 5m")
	RootCmd.PersistentFlags().IntVarP(&opts.CacheResultMaxEntries,
		"cache-result-max-entries", "", defaultCacheResultMaxEntries,
		"Maximum number of cached cache check results. Default: 1000")
	RootCmd.PersistentFlags().IntVarP(&opts.CacheResultMaxMemoryMB,
		"cache-result-max-memory-mb", "", defaultCacheResultMaxMemoryMB,
		"Maximum memory usage for cached cache check results in MB. Default: 100 MB")

	// File hash cache flags
	RootCmd.PersistentFlags().IntVarP(&opts.FileHashCacheMaxEntries,
		"file-hash-cache-max-entries", "", defaultFileHashCacheMaxEntries,
		"Maximum number of cached file hashes. Default: 10000")
	RootCmd.PersistentFlags().IntVarP(&opts.FileHashCacheMaxMemoryMB,
		"file-hash-cache-max-memory-mb", "", defaultFileHashCacheMaxMemoryMB,
		"Maximum memory usage for cached file hashes in MB. Default: 200 MB")

	// Parallel layer loading flags
	RootCmd.PersistentFlags().IntVarP(&opts.LayerLoadMaxConcurrent,
		"layer-load-max-concurrent", "", defaultLayerLoadMaxConcurrent,
		"Maximum number of concurrent layer loads from cache. Default: 3")

	// Predictive caching flags (experimental)
	RootCmd.PersistentFlags().BoolVarP(&opts.EnablePredictiveCache, "enable-predictive-cache", "", false,
		"Enable predictive caching to prefetch layers based on build history patterns (experimental). Default: false")
	RootCmd.PersistentFlags().IntVarP(&opts.PredictiveCacheMaxLayers,
		"predictive-cache-max-layers", "", defaultPredictiveCacheMaxLayers,
		"Maximum number of layers to prefetch with predictive caching. Default: 20")
	RootCmd.PersistentFlags().IntVarP(&opts.PredictiveCacheMaxMemoryMB,
		"predictive-cache-max-memory-mb", "", defaultPredictiveCacheMaxMemoryMB,
		"Maximum memory (MB) to use for predictive cache prefetching. Default: 50 MB")
}

// addMultiPlatformFlags adds multi-platform build flags
func addMultiPlatformFlags() {
	RootCmd.PersistentFlags().VarP(&opts.MultiPlatform, "multi-platform", "",
		"Platforms to build for (comma-separated), e.g. linux/amd64,linux/arm64")
	RootCmd.PersistentFlags().BoolVar(&opts.PublishIndex, "publish-index", false,
		"Publish OCI Image Index or Docker Manifest List after building all platforms")
	RootCmd.PersistentFlags().BoolVar(&opts.LegacyManifestList, "legacy-manifest-list", false,
		"Create Docker Manifest List instead of OCI Image Index for backward compatibility")
	opts.IndexAnnotations = make(map[string]string)
	RootCmd.PersistentFlags().VarP(&opts.IndexAnnotations, "index-annotations", "",
		"Annotations for the image index (comma-separated key=value pairs)")
	RootCmd.PersistentFlags().StringVar(&opts.ArchCacheRepoSuffix, "arch-cache-repo-suffix", "-${ARCH}",
		"Suffix pattern for architecture-specific cache repositories")
	RootCmd.PersistentFlags().StringVar(&opts.Driver, "driver", "local",
		"Multi-platform driver to use: local, k8s, or ci")
	RootCmd.PersistentFlags().StringVar(&opts.DigestsFrom, "digests-from", "",
		"Path to read digests from for CI driver mode")
	RootCmd.PersistentFlags().BoolVar(&opts.RequireNativeNodes, "require-native-nodes", true,
		"Require native architecture nodes for Kubernetes driver")
	RootCmd.PersistentFlags().StringVar(&opts.OCIMode, "oci-mode", "auto",
		"OCI compliance mode: oci, docker, or auto")
}

// addDeprecatedFlags adds deprecated flags
func addDeprecatedFlags() {
	RootCmd.PersistentFlags().StringVarP(&opts.SnapshotModeDeprecated, "snapshotMode", "", "",
		"This flag is deprecated. Please use '--snapshot-mode'.")
	RootCmd.PersistentFlags().StringVarP(&opts.CustomPlatformDeprecated, "customPlatform", "", "",
		"This flag is deprecated. Please use '--custom-platform'.")
	RootCmd.PersistentFlags().StringVarP(&opts.TarPath, "tarPath", "", "",
		"This flag is deprecated. Please use '--tar-path'.")
}

// addHiddenFlags marks certain flags as hidden from the executor help text
func addHiddenFlags(cmd *cobra.Command) {
	// Hide this flag as we want to encourage people to use the --context flag instead
	if err := cmd.PersistentFlags().MarkHidden("bucket"); err != nil {
		logrus.Warnf("Failed to hide flag: %v", err)
	}
}

// checkKanikoDir will check whether the executor is operating in the default '/kaniko' directory,
// conducting the relevant operations if it is not
func checkKanikoDir(dir string) error {
	if dir != filepath.Clean(constants.DefaultKanikoPath) {
		// The destination directory may be across a different partition, so we cannot simply rename/move the directory.
		if _, err := util.CopyDir(constants.DefaultKanikoPath, dir, util.FileContext{},
			util.DoNotChangeUID, util.DoNotChangeGID, fs.FileMode(filePermission), true); err != nil {
			return err
		}

		if err := os.RemoveAll(constants.DefaultKanikoPath); err != nil {
			return err
		}
		// After remove DefaultKankoPath, the DOCKER_CONFIG env will point to a non-exist dir,
		// so we should update DOCKER_CONFIG env to new dir
		if err := os.Setenv("DOCKER_CONFIG", filepath.Join(dir, ".docker")); err != nil {
			return err
		}
	}
	return nil
}

func checkContained() bool {
	return proc.GetContainerRuntime(0, 0) != proc.RuntimeNotFound
}

// checkNoDeprecatedFlags return an error if deprecated flags are used.
func checkNoDeprecatedFlags() {
	// In version >=2.0.0 make it fail (`Warn` -> `Fatal`)
	if opts.CustomPlatformDeprecated != "" {
		logrus.Warn("Flag --customPlatform is deprecated. Use: --custom-platform")
		opts.CustomPlatform = opts.CustomPlatformDeprecated
	}

	if opts.SnapshotModeDeprecated != "" {
		logrus.Warn("Flag --snapshotMode is deprecated. Use: --snapshot-mode")
		opts.SnapshotMode = opts.SnapshotModeDeprecated
	}

	if opts.TarPathDeprecated != "" {
		logrus.Warn("Flag --tarPath is deprecated. Use: --tar-path")
		opts.TarPath = opts.TarPathDeprecated
	}
}

// cacheFlagsValid makes sure the flags passed in related to caching are valid
func cacheFlagsValid() error {
	if !opts.Cache {
		return nil
	}
	// If --cache=true and --no-push=true, then cache repo must be provided
	// since cache can't be inferred from destination
	if opts.CacheRepo == "" && opts.NoPush {
		return errors.New("if using cache with --no-push, specify cache repo with --cache-repo")
	}
	return nil
}

// resolveDockerfilePath resolves the Dockerfile path to an absolute path
func resolveDockerfilePath() error {
	if isURL(opts.DockerfilePath) {
		return nil
	}
	if util.FilepathExists(opts.DockerfilePath) {
		abs, err := filepath.Abs(opts.DockerfilePath)
		if err != nil {
			return errors.Wrap(err, "getting absolute path for dockerfile")
		}
		opts.DockerfilePath = abs
		return copyDockerfile()
	}
	// Otherwise, check if the path relative to the build context exists
	if util.FilepathExists(filepath.Join(opts.SrcContext, opts.DockerfilePath)) {
		abs, err := filepath.Abs(filepath.Join(opts.SrcContext, opts.DockerfilePath))
		if err != nil {
			return errors.Wrap(err, "getting absolute path for src context/dockerfile path")
		}
		opts.DockerfilePath = abs
		return copyDockerfile()
	}
	return errors.New("please provide a valid path to a Dockerfile within the build context with --dockerfile")
}

// resolveEnvironmentBuildArgs replace build args without value by the same named environment variable
// and add all build args to the environment for RUN commands
func resolveEnvironmentBuildArgs(arguments []string, resolver func(string) string) {
	for index, argument := range arguments {
		i := strings.Index(argument, "=")
		if i < 0 {
			value := resolver(argument)
			arguments[index] = fmt.Sprintf("%s=%s", argument, value)
		}
	}

	// CRITICAL FIX: Add all build args to the environment
	// This ensures that build args are available in RUN commands
	for _, argument := range arguments {
		if argument != "" {
			// Parse the argument to extract key and value
			const keyValueParts = 2
			parts := strings.SplitN(argument, "=", keyValueParts)
			if len(parts) == keyValueParts {
				key := parts[0]
				value := parts[1]
				// Set the environment variable in the current process
				// This will be inherited by RUN commands
				if err := os.Setenv(key, value); err != nil {
					logrus.Warnf("Failed to set environment variable %s: %v", argument, err)
				} else {
					logrus.Debugf("Added build arg to environment: %s=%s", key, value)
				}
			} else {
				logrus.Warnf("Invalid build arg format: %s (expected key=value)", argument)
			}
		}
	}
}

// copy Dockerfile to /kaniko/Dockerfile so that if it's specified in the .dockerignore
// it won't be copied into the image
func copyDockerfile() error {
	if _, err := util.CopyFile(opts.DockerfilePath, config.DockerfilePath, util.FileContext{},
		util.DoNotChangeUID, util.DoNotChangeGID, fs.FileMode(filePermission), true); err != nil {
		return errors.Wrap(err, "copying dockerfile")
	}
	dockerignorePath := opts.DockerfilePath + ".dockerignore"
	if util.FilepathExists(dockerignorePath) {
		if _, err := util.CopyFile(dockerignorePath, config.DockerfilePath+".dockerignore", util.FileContext{},
			util.DoNotChangeUID, util.DoNotChangeGID, fs.FileMode(filePermission), true); err != nil {
			return errors.Wrap(err, "copying Dockerfile.dockerignore")
		}
	}
	opts.DockerfilePath = config.DockerfilePath
	return nil
}

// resolveSourceContext unpacks the source context if it is a tar in a bucket or in kaniko container
// it resets srcContext to be the path to the unpacked build context within the image
func resolveSourceContext() error {
	if opts.SrcContext == "" && opts.Bucket == "" {
		return errors.New("please specify a path to the build context with the --context flag " +
			"or a bucket with the --bucket flag")
	}
	if opts.SrcContext != "" && !strings.Contains(opts.SrcContext, "://") {
		return nil
	}
	if opts.Bucket != "" {
		if !strings.Contains(opts.Bucket, "://") {
			// if no prefix use Google Cloud Storage as default for backwards compatibility
			opts.SrcContext = constants.GCSBuildContextPrefix + opts.Bucket
		} else {
			opts.SrcContext = opts.Bucket
		}
	}
	contextExecutor, err := buildcontext.GetBuildContext(opts.SrcContext, buildcontext.BuildOptions{
		GitBranch:            opts.Git.Branch,
		GitSingleBranch:      opts.Git.SingleBranch,
		GitRecurseSubmodules: opts.Git.RecurseSubmodules,
		InsecureSkipTLS:      opts.Git.InsecureSkipTLS,
	})
	if err != nil {
		return err
	}
	logrus.Debugf("Getting source context from %s", opts.SrcContext)
	opts.SrcContext, err = contextExecutor.UnpackTarFromBuildContext()
	if err != nil {
		return err
	}
	if ctxSubPath != "" {
		opts.SrcContext = filepath.Join(opts.SrcContext, ctxSubPath)
		if _, err := os.Stat(opts.SrcContext); os.IsNotExist(err) {
			return err
		}
	}
	logrus.Debugf("Build context located at %s", opts.SrcContext)
	return nil
}

func resolveRelativePaths() error {
	optsPaths := []*string{
		&opts.DockerfilePath,
		&opts.SrcContext,
		&opts.CacheDir,
		&opts.TarPath,
		&opts.DigestFile,
		&opts.ImageNameDigestFile,
		&opts.ImageNameTagDigestFile,
	}

	for _, p := range optsPaths {
		if path := *p; shdSkip(path) {
			logrus.Debugf("Skip resolving path %s", path)
			continue
		}

		// Resolve relative path to absolute path
		var err error
		relp := *p // save original relative path
		if *p, err = filepath.Abs(*p); err != nil {
			return errors.Wrapf(err, "Couldn't resolve relative path %s to an absolute path", *p)
		}
		logrus.Debugf("Resolved relative path %s to %s", relp, *p)
	}
	return nil
}

func exit(err error) {
	var execErr *exec.ExitError
	if errors.As(err, &execErr) {
		// if there is an exit code propagate it
		exitWithCode(err, execErr.ExitCode())
	}
	// otherwise exit with catch all 1
	exitWithCode(err, 1)
}

// exits with the given error and exit code
func exitWithCode(err error, exitCode int) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(exitCode)
}

func isURL(path string) bool {
	if match, _ := regexp.MatchString("^https?://", path); match {
		return true
	}
	return false
}

func shdSkip(path string) bool {
	return path == "" || isURL(path) || filepath.IsAbs(path)
}

// executeMultiPlatformBuild handles multi-platform builds using the coordinator
func executeMultiPlatformBuild(opts *config.KanikoOptions) error {
	// Import the multiplatform package to avoid circular imports
	coordinator, err := multiplatform.NewCoordinator(opts)
	if err != nil {
		return errors.Wrap(err, "failed to create multi-platform coordinator")
	}

	// Log the multi-platform configuration
	coordinator.LogMultiPlatformConfig()

	// Execute the multi-platform build
	index, err := coordinator.Execute(context.Background())
	if err != nil {
		return errors.Wrap(err, "multi-platform build failed")
	}

	// Push the index if requested
	if opts.PublishIndex && index != nil {
		if err := oci.PushIndex(index, opts); err != nil {
			return errors.Wrap(err, "failed to push image index")
		}
	}

	// Cleanup
	if err := coordinator.Cleanup(); err != nil {
		logrus.Warnf("Multi-platform cleanup failed: %v", err)
	}

	return nil
}
