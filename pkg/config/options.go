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

package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// CacheOptions are base image cache options that are set by command line arguments
type CacheOptions struct {
	CacheDir string
	CacheTTL time.Duration
}

// RegistryOptions are all the options related to the registries, set by command line arguments.
type RegistryOptions struct {
	RegistryMaps                 multiKeyMultiValueArg
	RegistryMirrors              multiArg
	InsecureRegistries           multiArg
	SkipTLSVerifyRegistries      multiArg
	RegistriesCertificates       keyValueArg
	RegistriesClientCertificates keyValueArg
	SkipDefaultRegistryFallback  bool
	Insecure                     bool
	SkipTLSVerify                bool
	InsecurePull                 bool
	SkipTLSVerifyPull            bool
	PushIgnoreImmutableTagErrors bool
	PushRetry                    int
	PushRetryInitialDelay        int
	PushRetryMaxDelay            int
	PushRetryBackoffMultiplier   float64
	ImageDownloadRetry           int
}

// KanikoOptions are options that are set by command line arguments
type KanikoOptions struct {
	RegistryOptions
	CacheOptions
	Destinations             multiArg
	BuildArgs                multiArg
	Labels                   multiArg
	Git                      KanikoGitOptions
	IgnorePaths              multiArg
	DockerfilePath           string
	SrcContext               string
	SnapshotMode             string
	SnapshotModeDeprecated   string
	CustomPlatform           string
	CustomPlatformDeprecated string
	Bucket                   string
	TarPath                  string
	TarPathDeprecated        string
	KanikoDir                string
	Target                   string
	CacheRepo                string
	DigestFile               string
	ImageNameDigestFile      string
	ImageNameTagDigestFile   string
	OCILayoutPath            string
	Compression              Compression
	CompressionLevel         int
	ImageFSExtractRetry      int
	SingleSnapshot           bool
	Reproducible             bool
	NoPush                   bool
	NoPushCache              bool
	Cache                    bool
	Cleanup                  bool
	CompressedCaching        bool
	IgnoreVarRun             bool
	SkipUnusedStages         bool
	RunV2                    bool
	CacheCopyLayers          bool
	CacheRunLayers           bool
	ForceBuildMetadata       bool
	InitialFSUnpacked        bool
	SkipPushPermissionCheck  bool

	// Multi-platform build options
	MultiPlatform       multiArg         // --multi-platform=linux/amd64,linux/arm64
	PublishIndex        bool             // --publish-index[=true|false]
	LegacyManifestList  bool             // --legacy-manifest-list[=true|false]
	IndexAnnotations    multiKeyValueArg // --index-annotations=key=value,...
	ArchCacheRepoSuffix string           // --arch-cache-repo-suffix=-${ARCH}
	Driver              string           // --driver=[local|k8s|ci]
	DigestsFrom         string           // --digests-from=/path
	RequireNativeNodes  bool             // --require-native-nodes=true
	OCIMode             string           // --oci-mode=[oci|auto|docker]
	SignImages          bool             // --sign-images[=true|false]

	// User configuration options
	DefaultUser       string // --default-user (default: root, Docker-compatible)
	CosignKeyPath     string // --cosign-key-path=/path/to/key
	CosignKeyPassword string // --cosign-key-password=secret

	// File size limit options for security and resource control
	MaxFileSize         string // --max-file-size=500MB
	MaxTarFileSize      string // --max-tar-file-size=5GB
	MaxTotalArchiveSize string // --max-total-archive-size=10GB

	// Performance optimization options
	IncrementalSnapshots bool // --incremental-snapshots=true
	MaxExpectedChanges   int  // --max-expected-changes=1000
	IntegrityCheck       bool // --integrity-check=true
	FullScanBackup       bool // --full-scan-backup=true

	// Resource control options
	MaxMemoryUsageBytes   int64 // --max-memory-usage-bytes=2GB
	MaxFileSizeBytes      int64 // --max-file-size-bytes=500MB
	MaxTotalFileSizeBytes int64 // --max-total-file-size-bytes=10GB
	MemoryMonitoring      bool  // --memory-monitoring=true
	GCThreshold           int   // --gc-threshold=80
	MonitoringInterval    int   // --monitoring-interval=5s

	// Parallel execution options (disabled by default for stability)
	MaxParallelCommands int           // --max-parallel-commands=4 (auto-detect CPU cores)
	CommandTimeout      time.Duration // --command-timeout=30m
	EnableParallelExec  bool          // --enable-parallel-exec=false (disabled by default, sequential is default)
	// --optimize-execution-order=true (use dependency graph to optimize order, enabled by default)
	OptimizeExecutionOrder bool
	// --enable-lazy-image-loading=true (load image layers on demand for memory optimization, enabled by default)
	EnableLazyImageLoading bool

	// Source policy for security (validates image sources before loading)
	// Set via SetSourcePolicy() to avoid circular dependencies
	SourcePolicy interface{} // *policy.SourcePolicy

	// GenerateProvenance enables SLSA provenance attestation generation
	GenerateProvenance bool // --generate-provenance (disabled by default)

	// Smart cache options (optimized for 1GB cache)
	MaxCacheEntries  int           // --max-cache-entries=2000 (optimized for 1GB)
	MaxPreloadSize   int           // --max-preload-size=100 (increased for better performance)
	PreloadTimeout   time.Duration // --preload-timeout=10m (increased for large cache)
	EnableSmartCache bool          // --enable-smart-cache=true (enabled by default)

	// Unified cache options (for combining multiple cache sources)
	EnableUnifiedCache bool // --enable-unified-cache=false (disabled by default)

	// Debug options for enhanced debugging and development
	DebugOptions
}

// DebugOptions are options for enhanced debugging and development
type DebugOptions struct {
	EnableFullDebug       bool     `json:"enableFullDebug" yaml:"enableFullDebug"`
	DebugBuildSteps       bool     `json:"debugBuildSteps" yaml:"debugBuildSteps"`
	DebugMultiPlatform    bool     `json:"debugMultiPlatform" yaml:"debugMultiPlatform"`
	DebugOCIOperations    bool     `json:"debugOCIOperations" yaml:"debugOCIOperations"`
	DebugDriverOperations bool     `json:"debugDriverOperations" yaml:"debugDriverOperations"`
	DebugFilesystem       bool     `json:"debugFilesystem" yaml:"debugFilesystem"`
	DebugCacheOperations  bool     `json:"debugCacheOperations" yaml:"debugCacheOperations"`
	DebugRegistry         bool     `json:"debugRegistry" yaml:"debugRegistry"`
	DebugSigning          bool     `json:"debugSigning" yaml:"debugSigning"`
	OutputDebugFiles      bool     `json:"outputDebugFiles" yaml:"outputDebugFiles"`
	DebugLogLevel         string   `json:"debugLogLevel" yaml:"debugLogLevel"`     // trace, debug, info
	DebugComponents       []string `json:"debugComponents" yaml:"debugComponents"` // specific components to debug
}

// KanikoGitOptions represents Git-specific configuration options
// for handling Git repositories as build contexts
type KanikoGitOptions struct {
	Branch            string
	SingleBranch      bool
	RecurseSubmodules bool
	InsecureSkipTLS   bool
}

// ErrInvalidGitFlag is returned when Git flag format is invalid
var ErrInvalidGitFlag = errors.New("invalid git flag, must be in the key=value format")

// Type returns the string identifier for Git options type
func (k *KanikoGitOptions) Type() string {
	return "gitoptions"
}

func (k *KanikoGitOptions) String() string {
	return fmt.Sprintf("branch=%s,single-branch=%t,recurse-submodules=%t", k.Branch, k.SingleBranch, k.RecurseSubmodules)
}

// Set parses and applies Git configuration options from string format
func (k *KanikoGitOptions) Set(s string) error {
	// splitLimit is the limit for strings.SplitN operations when parsing key=value pairs
	const splitLimit = 2

	var parts = strings.SplitN(s, "=", splitLimit)
	if len(parts) != splitLimit {
		return fmt.Errorf("%w: %s", ErrInvalidGitFlag, s)
	}
	switch parts[0] {
	case "branch":
		k.Branch = parts[1]
	case "single-branch":
		v, err := strconv.ParseBool(parts[1])
		if err != nil {
			return err
		}
		k.SingleBranch = v
	case "recurse-submodules":
		v, err := strconv.ParseBool(parts[1])
		if err != nil {
			return err
		}
		k.RecurseSubmodules = v
	case "insecure-skip-tls":
		v, err := strconv.ParseBool(parts[1])
		if err != nil {
			return err
		}
		k.InsecureSkipTLS = v
	}
	return nil
}

// Compression is an enumeration of the supported compression algorithms
type Compression string

// The collection of known MediaType values.
const (
	GZip Compression = "gzip"
	ZStd Compression = "zstd"
)

func (c *Compression) String() string {
	return string(*c)
}

// Set validates and sets the compression algorithm from string value
func (c *Compression) Set(v string) error {
	switch v {
	case "gzip", "zstd":
		*c = Compression(v)
		return nil
	default:
		return errors.New(`must be either "gzip" or "zstd"`)
	}
}

// Type returns the string identifier for compression type
func (c *Compression) Type() string {
	return "compression"
}

// WarmerOptions are options that are set by command line arguments to the cache warmer.
type WarmerOptions struct {
	CacheOptions
	RegistryOptions
	CustomPlatform string
	Images         multiArg
	Force          bool
	DockerfilePath string
	BuildArgs      multiArg
}
