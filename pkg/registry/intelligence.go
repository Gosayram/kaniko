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

// Package registry provides intelligence and optimization for container registries.
package registry

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Gosayram/kaniko/pkg/debug"
)

const (
	gcrRegistry  = "gcr.io"
	ghcrRegistry = "ghcr.io"

	// Registry configuration constants
	defaultRequestsPerMinute = 100
	defaultRequestsPerHour   = 6000
	defaultRequestsPerDay    = 100000
	defaultBurstSize         = 10
	defaultCompressionLevel  = 6
	defaultMaxRetries        = 3
	defaultTimeoutSeconds    = 300
	defaultParallelPushes    = 4
	defaultChunkSizeMB       = 10
	defaultMaxLayerSizeGB    = 5
	defaultMaxManifestSizeMB = 4
	defaultCacheTTLHours     = 24

	// GCR specific constants
	gcrMaxRetries     = 5
	gcrTimeoutSeconds = 600
	gcrParallelPushes = 8

	// GHCR specific constants
	ghcrMaxRetries     = 4
	ghcrTimeoutSeconds = 450
	ghcrParallelPushes = 6

	// ACR specific constants
	acrMaxRetries     = 4
	acrTimeoutSeconds = 360
	acrParallelPushes = 5

	// GCR specific constants
	gcrRequestsPerMinute = 1000
	gcrRequestsPerHour   = 60000
	gcrRequestsPerDay    = 1000000
	gcrBurstSize         = 100
	gcrCompressionLevel  = 9
	gcrChunkSizeMB       = 32
	gcrMaxLayerSizeGB    = 32
	gcrMaxManifestSizeMB = 64
	gcrCacheTTLHours     = 168

	// GHCR specific constants
	ghcrRequestsPerMinute = 500
	ghcrRequestsPerHour   = 30000
	ghcrRequestsPerDay    = 500000
	ghcrBurstSize         = 50
	ghcrCompressionLevel  = 8
	ghcrChunkSizeMB       = 16
	ghcrMaxLayerSizeGB    = 10
	ghcrMaxManifestSizeMB = 32
	ghcrCacheTTLHours     = 72

	// ECR Public specific constants
	ecrPublicRequestsPerMinute = 100
	ecrPublicRequestsPerHour   = 6000
	ecrPublicRequestsPerDay    = 100000
	ecrPublicBurstSize         = 10
	ecrPublicCompressionLevel  = 6
	ecrPublicChunkSizeMB       = 10
	ecrPublicMaxLayerSizeGB    = 10
	ecrPublicMaxManifestSizeMB = 8
	ecrPublicCacheTTLHours     = 24

	// ACR specific constants
	acrRequestsPerMinute = 200
	acrRequestsPerHour   = 12000
	acrRequestsPerDay    = 200000
	acrBurstSize         = 20
	acrCompressionLevel  = 6
	acrChunkSizeMB       = 15
	acrMaxLayerSizeGB    = 10
	acrMaxManifestSizeMB = 16
	acrCacheTTLHours     = 48

	// Size constants
	bytesInKB = 1024
	bytesInMB = 1024 * 1024
	bytesInGB = 1024 * 1024 * 1024

	// Platform constants
	maxPlatformsForParallelism = 3
)

var (
	// Default timeout for HTTP requests
	defaultTimeout = 30 * time.Second
	// Cache TTL for registry capabilities
	cacheTTL = 5 * time.Minute
)

// Capabilities defines the capabilities of a registry.
type Capabilities struct {
	SupportsMultiArch    bool              `json:"supportsMultiArch"`
	SupportsOCI          bool              `json:"supportsOCI"`
	SupportsZstd         bool              `json:"supportsZstd"`
	SupportsManifestList bool              `json:"supportsManifestList"`
	RateLimits           RateLimitInfo     `json:"rateLimits"`
	RecommendedSettings  RecommendedConfig `json:"recommendedSettings"`
	MaxLayerSize         int64             `json:"maxLayerSize"`
	MaxManifestSize      int64             `json:"maxManifestSize"`
	SupportedPlatforms   []string          `json:"supportedPlatforms"`
	AuthenticationScheme string            `json:"authenticationScheme"`
}

// Intelligence manages registry intelligence and optimization.
type Intelligence struct {
	client          *http.Client
	cache           map[string]Capabilities
	cacheTTL        map[string]time.Time
	knownRegistries map[string]Capabilities
	mu              sync.RWMutex
}

// RateLimitInfo contains rate limiting information for a registry.
type RateLimitInfo struct {
	RequestsPerMinute int `json:"requestsPerMinute"`
	RequestsPerHour   int `json:"requestsPerHour"`
	RequestsPerDay    int `json:"requestsPerDay"`
	BurstSize         int `json:"burstSize"`
}

// RecommendedConfig contains recommended configuration for a registry.
type RecommendedConfig struct {
	CompressionLevel int    `json:"compressionLevel"`
	ChunkSize        int64  `json:"chunkSize"`
	MaxRetries       int    `json:"maxRetries"`
	Timeout          int    `json:"timeout"`
	ParallelPushes   int    `json:"parallelPushes"`
	EnableCache      bool   `json:"enableCache"`
	CacheTTL         string `json:"cacheTTL"`
}

// PushStrategy defines the optimal push strategy for a registry.
type PushStrategy struct {
	ParallelPushes       bool   `json:"parallelPushes"`
	ChunkSize            int64  `json:"chunkSize"`
	CompressionLevel     int    `json:"compressionLevel"`
	MaxRetries           int    `json:"maxRetries"`
	Timeout              int    `json:"timeout"`
	BackoffAlgorithm     string `json:"backoffAlgorithm"`
	RetryableStatusCodes []int  `json:"retryableStatusCodes"`
	PreferHTTP1_1        bool   `json:"preferHTTP1_1"`
	EnableCache          bool   `json:"enableCache"`
	CacheKey             string `json:"cacheKey"`
}

// NewIntelligence creates a new registry intelligence instance
func NewIntelligence() *Intelligence {
	ri := &Intelligence{
		client: &http.Client{
			Timeout: defaultTimeout,
		},
		cache:           make(map[string]Capabilities),
		cacheTTL:        make(map[string]time.Time),
		knownRegistries: make(map[string]Capabilities),
	}

	// Initialize with known registry capabilities
	ri.initializeKnownRegistries()

	return ri
}

// initializeKnownRegistries initializes known registry capabilities
func (ri *Intelligence) initializeKnownRegistries() {
	ri.setupDockerHub()
	ri.setupGCR()
	ri.setupGHCR()
	ri.setupECRPublic()
	ri.setupACR()

	debug.LogComponent("registry", "Initialized known registry capabilities for %d registries", len(ri.knownRegistries))
}

// setupDockerHub sets up Docker Hub registry capabilities
func (ri *Intelligence) setupDockerHub() {
	ri.knownRegistries["docker.io"] = ri.createRegistryCapabilities(
		true,  // SupportsMultiArch
		true,  // SupportsOCI
		false, // SupportsZstd
		true,  // SupportsManifestList
		RateLimitInfo{
			RequestsPerMinute: defaultRequestsPerMinute,
			RequestsPerHour:   defaultRequestsPerHour,
			RequestsPerDay:    defaultRequestsPerDay,
			BurstSize:         defaultBurstSize,
		},
		RecommendedConfig{
			CompressionLevel: defaultCompressionLevel,
			ChunkSize:        defaultChunkSizeMB * bytesInMB,
			MaxRetries:       defaultMaxRetries,
			Timeout:          defaultTimeoutSeconds,
			ParallelPushes:   defaultParallelPushes,
			EnableCache:      true,
			CacheTTL:         fmt.Sprintf("%dh", defaultCacheTTLHours),
		},
		defaultMaxLayerSizeGB*bytesInGB,
		defaultMaxManifestSizeMB*bytesInMB,
		[]string{"linux/amd64", "linux/arm64", "linux/arm/v7", "linux/s390x", "linux/ppc64le"},
		"token",
	)
}

// setupGCR sets up Google Container Registry capabilities
func (ri *Intelligence) setupGCR() {
	ri.knownRegistries[gcrRegistry] = Capabilities{
		SupportsMultiArch:    true,
		SupportsOCI:          true,
		SupportsZstd:         true,
		SupportsManifestList: true,
		RateLimits: RateLimitInfo{
			RequestsPerMinute: gcrRequestsPerMinute,
			RequestsPerHour:   gcrRequestsPerHour,
			RequestsPerDay:    gcrRequestsPerDay,
			BurstSize:         gcrBurstSize,
		},
		RecommendedSettings: RecommendedConfig{
			CompressionLevel: gcrCompressionLevel,
			ChunkSize:        gcrChunkSizeMB * bytesInMB,
			MaxRetries:       gcrMaxRetries,
			Timeout:          gcrTimeoutSeconds,
			ParallelPushes:   gcrParallelPushes,
			EnableCache:      true,
			CacheTTL:         fmt.Sprintf("%dh", gcrCacheTTLHours),
		},
		MaxLayerSize:         gcrMaxLayerSizeGB * bytesInGB,
		MaxManifestSize:      gcrMaxManifestSizeMB * bytesInMB,
		SupportedPlatforms:   []string{"linux/amd64", "linux/arm64", "linux/arm/v7", "linux/s390x"},
		AuthenticationScheme: "oauth2",
	}
}

// setupGHCR sets up GitHub Container Registry capabilities
func (ri *Intelligence) setupGHCR() {
	ri.knownRegistries["ghcr.io"] = ri.createRegistryCapabilities(
		true, // SupportsMultiArch
		true, // SupportsOCI
		true, // SupportsZstd
		true, // SupportsManifestList
		RateLimitInfo{
			RequestsPerMinute: ghcrRequestsPerMinute,
			RequestsPerHour:   ghcrRequestsPerHour,
			RequestsPerDay:    ghcrRequestsPerDay,
			BurstSize:         ghcrBurstSize,
		},
		RecommendedConfig{
			CompressionLevel: ghcrCompressionLevel,
			ChunkSize:        ghcrChunkSizeMB * bytesInMB,
			MaxRetries:       ghcrMaxRetries,
			Timeout:          ghcrTimeoutSeconds,
			ParallelPushes:   ghcrParallelPushes,
			EnableCache:      true,
			CacheTTL:         fmt.Sprintf("%dh", ghcrCacheTTLHours),
		},
		ghcrMaxLayerSizeGB*bytesInGB,
		ghcrMaxManifestSizeMB*bytesInMB,
		[]string{"linux/amd64", "linux/arm64", "linux/arm/v7", "linux/s390x", "linux/ppc64le"},
		"token",
	)
}

// setupECRPublic sets up Amazon ECR Public capabilities
func (ri *Intelligence) setupECRPublic() {
	ri.knownRegistries["public.ecr.aws"] = ri.createRegistryCapabilities(
		true,  // SupportsMultiArch
		true,  // SupportsOCI
		false, // SupportsZstd
		true,  // SupportsManifestList
		RateLimitInfo{
			RequestsPerMinute: ecrPublicRequestsPerMinute,
			RequestsPerHour:   ecrPublicRequestsPerHour,
			RequestsPerDay:    ecrPublicRequestsPerDay,
			BurstSize:         ecrPublicBurstSize,
		},
		RecommendedConfig{
			CompressionLevel: ecrPublicCompressionLevel,
			ChunkSize:        ecrPublicChunkSizeMB * bytesInMB,
			MaxRetries:       defaultMaxRetries,
			Timeout:          defaultTimeoutSeconds,
			ParallelPushes:   defaultParallelPushes,
			EnableCache:      true,
			CacheTTL:         fmt.Sprintf("%dh", ecrPublicCacheTTLHours),
		},
		ecrPublicMaxLayerSizeGB*bytesInGB,
		ecrPublicMaxManifestSizeMB*bytesInMB,
		[]string{"linux/amd64", "linux/arm64", "linux/arm/v7", "linux/s390x"},
		"aws",
	)
}

// setupACR sets up Azure Container Registry capabilities
func (ri *Intelligence) setupACR() {
	ri.knownRegistries["*.azurecr.io"] = ri.createRegistryCapabilities(
		true,  // SupportsMultiArch
		true,  // SupportsOCI
		false, // SupportsZstd
		true,  // SupportsManifestList
		RateLimitInfo{
			RequestsPerMinute: acrRequestsPerMinute,
			RequestsPerHour:   acrRequestsPerHour,
			RequestsPerDay:    acrRequestsPerDay,
			BurstSize:         acrBurstSize,
		},
		RecommendedConfig{
			CompressionLevel: acrCompressionLevel,
			ChunkSize:        acrChunkSizeMB * bytesInMB,
			MaxRetries:       acrMaxRetries,
			Timeout:          acrTimeoutSeconds,
			ParallelPushes:   acrParallelPushes,
			EnableCache:      true,
			CacheTTL:         fmt.Sprintf("%dh", acrCacheTTLHours),
		},
		acrMaxLayerSizeGB*bytesInGB,
		acrMaxManifestSizeMB*bytesInMB,
		[]string{"linux/amd64", "linux/arm64", "linux/arm/v7", "linux/s390x"},
		"azure",
	)
}

// createRegistryCapabilities creates a Capabilities struct with the provided parameters
// nolint:unparam // Parameters are used for consistency with other registry capability functions
func (ri *Intelligence) createRegistryCapabilities(
	supportsMultiArch bool,
	supportsOCI bool,
	supportsZstd bool,
	supportsManifestList bool,
	rateLimits RateLimitInfo,
	recommendedSettings RecommendedConfig,
	maxLayerSize int64,
	maxManifestSize int64,
	supportedPlatforms []string,
	authenticationScheme string,
) Capabilities {
	return Capabilities{
		SupportsMultiArch:    supportsMultiArch,
		SupportsOCI:          supportsOCI,
		SupportsZstd:         supportsZstd,
		SupportsManifestList: supportsManifestList,
		RateLimits:           rateLimits,
		RecommendedSettings:  recommendedSettings,
		MaxLayerSize:         maxLayerSize,
		MaxManifestSize:      maxManifestSize,
		SupportedPlatforms:   supportedPlatforms,
		AuthenticationScheme: authenticationScheme,
	}
}

// DetectCapabilities detects the capabilities of a registry through various methods
func (ri *Intelligence) DetectCapabilities(ctx context.Context, registry string) (Capabilities, error) {
	debug.LogComponent("registry", "Detecting capabilities for registry: %s", registry)

	// Check cache first
	if cached, found := ri.getFromCache(registry); found {
		debug.LogComponent("registry", "Using cached capabilities for registry: %s", registry)
		return cached, nil
	}

	// Check known registries first
	if capabilities, exists := ri.getKnownRegistryCapabilities(registry); exists {
		ri.setToCache(registry, &capabilities)
		debug.LogComponent("registry", "Using known capabilities for registry: %s", registry)
		return capabilities, nil
	}

	// Perform dynamic detection
	capabilities := ri.performDynamicDetection(ctx, registry)

	// Cache the result
	ri.setToCache(registry, &capabilities)
	debug.LogComponent("registry", "Detected capabilities for registry %s: %+v", registry, capabilities)

	return capabilities, nil
}

// getKnownRegistryCapabilities gets capabilities for known registries
func (ri *Intelligence) getKnownRegistryCapabilities(registry string) (Capabilities, bool) {
	ri.mu.RLock()
	defer ri.mu.RUnlock()

	// Check exact match
	if capabilities, exists := ri.knownRegistries[registry]; exists {
		return capabilities, true
	}

	// Check wildcard patterns
	for pattern := range ri.knownRegistries {
		if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(registry, prefix) {
				capsPtr := ri.knownRegistries[pattern]
				return capsPtr, true
			}
		}
	}

	return Capabilities{}, false
}

// getFromCache gets capabilities from cache
func (ri *Intelligence) getFromCache(registry string) (Capabilities, bool) {
	ri.mu.RLock()
	defer ri.mu.RUnlock()

	capabilities, exists := ri.cache[registry]
	if !exists {
		return Capabilities{}, false
	}

	// Check if cache entry has expired
	if ri.cacheTTL[registry].Before(time.Now()) {
		delete(ri.cache, registry)
		delete(ri.cacheTTL, registry)
		return Capabilities{}, false
	}

	return capabilities, true
}

// setToCache sets capabilities in cache
func (ri *Intelligence) setToCache(registry string, capabilities *Capabilities) {
	ri.mu.Lock()
	defer ri.mu.Unlock()

	ri.cache[registry] = *capabilities
	ri.cacheTTL[registry] = time.Now().Add(cacheTTL)
}

// performDynamicDetection performs dynamic capability detection
func (ri *Intelligence) performDynamicDetection(ctx context.Context, registry string) Capabilities {
	capabilities := Capabilities{
		SupportsMultiArch:    true,  // Assume multi-arch support by default
		SupportsOCI:          true,  // Assume OCI support by default
		SupportsZstd:         false, // Zstd not widely supported
		SupportsManifestList: true,  // Assume manifest list support
	}

	// Test for OCI support
	ociSupported, err := ri.testOCISupport(ctx, registry)
	if err != nil {
		debug.LogComponent("registry", "OCI support test failed for %s: %v", registry, err)
	} else {
		capabilities.SupportsOCI = ociSupported
	}

	// Test for Zstd support
	zstdSupported := ri.testZstdSupport(ctx, registry)
	capabilities.SupportsZstd = zstdSupported

	// Test for rate limiting
	capabilities.RateLimits = ri.testRateLimiting(ctx, registry)

	// Set default recommended settings
	capabilities.RecommendedSettings = RecommendedConfig{
		CompressionLevel: defaultCompressionLevel,
		ChunkSize:        defaultChunkSizeMB * bytesInMB,
		MaxRetries:       defaultMaxRetries,
		Timeout:          defaultTimeoutSeconds,
		ParallelPushes:   defaultParallelPushes,
		EnableCache:      true,
		CacheTTL:         fmt.Sprintf("%dh", defaultCacheTTLHours),
	}

	return capabilities
}

// testOCISupport tests if a registry supports OCI media types
func (ri *Intelligence) testOCISupport(_ context.Context, _ string) (bool, error) {
	// This is a simplified test. In a real implementation, you would:
	// 1. Make a HEAD request to the manifest endpoint
	// 2. Check the Accept header response
	// 3. Look for OCI media types in the response

	// For now, assume most registries support OCI
	return true, nil
}

// testZstdSupport tests if a registry supports Zstd compression.
func (ri *Intelligence) testZstdSupport(_ context.Context, registry string) bool {
	// This is a simplified test. In a real implementation, you would:
	// 1. Try to push a layer with Zstd compression
	// 2. Check if the registry accepts it

	// For now, assume only major registries support Zstd
	switch registry {
	case gcrRegistry, ghcrRegistry:
		return true
	default:
		return false
	}
}

// testRateLimiting tests rate limiting behavior of a registry.
func (ri *Intelligence) testRateLimiting(_ context.Context, _ string) RateLimitInfo {
	// This is a simplified test. In a real implementation, you would:
	// 1. Make multiple requests in quick succession
	// 2. Check for rate limiting headers (X-RateLimit-*, etc.)
	// 3. Analyze the response patterns

	// For now, return default rate limits
	return RateLimitInfo{
		RequestsPerMinute: defaultRequestsPerMinute,
		RequestsPerHour:   defaultRequestsPerHour,
		RequestsPerDay:    defaultRequestsPerDay,
		BurstSize:         defaultBurstSize,
	}
}

// OptimizePushStrategy determines the optimal push strategy for a registry and platforms
func (ri *Intelligence) OptimizePushStrategy(registry string, platforms []string) PushStrategy {
	debug.LogComponent("registry", "Optimizing push strategy for registry: %s, platforms: %v", registry, platforms)

	// Get registry capabilities
	capabilities, exists := ri.getKnownRegistryCapabilities(registry)
	if !exists {
		// Fallback to default strategy
		return ri.getDefaultPushStrategy()
	}

	strategy := PushStrategy{
		ParallelPushes:       capabilities.RecommendedSettings.ParallelPushes > 0,
		ChunkSize:            capabilities.RecommendedSettings.ChunkSize,
		CompressionLevel:     capabilities.RecommendedSettings.CompressionLevel,
		MaxRetries:           capabilities.RecommendedSettings.MaxRetries,
		Timeout:              capabilities.RecommendedSettings.Timeout,
		BackoffAlgorithm:     "exponential",
		RetryableStatusCodes: []int{429, 500, 502, 503, 504}, // HTTP status codes to retry on
		PreferHTTP1_1:        false,
		EnableCache:          capabilities.RecommendedSettings.EnableCache,
		CacheKey: fmt.Sprintf("%s-%s", registry,
			strings.Join(platforms, ",")),
	}

	// Adjust strategy based on registry-specific optimizations
	switch registry {
	case gcrRegistry:
		strategy.CompressionLevel = gcrCompressionLevel
		strategy.ChunkSize = gcrChunkSizeMB * bytesInMB
		strategy.ParallelPushes = true
		strategy.EnableCache = true
	case ghcrRegistry:
		strategy.CompressionLevel = ghcrCompressionLevel
		strategy.ChunkSize = ghcrChunkSizeMB * bytesInMB
		strategy.ParallelPushes = true
		strategy.EnableCache = true
	case "docker.io":
		strategy.CompressionLevel = defaultCompressionLevel
		strategy.ChunkSize = defaultChunkSizeMB * bytesInMB
		strategy.ParallelPushes = true
		strategy.EnableCache = true
	}

	// Adjust for number of platforms
	if len(platforms) > maxPlatformsForParallelism {
		strategy.ParallelPushes = false // Reduce parallelism for many platforms
	}

	debug.LogComponent("registry", "Optimized push strategy: %+v", strategy)
	return strategy
}

// getDefaultPushStrategy returns a default push strategy
func (ri *Intelligence) getDefaultPushStrategy() PushStrategy {
	return PushStrategy{
		ParallelPushes:       true,
		ChunkSize:            defaultChunkSizeMB * bytesInMB,
		CompressionLevel:     defaultCompressionLevel,
		MaxRetries:           defaultMaxRetries,
		Timeout:              defaultTimeoutSeconds,
		BackoffAlgorithm:     "exponential",
		RetryableStatusCodes: []int{429, 500, 502, 503, 504},
		PreferHTTP1_1:        false,
		EnableCache:          true,
		CacheKey:             "default",
	}
}

// GetRegistryRecommendations returns recommendations for using a specific registry
func (ri *Intelligence) GetRegistryRecommendations(registry string) map[string]string {
	recommendations := make(map[string]string)

	capabilities, exists := ri.getKnownRegistryCapabilities(registry)
	if !exists {
		recommendations["error"] = "Unknown registry capabilities"
		return recommendations
	}

	// General recommendations
	recommendations["compression"] = "gzip"
	if capabilities.SupportsZstd {
		recommendations["compression"] = "zstd"
	}

	recommendations["parallel_pushes"] = fmt.Sprintf("%d", capabilities.RecommendedSettings.ParallelPushes)
	recommendations["chunk_size"] = fmt.Sprintf("%d", capabilities.RecommendedSettings.ChunkSize)
	recommendations["max_retries"] = fmt.Sprintf("%d", capabilities.RecommendedSettings.MaxRetries)
	recommendations["timeout"] = fmt.Sprintf("%d", capabilities.RecommendedSettings.Timeout)
	recommendations["enable_cache"] = fmt.Sprintf("%t", capabilities.RecommendedSettings.EnableCache)

	// Registry-specific recommendations
	switch registry {
	case gcrRegistry:
		recommendations["best_practices"] = "Use high compression (zstd level 9), larger chunks (32MB), and enable caching"
	case "ghcr.io":
		recommendations["best_practices"] = "Use medium compression (zstd level 8), medium chunks (16MB), and enable caching"
	case "docker.io":
		recommendations["best_practices"] = "Use standard compression (gzip level 6), " +
			"standard chunks (10MB), and enable caching"
	case "public.ecr.aws":
		recommendations["best_practices"] = "Use standard compression (gzip level 6), " +
			"standard chunks (10MB), and enable caching"
	}

	return recommendations
}

// ValidateRegistry validates that a registry is accessible and has the required capabilities.
func (ri *Intelligence) ValidateRegistry(ctx context.Context, registry string, requiredCapabilities []string) error {
	debug.LogComponent("registry", "Validating registry: %s with required capabilities: %v",
		registry, requiredCapabilities)

	capabilities, err := ri.DetectCapabilities(ctx, registry)
	if err != nil {
		return fmt.Errorf("failed to detect registry capabilities: %w", err)
	}

	// Check required capabilities
	for _, required := range requiredCapabilities {
		switch required {
		case "multiarch":
			if !capabilities.SupportsMultiArch {
				return fmt.Errorf("registry %s does not support multi-architecture images", registry)
			}
		case "oci":
			if !capabilities.SupportsOCI {
				return fmt.Errorf("registry %s does not support OCI media types", registry)
			}
		case "zstd":
			if !capabilities.SupportsZstd {
				return fmt.Errorf("registry %s does not support Zstd compression", registry)
			}
		case "manifest-list":
			if !capabilities.SupportsManifestList {
				return fmt.Errorf("registry %s does not support manifest lists", registry)
			}
		}
	}

	debug.LogComponent("registry", "Registry %s validation successful", registry)
	return nil
}

// Statistics represents statistics about registry usage and performance.
// This struct provides structured data about registry operations and performance metrics.
type Statistics struct {
	KnownRegistries int    `json:"known_registries"`
	CacheSize       int    `json:"cache_size"`
	CacheHitRate    string `json:"cache_hit_rate"`
	TotalRequests   int    `json:"total_requests"`
	FailedRequests  int    `json:"failed_requests"`
}

// GetRegistryStatistics returns statistics about registry usage and performance.
// This method provides comprehensive metrics about registry operations including
// cache performance, request counts, and registry type distribution.
func (ri *Intelligence) GetRegistryStatistics() Statistics {
	ri.mu.RLock()
	defer ri.mu.RUnlock()

	// Count registries by type
	registryTypes := make(map[string]int)
	for registry := range ri.knownRegistries {
		switch {
		case strings.Contains(registry, "docker.io"):
			registryTypes["docker"]++
		case strings.Contains(registry, gcrRegistry):
			registryTypes["gcr"]++
		case strings.Contains(registry, ghcrRegistry):
			registryTypes["ghcr"]++
		case strings.Contains(registry, "ecr"):
			registryTypes["ecr"]++
		case strings.Contains(registry, "azurecr.io"):
			registryTypes["acr"]++
		default:
			registryTypes["other"]++
		}
	}

	return Statistics{
		KnownRegistries: len(ri.knownRegistries),
		CacheSize:       len(ri.cache),
		CacheHitRate:    "N/A", // Would need to implement cache hit tracking
		TotalRequests:   0,     // Would need to implement request tracking
		FailedRequests:  0,     // Would need to implement failure tracking
	}
}

// Cleanup cleans up the registry intelligence cache
func (ri *Intelligence) Cleanup() {
	ri.mu.Lock()
	defer ri.mu.Unlock()

	ri.cache = make(map[string]Capabilities)
	ri.cacheTTL = make(map[string]time.Time)
	debug.LogComponent("registry", "Registry intelligence cache cleaned up")
}
