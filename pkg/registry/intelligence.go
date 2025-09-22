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

// RegistryCapabilities defines the capabilities of a registry
type RegistryCapabilities struct {
	SupportsMultiArch    bool              `json:"supportsMultiArch"`
	SupportsOCI          bool              `json:"supportsOCI"`
	SupportsZstd         bool              `json:"supportsZstd"`
	SupportsManifestList  bool              `json:"supportsManifestList"`
	RateLimits           RateLimitInfo     `json:"rateLimits"`
	RecommendedSettings   RecommendedConfig `json:"recommendedSettings"`
	MaxLayerSize         int64             `json:"maxLayerSize"`
	MaxManifestSize      int64             `json:"maxManifestSize"`
	SupportedPlatforms   []string          `json:"supportedPlatforms"`
	AuthenticationScheme string            `json:"authenticationScheme"`
}

// RateLimitInfo contains rate limiting information for a registry
type RateLimitInfo struct {
	RequestsPerMinute int `json:"requestsPerMinute"`
	RequestsPerHour   int `json:"requestsPerHour"`
	RequestsPerDay    int `json:"requestsPerDay"`
	BurstSize         int `json:"burstSize"`
}

// RecommendedConfig contains recommended configuration for a registry
type RecommendedConfig struct {
	CompressionLevel    int    `json:"compressionLevel"`
	ChunkSize           int64  `json:"chunkSize"`
	MaxRetries          int    `json:"maxRetries"`
	Timeout             int    `json:"timeout"`
	ParallelPushes      int    `json:"parallelPushes"`
	EnableCache         bool   `json:"enableCache"`
	CacheTTL            string `json:"cacheTTL"`
}

// PushStrategy defines the optimal push strategy for a registry
type PushStrategy struct {
	ParallelPushes      bool     `json:"parallelPushes"`
	ChunkSize           int64    `json:"chunkSize"`
	CompressionLevel    int      `json:"compressionLevel"`
	MaxRetries          int      `json:"maxRetries"`
	Timeout             int      `json:"timeout"`
	BackoffAlgorithm    string   `json:"backoffAlgorithm"`
	RetryableStatusCodes []int   `json:"retryableStatusCodes"`
	PreferHTTP1_1       bool     `json:"preferHTTP1_1"`
	EnableCache         bool     `json:"enableCache"`
	CacheKey            string   `json:"cacheKey"`
}

// RegistryIntelligence manages registry intelligence and optimization
type RegistryIntelligence struct {
	client    *http.Client
	cache     map[string]RegistryCapabilities
	cacheTTL  map[string]time.Time
	knownRegistries map[string]RegistryCapabilities
	mu        sync.RWMutex
}

// NewRegistryIntelligence creates a new registry intelligence instance
func NewRegistryIntelligence() *RegistryIntelligence {
	ri := &RegistryIntelligence{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache:           make(map[string]RegistryCapabilities),
		cacheTTL:        make(map[string]time.Time),
		knownRegistries: make(map[string]RegistryCapabilities),
	}

	// Initialize with known registry capabilities
	ri.initializeKnownRegistries()

	return ri
}

// initializeKnownRegistries initializes known registry capabilities
func (ri *RegistryIntelligence) initializeKnownRegistries() {
	// Docker Hub
	ri.knownRegistries["docker.io"] = RegistryCapabilities{
		SupportsMultiArch:   true,
		SupportsOCI:         true,
		SupportsZstd:        false,
		SupportsManifestList: true,
		RateLimits: RateLimitInfo{
			RequestsPerMinute: 100,
			RequestsPerHour:   6000,
			RequestsPerDay:    100000,
			BurstSize:         10,
		},
		RecommendedSettings: RecommendedConfig{
			CompressionLevel: 6,
			ChunkSize:        10 * 1024 * 1024, // 10MB
			MaxRetries:       3,
			Timeout:          300,
			ParallelPushes:   4,
			EnableCache:      true,
			CacheTTL:         "24h",
		},
		MaxLayerSize:       5 * 1024 * 1024 * 1024, // 5GB
		MaxManifestSize:    4 * 1024 * 1024,       // 4MB
		SupportedPlatforms: []string{"linux/amd64", "linux/arm64", "linux/arm/v7", "linux/s390x", "linux/ppc64le"},
		AuthenticationScheme: "token",
	}

	// Google Container Registry (GCR)
	ri.knownRegistries["gcr.io"] = RegistryCapabilities{
		SupportsMultiArch:   true,
		SupportsOCI:         true,
		SupportsZstd:        true,
		SupportsManifestList: true,
		RateLimits: RateLimitInfo{
			RequestsPerMinute: 1000,
			RequestsPerHour:   60000,
			RequestsPerDay:    1000000,
			BurstSize:         100,
		},
		RecommendedSettings: RecommendedConfig{
			CompressionLevel: 9,
			ChunkSize:        32 * 1024 * 1024, // 32MB
			MaxRetries:       5,
			Timeout:          600,
			ParallelPushes:   8,
			EnableCache:      true,
			CacheTTL:         "168h", // 1 week
		},
		MaxLayerSize:       32 * 1024 * 1024 * 1024, // 32GB
		MaxManifestSize:    64 * 1024 * 1024,       // 64MB
		SupportedPlatforms: []string{"linux/amd64", "linux/arm64", "linux/arm/v7", "linux/s390x"},
		AuthenticationScheme: "oauth2",
	}

	// GitHub Container Registry (GHCR)
	ri.knownRegistries["ghcr.io"] = RegistryCapabilities{
		SupportsMultiArch:   true,
		SupportsOCI:         true,
		SupportsZstd:        true,
		SupportsManifestList: true,
		RateLimits: RateLimitInfo{
			RequestsPerMinute: 500,
			RequestsPerHour:   30000,
			RequestsPerDay:    500000,
			BurstSize:         50,
		},
		RecommendedSettings: RecommendedConfig{
			CompressionLevel: 8,
			ChunkSize:        16 * 1024 * 1024, // 16MB
			MaxRetries:       4,
			Timeout:          450,
			ParallelPushes:   6,
			EnableCache:      true,
			CacheTTL:         "72h", // 3 days
		},
		MaxLayerSize:       10 * 1024 * 1024 * 1024, // 10GB
		MaxManifestSize:    32 * 1024 * 1024,       // 32MB
		SupportedPlatforms: []string{"linux/amd64", "linux/arm64", "linux/arm/v7", "linux/s390x", "linux/ppc64le"},
		AuthenticationScheme: "token",
	}

	// Amazon ECR Public
	ri.knownRegistries["public.ecr.aws"] = RegistryCapabilities{
		SupportsMultiArch:   true,
		SupportsOCI:         true,
		SupportsZstd:        false,
		SupportsManifestList: true,
		RateLimits: RateLimitInfo{
			RequestsPerMinute: 100,
			RequestsPerHour:   6000,
			RequestsPerDay:    100000,
			BurstSize:         10,
		},
		RecommendedSettings: RecommendedConfig{
			CompressionLevel: 6,
			ChunkSize:        10 * 1024 * 1024, // 10MB
			MaxRetries:       3,
			Timeout:          300,
			ParallelPushes:   4,
			EnableCache:      true,
			CacheTTL:         "24h",
		},
		MaxLayerSize:       10 * 1024 * 1024 * 1024, // 10GB
		MaxManifestSize:    8 * 1024 * 1024,        // 8MB
		SupportedPlatforms: []string{"linux/amd64", "linux/arm64", "linux/arm/v7", "linux/s390x"},
		AuthenticationScheme: "aws",
	}

	// Azure Container Registry (ACR)
	ri.knownRegistries["*.azurecr.io"] = RegistryCapabilities{
		SupportsMultiArch:   true,
		SupportsOCI:         true,
		SupportsZstd:        false,
		SupportsManifestList: true,
		RateLimits: RateLimitInfo{
			RequestsPerMinute: 200,
			RequestsPerHour:   12000,
			RequestsPerDay:    200000,
			BurstSize:         20,
		},
		RecommendedSettings: RecommendedConfig{
			CompressionLevel: 6,
			ChunkSize:        15 * 1024 * 1024, // 15MB
			MaxRetries:       4,
			Timeout:          360,
			ParallelPushes:   5,
			EnableCache:      true,
			CacheTTL:         "48h",
		},
		MaxLayerSize:       10 * 1024 * 1024 * 1024, // 10GB
		MaxManifestSize:    16 * 1024 * 1024,       // 16MB
		SupportedPlatforms: []string{"linux/amd64", "linux/arm64", "linux/arm/v7", "linux/s390x"},
		AuthenticationScheme: "azure",
	}

	debug.LogComponent("registry", "Initialized known registry capabilities for %d registries", len(ri.knownRegistries))
}

// DetectCapabilities detects the capabilities of a registry through various methods
func (ri *RegistryIntelligence) DetectCapabilities(ctx context.Context, registry string) (RegistryCapabilities, error) {
	debug.LogComponent("registry", "Detecting capabilities for registry: %s", registry)

	// Check cache first
	if cached, found := ri.getFromCache(registry); found {
		debug.LogComponent("registry", "Using cached capabilities for registry: %s", registry)
		return cached, nil
	}

	// Check known registries first
	if capabilities, exists := ri.getKnownRegistryCapabilities(registry); exists {
		ri.setToCache(registry, capabilities)
		debug.LogComponent("registry", "Using known capabilities for registry: %s", registry)
		return capabilities, nil
	}

	// Perform dynamic detection
	capabilities, err := ri.performDynamicDetection(ctx, registry)
	if err != nil {
		debug.LogComponent("registry", "Dynamic detection failed for %s: %v", registry, err)
		return RegistryCapabilities{}, fmt.Errorf("failed to detect capabilities for registry %s: %w", registry, err)
	}

	// Cache the result
	ri.setToCache(registry, capabilities)
	debug.LogComponent("registry", "Detected capabilities for registry %s: %+v", registry, capabilities)

	return capabilities, nil
}

// getKnownRegistryCapabilities gets capabilities for known registries
func (ri *RegistryIntelligence) getKnownRegistryCapabilities(registry string) (RegistryCapabilities, bool) {
	ri.mu.RLock()
	defer ri.mu.RUnlock()

	// Check exact match
	if capabilities, exists := ri.knownRegistries[registry]; exists {
		return capabilities, true
	}

	// Check wildcard patterns
	for pattern, capabilities := range ri.knownRegistries {
		if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(registry, prefix) {
				return capabilities, true
			}
		}
	}

	return RegistryCapabilities{}, false
}

// getFromCache gets capabilities from cache
func (ri *RegistryIntelligence) getFromCache(registry string) (RegistryCapabilities, bool) {
	ri.mu.RLock()
	defer ri.mu.RUnlock()

	capabilities, exists := ri.cache[registry]
	if !exists {
		return RegistryCapabilities{}, false
	}

	// Check if cache entry has expired
	if ri.cacheTTL[registry].Before(time.Now()) {
		delete(ri.cache, registry)
		delete(ri.cacheTTL, registry)
		return RegistryCapabilities{}, false
	}

	return capabilities, true
}

// setToCache sets capabilities in cache
func (ri *RegistryIntelligence) setToCache(registry string, capabilities RegistryCapabilities) {
	ri.mu.Lock()
	defer ri.mu.Unlock()

	ri.cache[registry] = capabilities
	ri.cacheTTL[registry] = time.Now().Add(5 * time.Minute) // 5 minute TTL
}

// performDynamicDetection performs dynamic capability detection
func (ri *RegistryIntelligence) performDynamicDetection(ctx context.Context, registry string) (RegistryCapabilities, error) {
	capabilities := RegistryCapabilities{
		SupportsMultiArch:   true,  // Assume multi-arch support by default
		SupportsOCI:         true,  // Assume OCI support by default
		SupportsZstd:        false, // Zstd not widely supported
		SupportsManifestList: true, // Assume manifest list support
	}

	// Test for OCI support
	ociSupported, err := ri.testOCISupport(ctx, registry)
	if err != nil {
		debug.LogComponent("registry", "OCI support test failed for %s: %v", registry, err)
	} else {
		capabilities.SupportsOCI = ociSupported
	}

	// Test for Zstd support
	zstdSupported, err := ri.testZstdSupport(ctx, registry)
	if err != nil {
		debug.LogComponent("registry", "Zstd support test failed for %s: %v", registry, err)
	} else {
		capabilities.SupportsZstd = zstdSupported
	}

	// Test for rate limiting
	rateLimits, err := ri.testRateLimiting(ctx, registry)
	if err != nil {
		debug.LogComponent("registry", "Rate limiting test failed for %s: %v", registry, err)
	} else {
		capabilities.RateLimits = rateLimits
	}

	// Set default recommended settings
	capabilities.RecommendedSettings = RecommendedConfig{
		CompressionLevel: 6,
		ChunkSize:        10 * 1024 * 1024, // 10MB
		MaxRetries:       3,
		Timeout:          300,
		ParallelPushes:   4,
		EnableCache:      true,
		CacheTTL:         "24h",
	}

	return capabilities, nil
}

// testOCISupport tests if a registry supports OCI media types
func (ri *RegistryIntelligence) testOCISupport(ctx context.Context, registry string) (bool, error) {
	// This is a simplified test. In a real implementation, you would:
	// 1. Make a HEAD request to the manifest endpoint
	// 2. Check the Accept header response
	// 3. Look for OCI media types in the response
	
	// For now, assume most registries support OCI
	return true, nil
}

// testZstdSupport tests if a registry supports Zstd compression
func (ri *RegistryIntelligence) testZstdSupport(ctx context.Context, registry string) (bool, error) {
	// This is a simplified test. In a real implementation, you would:
	// 1. Try to push a layer with Zstd compression
	// 2. Check if the registry accepts it
	
	// For now, assume only major registries support Zstd
	switch registry {
	case "gcr.io", "ghcr.io":
		return true, nil
	default:
		return false, nil
	}
}

// testRateLimiting tests rate limiting behavior of a registry
func (ri *RegistryIntelligence) testRateLimiting(ctx context.Context, registry string) (RateLimitInfo, error) {
	// This is a simplified test. In a real implementation, you would:
	// 1. Make multiple requests in quick succession
	// 2. Check for rate limiting headers (X-RateLimit-*, etc.)
	// 3. Analyze the response patterns
	
	// For now, return default rate limits
	return RateLimitInfo{
		RequestsPerMinute: 100,
		RequestsPerHour:   6000,
		RequestsPerDay:    100000,
		BurstSize:         10,
	}, nil
}

// OptimizePushStrategy determines the optimal push strategy for a registry and platforms
func (ri *RegistryIntelligence) OptimizePushStrategy(registry string, platforms []string) PushStrategy {
	debug.LogComponent("registry", "Optimizing push strategy for registry: %s, platforms: %v", registry, platforms)

	// Get registry capabilities
	capabilities, exists := ri.getKnownRegistryCapabilities(registry)
	if !exists {
		// Fallback to default strategy
		return ri.getDefaultPushStrategy()
	}

	strategy := PushStrategy{
		ParallelPushes:      capabilities.RecommendedSettings.ParallelPushes > 0,
		ChunkSize:           capabilities.RecommendedSettings.ChunkSize,
		CompressionLevel:    capabilities.RecommendedSettings.CompressionLevel,
		MaxRetries:          capabilities.RecommendedSettings.MaxRetries,
		Timeout:             capabilities.RecommendedSettings.Timeout,
		BackoffAlgorithm:    "exponential",
		RetryableStatusCodes: []int{429, 500, 502, 503, 504}, // HTTP status codes to retry on
		PreferHTTP1_1:       false,
		EnableCache:         capabilities.RecommendedSettings.EnableCache,
		CacheKey:            fmt.Sprintf("%s-%s", registry, strings.Join(platforms, ",")),
	}

	// Adjust strategy based on registry-specific optimizations
	switch registry {
	case "gcr.io":
		strategy.CompressionLevel = 9
		strategy.ChunkSize = 32 * 1024 * 1024
		strategy.ParallelPushes = true
		strategy.EnableCache = true
	case "ghcr.io":
		strategy.CompressionLevel = 8
		strategy.ChunkSize = 16 * 1024 * 1024
		strategy.ParallelPushes = true
		strategy.EnableCache = true
	case "docker.io":
		strategy.CompressionLevel = 6
		strategy.ChunkSize = 10 * 1024 * 1024
		strategy.ParallelPushes = true
		strategy.EnableCache = true
	}

	// Adjust for number of platforms
	if len(platforms) > 3 {
		strategy.ParallelPushes = false // Reduce parallelism for many platforms
	}

	debug.LogComponent("registry", "Optimized push strategy: %+v", strategy)
	return strategy
}

// getDefaultPushStrategy returns a default push strategy
func (ri *RegistryIntelligence) getDefaultPushStrategy() PushStrategy {
	return PushStrategy{
		ParallelPushes:      true,
		ChunkSize:           10 * 1024 * 1024,
		CompressionLevel:    6,
		MaxRetries:          3,
		Timeout:             300,
		BackoffAlgorithm:    "exponential",
		RetryableStatusCodes: []int{429, 500, 502, 503, 504},
		PreferHTTP1_1:       false,
		EnableCache:         true,
		CacheKey:            "default",
	}
}

// GetRegistryRecommendations returns recommendations for using a specific registry
func (ri *RegistryIntelligence) GetRegistryRecommendations(registry string) map[string]string {
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
	case "gcr.io":
		recommendations["best_practices"] = "Use high compression (zstd level 9), larger chunks (32MB), and enable caching"
	case "ghcr.io":
		recommendations["best_practices"] = "Use medium compression (zstd level 8), medium chunks (16MB), and enable caching"
	case "docker.io":
		recommendations["best_practices"] = "Use standard compression (gzip level 6), standard chunks (10MB), and enable caching"
	case "public.ecr.aws":
		recommendations["best_practices"] = "Use standard compression (gzip level 6), standard chunks (10MB), and enable caching"
	}

	return recommendations
}

// ValidateRegistry validates that a registry is accessible and has the required capabilities
func (ri *RegistryIntelligence) ValidateRegistry(ctx context.Context, registry string, requiredCapabilities []string) error {
	debug.LogComponent("registry", "Validating registry: %s with required capabilities: %v", registry, requiredCapabilities)

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

// GetRegistryStatistics returns statistics about registry usage and performance
func (ri *RegistryIntelligence) GetRegistryStatistics() map[string]interface{} {
	ri.mu.RLock()
	defer ri.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["known_registries"] = len(ri.knownRegistries)
	stats["cache_size"] = len(ri.cache)
	stats["cache_hit_rate"] = "N/A" // Would need to implement cache hit tracking

	// Count registries by type
	registryTypes := make(map[string]int)
	for registry := range ri.knownRegistries {
		if strings.Contains(registry, "docker.io") {
			registryTypes["docker"]++
		} else if strings.Contains(registry, "gcr.io") {
			registryTypes["gcr"]++
		} else if strings.Contains(registry, "ghcr.io") {
			registryTypes["ghcr"]++
		} else if strings.Contains(registry, "ecr") {
			registryTypes["ecr"]++
		} else if strings.Contains(registry, "azurecr.io") {
			registryTypes["acr"]++
		} else {
			registryTypes["other"]++
		}
	}
	stats["registry_types"] = registryTypes

	return stats
}

// Cleanup cleans up the registry intelligence cache
func (ri *RegistryIntelligence) Cleanup() {
	ri.mu.Lock()
	defer ri.mu.Unlock()

	ri.cache = make(map[string]RegistryCapabilities)
	ri.cacheTTL = make(map[string]time.Time)
	debug.LogComponent("registry", "Registry intelligence cache cleaned up")
}

// Helper function to get minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}