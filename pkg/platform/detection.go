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

package platform

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"

	"github.com/containerd/containerd/platforms"
	"github.com/Gosayram/kaniko/pkg/debug"
)

// PlatformInfo contains information about a build platform
type PlatformInfo struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// PlatformDetector detects available build platforms in the current environment
type PlatformDetector struct {
	mu          sync.RWMutex
	available   []PlatformInfo
	detected    bool
	kubeClient  KubeClient
	ciClient    CIClient
}

// KubeClient defines the interface for Kubernetes platform detection
type KubeClient interface {
	GetNodeArchitectures(ctx context.Context) ([]PlatformInfo, error)
}

// CIClient defines the interface for CI platform detection
type CIClient interface {
	GetMatrixPlatforms(ctx context.Context) ([]PlatformInfo, error)
}

// NewPlatformDetector creates a new platform detector
func NewPlatformDetector(kubeClient KubeClient, ciClient CIClient) *PlatformDetector {
	return &PlatformDetector{
		kubeClient: kubeClient,
		ciClient:   ciClient,
	}
}

// AutoDetectAvailablePlatforms detects available build platforms in current environment
func (pd *PlatformDetector) AutoDetectAvailablePlatforms(ctx context.Context) ([]PlatformInfo, error) {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	if pd.detected {
		return pd.available, nil
	}

	debug.LogComponent("platform", "Starting platform auto-detection")

	var detectedPlatforms []PlatformInfo

	// Detect host platform
	hostPlatform := pd.detectHostPlatform()
	detectedPlatforms = append(detectedPlatforms, hostPlatform)
	debug.LogComponent("platform", "Detected host platform: %s", formatPlatform(hostPlatform))

	// Detect Kubernetes platforms if available
	if pd.kubeClient != nil {
		kubePlatforms, err := pd.kubeClient.GetNodeArchitectures(ctx)
		if err == nil {
			detectedPlatforms = append(detectedPlatforms, kubePlatforms...)
			debug.LogComponent("platform", "Detected %d Kubernetes platforms", len(kubePlatforms))
		} else {
			debug.LogComponent("platform", "Kubernetes platform detection failed: %v", err)
		}
	}

	// Detect CI platforms if available
	if pd.ciClient != nil {
		ciPlatforms, err := pd.ciClient.GetMatrixPlatforms(ctx)
		if err == nil {
			detectedPlatforms = append(detectedPlatforms, ciPlatforms...)
			debug.LogComponent("platform", "Detected %d CI platforms", len(ciPlatforms))
		} else {
			debug.LogComponent("platform", "CI platform detection failed: %v", err)
		}
	}

	// Remove duplicates
	detectedPlatforms = pd.deduplicatePlatforms(detectedPlatforms)

	pd.available = detectedPlatforms
	pd.detected = true

	debug.LogComponent("platform", "Platform auto-detection completed. Available platforms: %v", 
		formatPlatforms(detectedPlatforms))

	return detectedPlatforms, nil
}

// detectHostPlatform detects the current host platform
func (pd *PlatformDetector) detectHostPlatform() PlatformInfo {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	// Check for common architecture variants
	var variant string
	switch goarch {
	case "arm":
		variant = "v7"
	case "arm64":
		variant = "v8"
	case "amd64":
		variant = "v1"
	}

	return PlatformInfo{
		OS:           goos,
		Architecture: goarch,
		Variant:      variant,
	}
}

// deduplicatePlatforms removes duplicate platform entries
func (pd *PlatformDetector) deduplicatePlatforms(platforms []PlatformInfo) []PlatformInfo {
	seen := make(map[string]bool)
	var unique []PlatformInfo

	for _, platform := range platforms {
		key := formatPlatform(platform)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, platform)
		}
	}

	return unique
}

// SuggestOptimalPlatforms suggests optimal platform combinations based on various factors
func (pd *PlatformDetector) SuggestOptimalPlatforms(ctx context.Context, targets []string) ([]PlatformInfo, error) {
	debug.LogComponent("platform", "Suggesting optimal platforms for targets: %v", targets)

	availablePlatforms, err := pd.AutoDetectAvailablePlatforms(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to detect available platforms: %w", err)
	}

	// If no targets specified, return all available platforms
	if len(targets) == 0 {
		debug.LogComponent("platform", "No targets specified, returning all available platforms: %v", 
			formatPlatforms(availablePlatforms))
		return availablePlatforms, nil
	}

	// Filter available platforms based on targets
	var optimal []PlatformInfo
	for _, target := range targets {
		for _, platform := range availablePlatforms {
			if pd.isPlatformMatch(target, platform) {
				optimal = append(optimal, platform)
				debug.LogComponent("platform", "Platform %s matches target %s", formatPlatform(platform), target)
			}
		}
	}

	// If no matches found, return available platforms as fallback
	if len(optimal) == 0 {
		debug.LogComponent("platform", "No exact matches found for targets %v, returning all available platforms", targets)
		return availablePlatforms, nil
	}

	debug.LogComponent("platform", "Suggested optimal platforms: %v", formatPlatforms(optimal))
	return optimal, nil
}

// isPlatformMatch checks if a platform matches a target specification
func (pd *PlatformDetector) isPlatformMatch(target string, platform PlatformInfo) bool {
	// Parse target specification (e.g., "linux/amd64", "linux/arm64/v8", etc.)
	targetParts := strings.Split(target, "/")
	
	// OS match
	if len(targetParts) > 0 && targetParts[0] != "" && targetParts[0] != platform.OS {
		return false
	}
	
	// Architecture match
	if len(targetParts) > 1 && targetParts[1] != "" && targetParts[1] != platform.Architecture {
		return false
	}
	
	// Variant match
	if len(targetParts) > 2 && targetParts[2] != "" && targetParts[2] != platform.Variant {
		return false
	}
	
	return true
}

// ValidatePlatforms validates that the specified platforms are supported
func (pd *PlatformDetector) ValidatePlatforms(ctx context.Context, platformSpecs []string) error {
	debug.LogComponent("platform", "Validating platform specifications: %v", platformSpecs)

	availablePlatforms, err := pd.AutoDetectAvailablePlatforms(ctx)
	if err != nil {
		return fmt.Errorf("failed to detect available platforms: %w", err)
	}

	availableSpecs := make(map[string]bool)
	for _, platform := range availablePlatforms {
		availableSpecs[formatPlatform(platform)] = true
	}

	var invalidPlatforms []string
	for _, spec := range platformSpecs {
		if !availableSpecs[spec] {
			invalidPlatforms = append(invalidPlatforms, spec)
		}
	}

	if len(invalidPlatforms) > 0 {
		return fmt.Errorf("unsupported platforms: %v. Available platforms: %v", 
			invalidPlatforms, formatPlatforms(availablePlatforms))
	}

	debug.LogComponent("platform", "All platform specifications are valid: %v", platformSpecs)
	return nil
}

// GetPlatformCapabilities returns the capabilities for a given platform
func (pd *PlatformDetector) GetPlatformCapabilities(ctx context.Context, platformSpec string) ([]string, error) {
	platforms, err := pd.AutoDetectAvailablePlatforms(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to detect available platforms: %w", err)
	}

	for _, platform := range platforms {
		if formatPlatform(platform) == platformSpec {
			return platform.Capabilities, nil
		}
	}

	return nil, fmt.Errorf("platform not found: %s", platformSpec)
}

// IsPlatformAvailable checks if a specific platform is available
func (pd *PlatformDetector) IsPlatformAvailable(ctx context.Context, platformSpec string) (bool, error) {
	platforms, err := pd.AutoDetectAvailablePlatforms(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to detect available platforms: %w", err)
	}

	for _, platform := range platforms {
		if formatPlatform(platform) == platformSpec {
			return true, nil
		}
	}

	return false, nil
}

// GetRecommendedPlatforms returns recommended platforms based on popularity and registry support
func (pd *PlatformDetector) GetRecommendedPlatforms(ctx context.Context, registry string) ([]PlatformInfo, error) {
	debug.LogComponent("platform", "Getting recommended platforms for registry: %s", registry)

	availablePlatforms, err := pd.AutoDetectAvailablePlatforms(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to detect available platforms: %w", err)
	}

	// Define popular platforms in order of preference
	popularPlatforms := []PlatformInfo{
		{OS: "linux", Architecture: "amd64"},
		{OS: "linux", Architecture: "arm64"},
		{OS: "linux", Architecture: "arm", Variant: "v7"},
		{OS: "linux", Architecture: "s390x"},
		{OS: "linux", Architecture: "ppc64le"},
	}

	var recommended []PlatformInfo

	// Filter available platforms based on popularity
	for _, popular := range popularPlatforms {
		for _, available := range availablePlatforms {
			if popular.OS == available.OS && popular.Architecture == available.Architecture {
				// Check if variant matches or if available has no variant
				if popular.Variant == available.Variant || available.Variant == "" {
					recommended = append(recommended, available)
					debug.LogComponent("platform", "Added recommended platform: %s", formatPlatform(available))
				}
			}
		}
	}

	// If no popular platforms are available, return all available platforms
	if len(recommended) == 0 {
		debug.LogComponent("platform", "No popular platforms available, returning all available platforms")
		return availablePlatforms, nil
	}

	debug.LogComponent("platform", "Recommended platforms: %v", formatPlatforms(recommended))
	return recommended, nil
}

// NormalizePlatform normalizes a platform specification to a standard format
func NormalizePlatform(platformSpec string) (PlatformInfo, error) {
	// Parse the platform specification
	p, err := platforms.Parse(platformSpec)
	if err != nil {
		return PlatformInfo{}, fmt.Errorf("failed to parse platform specification %s: %w", platformSpec, err)
	}

	return PlatformInfo{
		OS:           p.OS,
		Architecture: p.Architecture,
		Variant:      p.Variant,
	}, nil
}

// formatPlatform formats a PlatformInfo as a string
func formatPlatform(platform PlatformInfo) string {
	if platform.Variant != "" {
		return fmt.Sprintf("%s/%s/%s", platform.OS, platform.Architecture, platform.Variant)
	}
	return fmt.Sprintf("%s/%s", platform.OS, platform.Architecture)
}

// formatPlatforms formats a slice of PlatformInfo as strings
func formatPlatforms(platforms []PlatformInfo) []string {
	result := make([]string, len(platforms))
	for i, platform := range platforms {
		result[i] = formatPlatform(platform)
	}
	return result
}

// PlatformRegistryCompatibility checks if a platform is compatible with a given registry
func (pd *PlatformDetector) PlatformRegistryCompatibility(ctx context.Context, platformSpec string, registry string) (bool, error) {
	// Registry-specific compatibility rules
	registryRules := map[string][]string{
		"docker.io":      {"linux/amd64", "linux/arm64", "linux/arm/v7", "linux/s390x", "linux/ppc64le"},
		"gcr.io":         {"linux/amd64", "linux/arm64", "linux/arm/v7", "linux/s390x"},
		"ghcr.io":        {"linux/amd64", "linux/arm64", "linux/arm/v7", "linux/s390x", "linux/ppc64le"},
		"public.ecr.aws": {"linux/amd64", "linux/arm64", "linux/arm/v7", "linux/s390x"},
		"registry.access.redhat.com": {"linux/amd64", "linux/arm64", "linux/ppc64le"},
	}

	// Check if registry has specific rules
	compatiblePlatforms, exists := registryRules[registry]
	if !exists {
		// Default compatibility - assume all platforms are compatible
		return true, nil
	}

	// Check if platform is in the compatible list
	for _, compatible := range compatiblePlatforms {
		if compatible == platformSpec {
			return true, nil
		}
	}

	return false, nil
}

// GetPlatformBuildOrder returns an optimal build order for multiple platforms
func (pd *PlatformDetector) GetPlatformBuildOrder(ctx context.Context, platforms []string) ([]string, error) {
	debug.LogComponent("platform", "Getting optimal build order for platforms: %v", platforms)

	// Define build order based on popularity and build time
	buildOrder := []string{
		"linux/amd64",    // Most popular, fastest to build
		"linux/arm64",    // Second most popular
		"linux/arm/v7",   // ARM 32-bit
		"linux/s390x",    // IBM Z
		"linux/ppc64le",  // PowerPC
	}

	var ordered []string

	// Filter build order based on requested platforms
	for _, platform := range buildOrder {
		for _, requested := range platforms {
			if platform == requested {
				ordered = append(ordered, platform)
				debug.LogComponent("platform", "Added platform %s to build order", platform)
			}
		}
	}

	// Add any remaining platforms that weren't in the predefined order
	for _, platform := range platforms {
		found := false
		for _, orderedPlatform := range ordered {
			if platform == orderedPlatform {
				found = true
				break
			}
		}
		if !found {
			ordered = append(ordered, platform)
			debug.LogComponent("platform", "Added platform %s to build order (not in predefined order)", platform)
		}
	}

	debug.LogComponent("platform", "Optimal build order: %v", ordered)
	return ordered, nil
}

// GetPlatformStatistics returns statistics about available platforms
func (pd *PlatformDetector) GetPlatformStatistics(ctx context.Context) (*PlatformStatistics, error) {
	platforms, err := pd.AutoDetectAvailablePlatforms(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to detect available platforms: %w", err)
	}

	stats := &PlatformStatistics{
		TotalPlatforms: len(platforms),
		ByOS:          make(map[string]int),
		ByArchitecture: make(map[string]int),
		ByVariant:     make(map[string]int),
	}

	for _, platform := range platforms {
		stats.ByOS[platform.OS]++
		stats.ByArchitecture[platform.Architecture]++
		if platform.Variant != "" {
			stats.ByVariant[platform.Variant]++
		}
	}

	debug.LogComponent("platform", "Platform statistics: %+v", stats)
	return stats, nil
}

// PlatformStatistics contains statistics about available platforms
type PlatformStatistics struct {
	TotalPlatforms int            `json:"totalPlatforms"`
	ByOS           map[string]int `json:"byOS"`
	ByArchitecture map[string]int `json:"byArchitecture"`
	ByVariant      map[string]int `json:"byVariant"`
}