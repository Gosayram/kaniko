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

package optimization

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Gosayram/kaniko/pkg/debug"
)

// BuildRecord contains information about a build execution
type BuildRecord struct {
	ID             string        `json:"id"`
	Duration       time.Duration `json:"duration"`
	Platform       string        `json:"platform"`
	LayerCount     int           `json:"layerCount"`
	CacheStats     CacheStats    `json:"cacheStats"`
	Performance    PerformanceMetrics `json:"performance"`
	Timestamp      time.Time     `json:"timestamp"`
	DockerfilePath string        `json:"dockerfilePath"`
	Registry       string        `json:"registry"`
	Success        bool          `json:"success"`
	Error          string        `json:"error,omitempty"`
}

// CacheStats contains cache-related statistics
type CacheStats struct {
	HitRate         float64 `json:"hitRate"`
	CacheHits       int     `json:"cacheHits"`
	CacheMisses     int     `json:"cacheMisses"`
	CacheSize       int64   `json:"cacheSize"`
	CacheLayers     int     `json:"cacheLayers"`
	AverageLayerSize int64   `json:"averageLayerSize"`
}

// PerformanceMetrics contains performance-related metrics
type PerformanceMetrics struct {
	PeakMemory     uint64 `json:"peakMemory"`
	AverageCPU     float64 `json:"averageCPU"`
	TotalIOBytes   int64   `json:"totalIOBytes"`
	NetworkBytes   int64   `json:"networkBytes"`
	BuildSteps     int     `json:"buildSteps"`
	AverageStepTime time.Duration `json:"averageStepTime"`
}

// PatternDetector detects common patterns in Dockerfiles
type PatternDetector struct {
	mu       sync.RWMutex
	patterns map[string]*PatternInfo
}

// PatternInfo contains information about a detected pattern
type PatternInfo struct {
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	Occurrences  int       `json:"occurrences"`
	Optimization string    `json:"optimization"`
	LastSeen     time.Time `json:"lastSeen"`
}

// RecommendationEngine generates build recommendations
type RecommendationEngine struct {
	mu           sync.RWMutex
	recommendations map[string]*Recommendation
}

// Recommendation contains a build recommendation
type Recommendation struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"`
	Title        string    `json:"title"`
	Description  string    `json:"description"`
	Severity     string    `json:"severity"` // low, medium, high, critical
	Priority     int       `json:"priority"`
	Confidence   float64   `json:"confidence"`
	SuggestedFix string    `json:"suggestedFix"`
	Implemented  bool      `json:"implemented"`
	LastUpdated  time.Time `json:"lastUpdated"`
}

// OptimizationEngine manages build optimization analysis and recommendations
type OptimizationEngine struct {
	buildHistory   []BuildRecord
	patternDetector *PatternDetector
	recommendationEngine *RecommendationEngine
	mu             sync.RWMutex
}

// NewOptimizationEngine creates a new optimization engine
func NewOptimizationEngine() *OptimizationEngine {
	oe := &OptimizationEngine{
		buildHistory:   make([]BuildRecord, 0),
		patternDetector: NewPatternDetector(),
		recommendationEngine: NewRecommendationEngine(),
	}

	// Initialize with default patterns
	oe.initializeDefaultPatterns()

	return oe
}

// NewPatternDetector creates a new pattern detector
func NewPatternDetector() *PatternDetector {
	return &PatternDetector{
		patterns: make(map[string]*PatternInfo),
	}
}

// NewRecommendationEngine creates a new recommendation engine
func NewRecommendationEngine() *RecommendationEngine {
	return &RecommendationEngine{
		recommendations: make(map[string]*Recommendation),
	}
}

// initializeDefaultPatterns initializes default Dockerfile patterns
func (oe *OptimizationEngine) initializeDefaultPatterns() {
	patterns := map[string]*PatternInfo{
		"multiple-runs": {
			Name:         "multiple-runs",
			Description:  "Multiple RUN commands that could be combined",
			Occurrences:  0,
			Optimization: "Combine RUN commands using && to reduce layers",
		},
		"apt-get-install-no-clean": {
			Name:         "apt-get-install-no-clean",
			Description:  "apt-get install without cleanup",
			Occurrences:  0,
			Optimization: "Add RUN apt-get clean && rm -rf /var/lib/apt/lists/* after apt-get install",
		},
		"apt-get-update-alone": {
			Name:         "apt-get-update-alone",
			Description:  "apt-get update without subsequent install",
			Occurrences:  0,
			Optimization: "Combine apt-get update with apt-get install in the same RUN command",
		},
		"copy-whole-directory": {
			Name:         "copy-whole-directory",
			Description:  "COPY . . or COPY * * patterns",
			Occurrences:  0,
			Optimization: "Copy only necessary files using specific file paths",
		},
		"inefficient-layer-order": {
			Name:         "inefficient-layer-order",
			Description:  "Files that change frequently are copied early",
			Occurrences:  0,
			Optimization: "Copy static files first, then frequently changing files",
		},
		"no-multi-stage": {
			Name:         "no-multi-stage",
			Description:  "No multi-stage builds used",
			Occurrences:  0,
			Optimization: "Use multi-stage builds to reduce final image size",
		},
		"large-base-image": {
			Name:         "large-base-image",
			Description:  "Using large base images when smaller ones are available",
			Occurrences:  0,
			Optimization: "Use smaller base images like alpine instead of debian/ubuntu when possible",
		},
	}

	oe.patternDetector.mu.Lock()
	defer oe.patternDetector.mu.Unlock()

	for name, pattern := range patterns {
		oe.patternDetector.patterns[name] = pattern
	}

	debug.LogComponent("optimization", "Initialized %d default patterns", len(patterns))
}

// RecordBuild records a build execution for analysis
func (oe *OptimizationEngine) RecordBuild(record BuildRecord) {
	oe.mu.Lock()
	defer oe.mu.Unlock()

	record.ID = generateBuildID()
	record.Timestamp = time.Now()

	oe.buildHistory = append(oe.buildHistory, record)

	// Keep only the last 1000 builds to prevent memory issues
	if len(oe.buildHistory) > 1000 {
		oe.buildHistory = oe.buildHistory[len(oe.buildHistory)-1000:]
	}

	debug.LogComponent("optimization", "Recorded build %s: duration=%v, platform=%s, success=%t", 
		record.ID, record.Duration, record.Platform, record.Success)

	// Analyze the build for patterns
	oe.analyzeBuildPatterns(record)

	// Generate recommendations based on the build
	oe.generateRecommendations(record)
}

// AnalyzeBuildPatterns analyzes build patterns from recorded builds
func (oe *OptimizationEngine) AnalyzeBuildPatterns() BuildRecommendations {
	oe.mu.RLock()
	defer oe.mu.RUnlock()

	recommendations := BuildRecommendations{
		TotalBuilds:    len(oe.buildHistory),
		AverageDuration: calculateAverageDuration(oe.buildHistory),
		CommonPatterns: make(map[string]*PatternInfo),
		PlatformStats:  make(map[string]*PlatformStats),
		CacheStats:     calculateCacheStats(oe.buildHistory),
		Performance:    calculatePerformanceStats(oe.buildHistory),
	}

	// Analyze patterns
	oe.patternDetector.mu.RLock()
	defer oe.patternDetector.mu.RUnlock()

	for name, pattern := range oe.patternDetector.patterns {
		if pattern.Occurrences > 0 {
			recommendations.CommonPatterns[name] = pattern
		}
	}

	// Analyze platform statistics
	platformStats := make(map[string]*PlatformStats)
	for _, build := range oe.buildHistory {
		if _, exists := platformStats[build.Platform]; !exists {
			platformStats[build.Platform] = &PlatformStats{
				Builds:        0,
				AverageDuration: 0,
				SuccessRate:   0,
				TotalCacheHits: 0,
			}
		}
		platformStats[build.Platform].Builds++
	}

	// Calculate platform statistics
	for platform, stats := range platformStats {
		var platformBuilds []BuildRecord
		for _, build := range oe.buildHistory {
			if build.Platform == platform {
				platformBuilds = append(platformBuilds, build)
			}
		}

		stats.AverageDuration = calculateAverageDuration(platformBuilds)
		stats.SuccessRate = calculateSuccessRate(platformBuilds)
		stats.TotalCacheHits = calculateTotalCacheHits(platformBuilds)
	}

	recommendations.PlatformStats = platformStats

	debug.LogComponent("optimization", "Analyzed %d builds, found %d common patterns", 
		recommendations.TotalBuilds, len(recommendations.CommonPatterns))

	return recommendations
}

// GenerateDockerfileSuggestions generates optimization suggestions for a Dockerfile
func (oe *OptimizationEngine) GenerateDockerfileSuggestions(dockerfile string) []Suggestion {
	oe.patternDetector.mu.RLock()
	defer oe.patternDetector.mu.RUnlock()

	var suggestions []Suggestion

	// Check for multiple RUN commands
	if oe.checkMultipleRUNCommands(dockerfile) {
		suggestions = append(suggestions, Suggestion{
			Type:        "layer-optimization",
			Title:       "Combine RUN Commands",
			Description: "Multiple RUN commands detected. Consider combining them using && to reduce the number of layers.",
			Severity:    "medium",
			Confidence:  0.8,
			SuggestedFix: "Combine consecutive RUN commands:\n" +
				"FROM ubuntu:20.04\n" +
				"RUN apt-get update && apt-get install -y package1 package2 && rm -rf /var/lib/apt/lists/*",
		})
	}

	// Check for apt-get update without install
	if oe.checkAptGetUpdateWithoutInstall(dockerfile) {
		suggestions = append(suggestions, Suggestion{
			Type:        "apt-optimization",
			Title:       "Combine apt-get update and install",
			Description: "apt-get update found without subsequent install. This creates an unnecessary layer.",
			Severity:    "high",
			Confidence:  0.9,
			SuggestedFix: "Combine apt-get update with install:\n" +
				"RUN apt-get update && apt-get install -y package && apt-get clean && rm -rf /var/lib/apt/lists/*",
		})
	}

	// Check for apt-get install without cleanup
	if oe.checkAptGetInstallWithoutCleanup(dockerfile) {
		suggestions = append(suggestions, Suggestion{
			Type:        "apt-optimization",
			Title:       "Add cleanup after apt-get install",
			Description: "apt-get install without cleanup. This leaves cache files in the image.",
			Severity:    "medium",
			Confidence:  0.85,
			SuggestedFix: "Add cleanup after apt-get install:\n" +
				"RUN apt-get update && apt-get install -y package && apt-get clean && rm -rf /var/lib/apt/lists/*",
		})
	}

	// Check for COPY . . patterns
	if oe.checkCopyWholeDirectory(dockerfile) {
		suggestions = append(suggestions, Suggestion{
			Type:        "copy-optimization",
			Title:       "Use specific file copying",
			Description: "COPY . . or COPY * * detected. This copies unnecessary files and increases build context size.",
			Severity:    "medium",
			Confidence:  0.75,
			SuggestedFix: "Copy only necessary files:\n" +
				"COPY package.json package-lock.json ./\n" +
				"COPY src/ ./src/",
		})
	}

	// Check for no multi-stage builds
	if oe.checkNoMultiStage(dockerfile) {
		suggestions = append(suggestions, Suggestion{
			Type:        "multi-stage",
			Title:       "Use multi-stage builds",
			Description: "No multi-stage builds detected. This increases final image size.",
			Severity:    "low",
			Confidence:  0.7,
			SuggestedFix: "Add multi-stage builds:\n" +
				"FROM golang:1.19 as builder\n" +
				"WORKDIR /app\n" +
				"COPY . .\n" +
				"RUN go build -o myapp\n" +
				"\n" +
				"FROM alpine:latest\n" +
				"WORKDIR /root/\n" +
				"COPY --from=builder /app/myapp .\n" +
				"CMD ./myapp",
		})
	}

	// Check for large base images
	if oe.checkLargeBaseImage(dockerfile) {
		suggestions = append(suggestions, Suggestion{
			Type:        "base-image",
			Title:       "Use smaller base images",
			Description: "Large base image detected. Consider using smaller alternatives like alpine.",
			Severity:    "low",
			Confidence:  0.65,
			SuggestedFix: "Use smaller base images:\n" +
				"FROM ubuntu:20.04 → FROM alpine:latest\n" +
				"FROM debian:bullseye → FROM alpine:latest\n" +
				"FROM centos:7 → FROM alpine:latest",
		})
	}

	debug.LogComponent("optimization", "Generated %d suggestions for Dockerfile", len(suggestions))

	return suggestions
}

// checkMultipleRUNCommands checks for multiple RUN commands that could be combined
func (oe *OptimizationEngine) checkMultipleRUNCommands(dockerfile string) bool {
	lines := strings.Split(dockerfile, "\n")
	runCount := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "RUN ") {
			runCount++
			if runCount > 1 {
				return true
			}
		}
	}

	return false
}

// checkAptGetUpdateWithoutInstall checks for apt-get update without install
func (oe *OptimizationEngine) checkAptGetUpdateWithoutInstall(dockerfile string) bool {
	lines := strings.Split(dockerfile, "\n")
	hasUpdate := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "RUN ") {
			if strings.Contains(line, "apt-get update") && !strings.Contains(line, "apt-get install") {
				hasUpdate = true
			} else if strings.Contains(line, "apt-get install") {
				return false // Found install after update
			}
		}
	}

	return hasUpdate
}

// checkAptGetInstallWithoutCleanup checks for apt-get install without cleanup
func (oe *OptimizationEngine) checkAptGetInstallWithoutCleanup(dockerfile string) bool {
	lines := strings.Split(dockerfile, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "RUN ") {
			if strings.Contains(line, "apt-get install") {
				// Check if there's cleanup
				if strings.Contains(line, "apt-get clean") || strings.Contains(line, "rm -rf /var/lib/apt/lists") {
					return false
				}
				return true
			}
		}
	}

	return false
}

// checkCopyWholeDirectory checks for COPY . . or COPY * * patterns
func (oe *OptimizationEngine) checkCopyWholeDirectory(dockerfile string) bool {
	lines := strings.Split(dockerfile, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "COPY ") {
			if strings.Contains(line, "COPY . .") || strings.Contains(line, "COPY * *") {
				return true
			}
		}
	}

	return false
}

// checkNoMultiStage checks if no multi-stage builds are used
func (oe *OptimizationEngine) checkNoMultiStage(dockerfile string) bool {
	lines := strings.Split(dockerfile, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "FROM ") {
			// Check if this is a multi-stage build (FROM with AS)
			if strings.Contains(line, " AS ") {
				return false
			}
		}
	}

	return true
}

// checkLargeBaseImage checks for large base images
func (oe *OptimizationEngine) checkLargeBaseImage(dockerfile string) bool {
	lines := strings.Split(dockerfile, "\n")

	largeBaseImages := []string{
		"ubuntu:",
		"debian:",
		"centos:",
		"fedora:",
		"oraclelinux:",
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "FROM ") {
			for _, largeBase := range largeBaseImages {
				if strings.Contains(line, largeBase) {
					return true
				}
			}
		}
	}

	return false
}

// analyzeBuildPatterns analyzes patterns in a specific build
func (oe *OptimizationEngine) analyzeBuildPatterns(record BuildRecord) {
	dockerfileContent := readDockerfileContent(record.DockerfilePath)

	// Check for multiple RUN commands
	if oe.checkMultipleRUNCommands(dockerfileContent) {
		oe.patternDetector.mu.Lock()
		if pattern, exists := oe.patternDetector.patterns["multiple-runs"]; exists {
			pattern.Occurrences++
			pattern.LastSeen = time.Now()
		}
		oe.patternDetector.mu.Unlock()
	}

	// Check for apt-get issues
	if oe.checkAptGetUpdateWithoutInstall(dockerfileContent) {
		oe.patternDetector.mu.Lock()
		if pattern, exists := oe.patternDetector.patterns["apt-get-update-alone"]; exists {
			pattern.Occurrences++
			pattern.LastSeen = time.Now()
		}
		oe.patternDetector.mu.Unlock()
	}

	if oe.checkAptGetInstallWithoutCleanup(dockerfileContent) {
		oe.patternDetector.mu.Lock()
		if pattern, exists := oe.patternDetector.patterns["apt-get-install-no-clean"]; exists {
			pattern.Occurrences++
			pattern.LastSeen = time.Now()
		}
		oe.patternDetector.mu.Unlock()
	}

	// Check for copy issues
	if oe.checkCopyWholeDirectory(dockerfileContent) {
		oe.patternDetector.mu.Lock()
		if pattern, exists := oe.patternDetector.patterns["copy-whole-directory"]; exists {
			pattern.Occurrences++
			pattern.LastSeen = time.Now()
		}
		oe.patternDetector.mu.Unlock()
	}

	// Check for multi-stage builds
	if oe.checkNoMultiStage(dockerfileContent) {
		oe.patternDetector.mu.Lock()
		if pattern, exists := oe.patternDetector.patterns["no-multi-stage"]; exists {
			pattern.Occurrences++
			pattern.LastSeen = time.Now()
		}
		oe.patternDetector.mu.Unlock()
	}

	// Check for large base images
	if oe.checkLargeBaseImage(dockerfileContent) {
		oe.patternDetector.mu.Lock()
		if pattern, exists := oe.patternDetector.patterns["large-base-image"]; exists {
			pattern.Occurrences++
			pattern.LastSeen = time.Now()
		}
		oe.patternDetector.mu.Unlock()
	}
}

// generateRecommendations generates recommendations based on build analysis
func (oe *OptimizationEngine) generateRecommendations(record BuildRecord) {
	// Generate recommendations based on build performance
	if record.Duration > 5*time.Minute {
		oe.recommendationEngine.mu.Lock()
		oe.recommendationEngine.recommendations["slow-build"] = &Recommendation{
			ID:           "slow-build-" + record.ID,
			Type:         "performance",
			Title:        "Build Time Optimization",
			Description:  fmt.Sprintf("Build took %v, which is longer than expected. Consider optimizing Dockerfile layers and cache usage.", record.Duration),
			Severity:     "medium",
			Priority:     5,
			Confidence:   0.8,
			SuggestedFix: "Optimize Dockerfile by combining RUN commands, using multi-stage builds, and improving cache usage.",
			Implemented:  false,
			LastUpdated:  time.Now(),
		}
		oe.recommendationEngine.mu.Unlock()
	}

	// Generate recommendations based on cache performance
	if record.CacheStats.HitRate < 0.5 {
		oe.recommendationEngine.mu.Lock()
		oe.recommendationEngine.recommendations["low-cache-hit"] = &Recommendation{
			ID:           "low-cache-hit-" + record.ID,
			Type:         "cache",
			Title:        "Cache Optimization",
			Description:  fmt.Sprintf("Cache hit rate is %.2f, which is low. Consider improving cache key strategy.", record.CacheStats.HitRate),
			Severity:     "medium",
			Priority:     4,
			Confidence:   0.7,
			SuggestedFix: "Improve cache usage by organizing Dockerfile layers and using more specific cache keys.",
			Implemented:  false,
			LastUpdated:  time.Now(),
		}
		oe.recommendationEngine.mu.Unlock()
	}
}

// GetRecommendations returns all current recommendations
func (oe *OptimizationEngine) GetRecommendations() []Recommendation {
	oe.recommendationEngine.mu.RLock()
	defer oe.recommendationEngine.mu.RUnlock()

	var recommendations []Recommendation
	for _, rec := range oe.recommendationEngine.recommendations {
		recommendations = append(recommendations, *rec)
	}

	// Sort by priority
	sort.Slice(recommendations, func(i, j int) bool {
		return recommendations[i].Priority > recommendations[j].Priority
	})

	return recommendations
}

// MarkRecommendationImplemented marks a recommendation as implemented
func (oe *OptimizationEngine) MarkRecommendationImplemented(id string) {
	oe.recommendationEngine.mu.Lock()
	defer oe.recommendationEngine.mu.Unlock()

	if rec, exists := oe.recommendationEngine.recommendations[id]; exists {
		rec.Implemented = true
		rec.LastUpdated = time.Now()
	}
}

// BuildRecommendations contains comprehensive build recommendations
type BuildRecommendations struct {
	TotalBuilds    int                    `json:"totalBuilds"`
	AverageDuration time.Duration         `json:"averageDuration"`
	CommonPatterns  map[string]*PatternInfo `json:"commonPatterns"`
	PlatformStats   map[string]*PlatformStats `json:"platformStats"`
	CacheStats      CacheStats             `json:"cacheStats"`
	Performance     PerformanceMetrics     `json:"performance"`
}

// PlatformStats contains platform-specific statistics
type PlatformStats struct {
	Builds           int           `json:"builds"`
	AverageDuration  time.Duration `json:"averageDuration"`
	SuccessRate      float64       `json:"successRate"`
	TotalCacheHits   int           `json:"totalCacheHits"`
}

// Suggestion contains a Dockerfile optimization suggestion
type Suggestion struct {
	Type           string    `json:"type"`
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	Severity       string    `json:"severity"`
	Confidence     float64   `json:"confidence"`
	SuggestedFix   string    `json:"suggestedFix"`
}

// Helper functions

// calculateAverageDuration calculates the average build duration
func calculateAverageDuration(builds []BuildRecord) time.Duration {
	if len(builds) == 0 {
		return 0
	}

	var total time.Duration
	for _, build := range builds {
		total += build.Duration
	}

	return total / time.Duration(len(builds))
}

// calculateCacheStats calculates aggregate cache statistics
func calculateCacheStats(builds []BuildRecord) CacheStats {
	if len(builds) == 0 {
		return CacheStats{}
	}

	var totalHits, totalMisses, totalSize int64
	var totalLayers int
	var layerSizes []int64

	for _, build := range builds {
		totalHits += int64(build.CacheStats.CacheHits)
		totalMisses += int64(build.CacheStats.CacheMisses)
		totalSize += build.CacheStats.CacheSize
		totalLayers += build.CacheStats.CacheLayers
		layerSizes = append(layerSizes, build.CacheStats.AverageLayerSize)
	}

	totalRequests := totalHits + totalMisses
	hitRate := 0.0
	if totalRequests > 0 {
		hitRate = float64(totalHits) / float64(totalRequests)
	}

	avgLayerSize := int64(0)
	if len(layerSizes) > 0 {
		var total int64
		for _, size := range layerSizes {
			total += size
		}
		avgLayerSize = total / int64(len(layerSizes))
	}

	return CacheStats{
		HitRate:         hitRate,
		CacheHits:       int(totalHits),
		CacheMisses:     int(totalMisses),
		CacheSize:       totalSize,
		CacheLayers:     totalLayers,
		AverageLayerSize: avgLayerSize,
	}
}

// calculatePerformanceStats calculates aggregate performance statistics
func calculatePerformanceStats(builds []BuildRecord) PerformanceMetrics {
	if len(builds) == 0 {
		return PerformanceMetrics{}
	}

	var peakMemory uint64
	var totalCPU float64
	var totalIOBytes, totalNetworkBytes int64
	var totalSteps int
	var totalStepTime time.Duration

	for _, build := range builds {
		if build.Performance.PeakMemory > peakMemory {
			peakMemory = build.Performance.PeakMemory
		}
		totalCPU += build.Performance.AverageCPU
		totalIOBytes += build.Performance.TotalIOBytes
		totalNetworkBytes += build.Performance.NetworkBytes
		totalSteps += build.Performance.BuildSteps
		totalStepTime += build.Performance.AverageStepTime
	}

	avgCPU := 0.0
	if len(builds) > 0 {
		avgCPU = totalCPU / float64(len(builds))
	}

	avgStepTime := time.Duration(0)
	if totalSteps > 0 {
		avgStepTime = totalStepTime / time.Duration(totalSteps)
	}

	return PerformanceMetrics{
		PeakMemory:       peakMemory,
		AverageCPU:       avgCPU,
		TotalIOBytes:     totalIOBytes,
		NetworkBytes:     totalNetworkBytes,
		BuildSteps:       totalSteps,
		AverageStepTime:  avgStepTime,
	}
}

// calculateSuccessRate calculates the success rate of builds
func calculateSuccessRate(builds []BuildRecord) float64 {
	if len(builds) == 0 {
		return 0
	}

	successCount := 0
	for _, build := range builds {
		if build.Success {
			successCount++
		}
	}

	return float64(successCount) / float64(len(builds))
}

// calculateTotalCacheHits calculates total cache hits for builds
func calculateTotalCacheHits(builds []BuildRecord) int {
	total := 0
	for _, build := range builds {
		total += build.CacheStats.CacheHits
	}
	return total
}

// generateBuildID generates a unique build ID
func generateBuildID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// readDockerfileContent reads Dockerfile content (placeholder implementation)
func readDockerfileContent(path string) string {
	// In a real implementation, this would read the actual Dockerfile
	return "# Placeholder Dockerfile content"
}