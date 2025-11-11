/*
Copyright 2024 Google LLC

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

package cache

import (
	"context"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/config"
)

// PredictiveCache provides experimental predictive caching based on build history patterns
// This is an experimental feature that predicts which layers will be needed next
// based on command patterns in the Dockerfile
type PredictiveCache struct {
	// Configuration
	opts            *config.KanikoOptions
	maxLayers       int
	maxMemoryMB     int
	currentMemoryMB int

	// Pattern analysis
	commandPatterns map[string][]string // command -> predicted next commands
	patternCounts   map[string]int      // pattern -> frequency
	mu              sync.RWMutex

	// Statistics
	stats *PredictiveStats
}

// PredictiveStats tracks statistics for predictive cache
type PredictiveStats struct {
	PredictionsMade  int
	PredictionsHit   int
	PredictionsMiss  int
	LayersPrefetched int
	MemoryUsedMB     int
	mu               sync.RWMutex
}

// NewPredictiveCache creates a new predictive cache instance
func NewPredictiveCache(opts *config.KanikoOptions) *PredictiveCache {
	maxLayers := opts.PredictiveCacheMaxLayers
	if maxLayers <= 0 {
		maxLayers = 20 // Default
	}

	maxMemoryMB := opts.PredictiveCacheMaxMemoryMB
	if maxMemoryMB <= 0 {
		maxMemoryMB = 50 // Default
	}

	return &PredictiveCache{
		opts:            opts,
		maxLayers:       maxLayers,
		maxMemoryMB:     maxMemoryMB,
		commandPatterns: make(map[string][]string),
		patternCounts:   make(map[string]int),
		stats:           &PredictiveStats{},
	}
}

// PredictNextKeys predicts cache keys for next commands based on current command pattern
// This is a simple implementation that looks at command sequences
func (pc *PredictiveCache) PredictNextKeys(currentCommand string, allCommands []string, currentIndex int) []string {
	if !pc.opts.EnablePredictiveCache {
		return nil
	}

	pc.mu.Lock()
	defer pc.mu.Unlock()

	// Simple pattern: predict next N commands after current
	// In a more sophisticated implementation, this would analyze historical patterns
	predictedKeys := make([]string, 0)
	maxPredictions := pc.maxLayers
	if maxPredictions > len(allCommands)-currentIndex-1 {
		maxPredictions = len(allCommands) - currentIndex - 1
	}

	// Predict next commands (simple sequential prediction)
	for i := 1; i <= maxPredictions && currentIndex+i < len(allCommands); i++ {
		nextCommand := allCommands[currentIndex+i]
		// In real implementation, we'd compute cache key here
		// For now, we just return command strings as placeholders
		predictedKeys = append(predictedKeys, nextCommand)
	}

	pc.stats.mu.Lock()
	pc.stats.PredictionsMade += len(predictedKeys)
	pc.stats.mu.Unlock()

	logrus.Debugf("Predictive cache: predicted %d next commands after '%s'", len(predictedKeys), currentCommand)
	return predictedKeys
}

// RecordPattern records a command pattern for future predictions
func (pc *PredictiveCache) RecordPattern(command string, nextCommands []string) {
	if !pc.opts.EnablePredictiveCache {
		return
	}

	pc.mu.Lock()
	defer pc.mu.Unlock()

	// Store pattern
	patternKey := command
	pc.commandPatterns[patternKey] = nextCommands
	pc.patternCounts[patternKey]++
}

// PrefetchKeys prefetches predicted cache keys with strict limits
func (pc *PredictiveCache) PrefetchKeys(ctx context.Context, keys []string, prefetchFunc func(string) error) {
	if !pc.opts.EnablePredictiveCache {
		return
	}

	// Apply strict limits
	if len(keys) > pc.maxLayers {
		keys = keys[:pc.maxLayers]
		logrus.Debugf("Predictive cache: limited prefetch to %d layers (max: %d)", pc.maxLayers, pc.maxLayers)
	}

	// Prefetch in background with context cancellation
	for _, key := range keys {
		select {
		case <-ctx.Done():
			logrus.Debugf("Predictive cache: prefetch canceled")
			return
		default:
			if err := prefetchFunc(key); err != nil {
				logrus.Debugf("Predictive cache: prefetch failed for key %s: %v", key, err)
				pc.stats.mu.Lock()
				pc.stats.PredictionsMiss++
				pc.stats.mu.Unlock()
			} else {
				pc.stats.mu.Lock()
				pc.stats.PredictionsHit++
				pc.stats.LayersPrefetched++
				pc.stats.mu.Unlock()
			}
		}
	}
}

// GetStats returns predictive cache statistics
func (pc *PredictiveCache) GetStats() *PredictiveStats {
	pc.stats.mu.RLock()
	defer pc.stats.mu.RUnlock()

	// Return a copy
	return &PredictiveStats{
		PredictionsMade:  pc.stats.PredictionsMade,
		PredictionsHit:   pc.stats.PredictionsHit,
		PredictionsMiss:  pc.stats.PredictionsMiss,
		LayersPrefetched: pc.stats.LayersPrefetched,
		MemoryUsedMB:     pc.stats.MemoryUsedMB,
	}
}

// Reset clears all patterns and statistics (for testing)
func (pc *PredictiveCache) Reset() {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	pc.commandPatterns = make(map[string][]string)
	pc.patternCounts = make(map[string]int)
	pc.stats = &PredictiveStats{}
	pc.currentMemoryMB = 0
}
