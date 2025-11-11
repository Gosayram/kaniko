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
	"testing"

	"github.com/Gosayram/kaniko/pkg/config"
)

func TestPredictiveCache_Disabled(t *testing.T) {
	opts := &config.KanikoOptions{
		EnablePredictiveCache: false,
	}
	pc := NewPredictiveCache(opts)

	// Should return nil when disabled
	keys := pc.PredictNextKeys("RUN echo test", []string{"RUN echo test"}, 0)
	if keys != nil {
		t.Errorf("Expected nil when predictive cache is disabled, got %v", keys)
	}
}

func TestPredictiveCache_PredictNextKeys(t *testing.T) {
	opts := &config.KanikoOptions{
		EnablePredictiveCache:    true,
		PredictiveCacheMaxLayers: 5,
	}
	pc := NewPredictiveCache(opts)

	allCommands := []string{
		"RUN echo 1",
		"RUN echo 2",
		"RUN echo 3",
		"RUN echo 4",
		"RUN echo 5",
		"RUN echo 6",
	}

	// Predict next keys from index 0
	predictedKeys := pc.PredictNextKeys(allCommands[0], allCommands, 0)
	if len(predictedKeys) == 0 {
		t.Error("Expected predicted keys, got empty slice")
	}

	// Should predict up to maxLayers
	if len(predictedKeys) > pc.maxLayers {
		t.Errorf("Expected at most %d predicted keys, got %d", pc.maxLayers, len(predictedKeys))
	}

	// Check statistics
	stats := pc.GetStats()
	if stats.PredictionsMade == 0 {
		t.Error("Expected predictions to be recorded in stats")
	}
}

func TestPredictiveCache_PredictNextKeys_Limit(t *testing.T) {
	opts := &config.KanikoOptions{
		EnablePredictiveCache:    true,
		PredictiveCacheMaxLayers: 3,
	}
	pc := NewPredictiveCache(opts)

	allCommands := []string{
		"RUN echo 1",
		"RUN echo 2",
		"RUN echo 3",
		"RUN echo 4",
		"RUN echo 5",
	}

	// Predict next keys from index 0
	predictedKeys := pc.PredictNextKeys(allCommands[0], allCommands, 0)

	// Should be limited to maxLayers (3)
	if len(predictedKeys) > 3 {
		t.Errorf("Expected at most 3 predicted keys, got %d", len(predictedKeys))
	}
}

func TestPredictiveCache_RecordPattern(t *testing.T) {
	opts := &config.KanikoOptions{
		EnablePredictiveCache: true,
	}
	pc := NewPredictiveCache(opts)

	// Record a pattern
	command := "RUN echo test"
	nextCommands := []string{"RUN echo next1", "RUN echo next2"}
	pc.RecordPattern(command, nextCommands)

	// Verify pattern was recorded
	pc.mu.RLock()
	patternCount := pc.patternCounts[command]
	pc.mu.RUnlock()

	if patternCount != 1 {
		t.Errorf("Expected pattern count to be 1, got %d", patternCount)
	}
}

func TestPredictiveCache_PrefetchKeys(t *testing.T) {
	opts := &config.KanikoOptions{
		EnablePredictiveCache:    true,
		PredictiveCacheMaxLayers: 5,
	}
	pc := NewPredictiveCache(opts)

	keys := []string{"key1", "key2", "key3"}
	prefetchedCount := 0

	// Prefetch keys
	ctx := context.Background()
	pc.PrefetchKeys(ctx, keys, func(key string) error {
		prefetchedCount++
		return nil
	})

	// Verify all keys were prefetched
	if prefetchedCount != len(keys) {
		t.Errorf("Expected %d keys to be prefetched, got %d", len(keys), prefetchedCount)
	}

	// Check statistics
	stats := pc.GetStats()
	if stats.LayersPrefetched != len(keys) {
		t.Errorf("Expected %d layers prefetched in stats, got %d", len(keys), stats.LayersPrefetched)
	}
}

func TestPredictiveCache_PrefetchKeys_Limit(t *testing.T) {
	opts := &config.KanikoOptions{
		EnablePredictiveCache:    true,
		PredictiveCacheMaxLayers: 2,
	}
	pc := NewPredictiveCache(opts)

	keys := []string{"key1", "key2", "key3", "key4", "key5"}
	prefetchedCount := 0

	// Prefetch keys (should be limited to maxLayers)
	ctx := context.Background()
	pc.PrefetchKeys(ctx, keys, func(key string) error {
		prefetchedCount++
		return nil
	})

	// Should be limited to maxLayers (2)
	if prefetchedCount > 2 {
		t.Errorf("Expected at most 2 keys to be prefetched, got %d", prefetchedCount)
	}
}

func TestPredictiveCache_PrefetchKeys_Cancellation(t *testing.T) {
	opts := &config.KanikoOptions{
		EnablePredictiveCache:    true,
		PredictiveCacheMaxLayers: 10,
	}
	pc := NewPredictiveCache(opts)

	keys := []string{"key1", "key2", "key3"}
	prefetchedCount := 0

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Prefetch keys (should be cancelled immediately)
	pc.PrefetchKeys(ctx, keys, func(key string) error {
		prefetchedCount++
		return nil
	})

	// Should not prefetch any keys due to cancellation
	if prefetchedCount > 0 {
		t.Errorf("Expected 0 keys to be prefetched due to cancellation, got %d", prefetchedCount)
	}
}

func TestPredictiveCache_GetStats(t *testing.T) {
	opts := &config.KanikoOptions{
		EnablePredictiveCache: true,
	}
	pc := NewPredictiveCache(opts)

	// Make some predictions
	allCommands := []string{"RUN echo 1", "RUN echo 2", "RUN echo 3"}
	pc.PredictNextKeys(allCommands[0], allCommands, 0)

	// Get stats
	stats := pc.GetStats()
	if stats == nil {
		t.Fatal("Expected stats, got nil")
	}

	if stats.PredictionsMade == 0 {
		t.Error("Expected predictions to be recorded")
	}
}

func TestPredictiveCache_Reset(t *testing.T) {
	opts := &config.KanikoOptions{
		EnablePredictiveCache: true,
	}
	pc := NewPredictiveCache(opts)

	// Record some patterns and make predictions
	pc.RecordPattern("RUN echo test", []string{"RUN echo next"})
	pc.PredictNextKeys("RUN echo test", []string{"RUN echo test"}, 0)

	// Reset
	pc.Reset()

	// Verify reset
	stats := pc.GetStats()
	if stats.PredictionsMade != 0 {
		t.Errorf("Expected predictions to be reset to 0, got %d", stats.PredictionsMade)
	}

	pc.mu.RLock()
	patternCount := len(pc.commandPatterns)
	pc.mu.RUnlock()

	if patternCount != 0 {
		t.Errorf("Expected patterns to be cleared, got %d patterns", patternCount)
	}
}
