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

// Package cache provides a unified cache system with automatic cache selection
// and predictive prefetching
package cache

import (
	"sync"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sirupsen/logrus"
)

// CachePolicy defines cache selection policy
//
//nolint:revive // stuttering name is intentional for public API clarity
type CachePolicy string

const (
	// CachePolicyFastest prefers fastest cache (fast cache first)
	CachePolicyFastest CachePolicy = "fastest"
	// CachePolicyMostReliable prefers most reliable cache
	CachePolicyMostReliable CachePolicy = "most_reliable"
	// CachePolicyBalanced balances speed and reliability
	CachePolicyBalanced CachePolicy = "balanced"
)

// UnifiedCache provides a unified interface for multiple cache types
// with automatic selection and predictive prefetching
type UnifiedCache struct {
	caches []LayerCache
	policy CachePolicy
	mu     sync.RWMutex

	// Prefetching
	prefetchKeys  []string
	prefetchMutex sync.Mutex
	prefetching   bool
}

// NewUnifiedCache creates a new unified cache
func NewUnifiedCache(caches ...LayerCache) *UnifiedCache {
	return &UnifiedCache{
		caches:       caches,
		policy:       CachePolicyBalanced,
		prefetchKeys: []string{},
		prefetching:  false,
	}
}

// SetPolicy sets the cache selection policy
func (uc *UnifiedCache) SetPolicy(policy CachePolicy) {
	uc.mu.Lock()
	defer uc.mu.Unlock()
	uc.policy = policy
}

// Get retrieves a layer from the unified cache
// Tries all caches according to the policy
func (uc *UnifiedCache) Get(key string) (v1.Image, error) {
	uc.mu.RLock()
	caches := uc.caches
	policy := uc.policy
	uc.mu.RUnlock()

	// Try caches according to policy
	switch policy {
	case CachePolicyFastest:
		// Try caches in order (assume first is fastest)
		for _, cache := range caches {
			if img, err := cache.RetrieveLayer(key); err == nil {
				logrus.Debugf("Cache hit in fastest cache for key: %s", key)
				return img, nil
			}
		}
	case CachePolicyMostReliable:
		// Try all caches and return first success
		var lastErr error
		for i, cache := range caches {
			img, err := cache.RetrieveLayer(key)
			if err == nil {
				logrus.Debugf("Cache hit in cache %d for key: %s", i, key)
				return img, nil
			}
			lastErr = err
		}
		return nil, lastErr
	case CachePolicyBalanced:
		// Try first cache (usually fastest), then fallback to others
		if len(caches) > 0 {
			if img, err := caches[0].RetrieveLayer(key); err == nil {
				logrus.Debugf("Cache hit in primary cache for key: %s", key)
				return img, nil
			}
		}
		// Fallback to other caches
		for i := 1; i < len(caches); i++ {
			if img, err := caches[i].RetrieveLayer(key); err == nil {
				logrus.Debugf("Cache hit in fallback cache %d for key: %s", i, key)
				return img, nil
			}
		}
	}

	return nil, ErrCacheMiss
}

// RetrieveLayer implements LayerCache interface
func (uc *UnifiedCache) RetrieveLayer(cacheKey string) (v1.Image, error) {
	return uc.Get(cacheKey)
}

// RetrieveLayersBatch retrieves multiple layers in parallel
func (uc *UnifiedCache) RetrieveLayersBatch(keys []string) map[string]LayerResult {
	results := make(map[string]LayerResult)
	if len(keys) == 0 {
		return results
	}

	uc.mu.RLock()
	caches := uc.caches
	uc.mu.RUnlock()

	// Try to use batch method from first cache if available
	if len(caches) > 0 {
		if batchCache, ok := caches[0].(interface {
			RetrieveLayersBatch([]string) map[string]LayerResult
		}); ok {
			// Use first cache's batch method
			return batchCache.RetrieveLayersBatch(keys)
		}
	}

	// Fallback: parallel retrieval using Get method
	maxConcurrent := 3
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, key := range keys {
		wg.Add(1)
		go func(ck string) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			img, err := uc.Get(ck)

			mu.Lock()
			results[ck] = LayerResult{
				Image: img,
				Error: err,
			}
			mu.Unlock()
		}(key)
	}

	wg.Wait()
	return results
}

// Prefetch prefetches keys for predictive caching
func (uc *UnifiedCache) Prefetch(keys []string) {
	uc.prefetchMutex.Lock()
	defer uc.prefetchMutex.Unlock()

	// Add keys to prefetch queue
	uc.prefetchKeys = append(uc.prefetchKeys, keys...)

	// Start prefetching if not already running
	if !uc.prefetching {
		uc.prefetching = true
		go uc.prefetchWorker()
	}
}

// prefetchWorker performs prefetching in background
func (uc *UnifiedCache) prefetchWorker() {
	defer func() {
		uc.prefetchMutex.Lock()
		uc.prefetching = false
		uc.prefetchMutex.Unlock()
	}()

	for {
		uc.prefetchMutex.Lock()
		if len(uc.prefetchKeys) == 0 {
			uc.prefetchMutex.Unlock()
			break
		}

		// Get next key
		key := uc.prefetchKeys[0]
		uc.prefetchKeys = uc.prefetchKeys[1:]
		uc.prefetchMutex.Unlock()

		// Prefetch key (non-blocking)
		uc.prefetchKey(key)
	}
}

// prefetchKey prefetches a single key
func (uc *UnifiedCache) prefetchKey(key string) {
	// Try to get from cache (this will populate cache if available)
	uc.mu.RLock()
	caches := uc.caches
	uc.mu.RUnlock()

	// Try first cache (usually fastest)
	if len(caches) > 0 {
		if _, err := caches[0].RetrieveLayer(key); err == nil {
			logrus.Debugf("Prefetched key: %s", key)
			return
		}
	}
}

// AddCache adds a cache to the unified cache
func (uc *UnifiedCache) AddCache(cache LayerCache) {
	uc.mu.Lock()
	defer uc.mu.Unlock()
	uc.caches = append(uc.caches, cache)
}

// GetCacheCount returns the number of caches
func (uc *UnifiedCache) GetCacheCount() int {
	uc.mu.RLock()
	defer uc.mu.RUnlock()
	return len(uc.caches)
}

// GetStats returns cache statistics
func (uc *UnifiedCache) GetStats() map[string]interface{} {
	uc.mu.RLock()
	defer uc.mu.RUnlock()

	uc.prefetchMutex.Lock()
	prefetchQueueLen := len(uc.prefetchKeys)
	prefetching := uc.prefetching
	uc.prefetchMutex.Unlock()

	return map[string]interface{}{
		"cache_count":    len(uc.caches),
		"policy":         string(uc.policy),
		"prefetch_queue": prefetchQueueLen,
		"prefetching":    prefetching,
	}
}

// LayerCache interface implementation
var _ LayerCache = (*UnifiedCache)(nil)
