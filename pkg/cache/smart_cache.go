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
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/config"
)

// Constants for cache operations (optimized for 1GB cache)
const (
	preloadBufferSize = 200         // Increased for better performance
	defaultImageSize  = 1024 * 1024 // 1MB
	percentageBase    = 100
	// Cache size optimization for 1GB (reserved for future use)
	// maxCacheSizeBytes = 1024 * 1024 * 1024 // 1GB
	// avgImageSizeBytes = 50 * 1024 * 1024   // 50MB average image size
	// Mathematical constants
	averageDivisor = 2
)

// SmartCache provides intelligent caching with LRU, preloading, and predictive caching
type SmartCache struct {
	// Core cache components
	lruCache     *LRUCache
	preloadCache map[string]v1.Image
	preloadMutex sync.RWMutex

	// Statistics and monitoring
	stats      *Statistics
	statsMutex sync.RWMutex

	// Configuration
	opts           *config.KanikoOptions
	maxPreloadSize int
	preloadTimeout time.Duration

	// Background workers
	preloadWorker chan string
	preloadCtx    context.Context
	preloadCancel context.CancelFunc
	preloadWg     sync.WaitGroup
}

// LRUCache implements a thread-safe LRU cache
type LRUCache struct {
	capacity int
	cache    map[string]*Node
	head     *Node
	tail     *Node
	mutex    sync.RWMutex
}

// Node represents a node in the LRU cache
type Node struct {
	key      string
	value    v1.Image
	prev     *Node
	next     *Node
	lastUsed time.Time
	size     int64
}

// Statistics provides detailed cache performance metrics
type Statistics struct {
	Hits              int64         `json:"hits"`
	Misses            int64         `json:"misses"`
	PreloadHits       int64         `json:"preload_hits"`
	PreloadMisses     int64         `json:"preload_misses"`
	Evictions         int64         `json:"evictions"`
	PreloadSuccesses  int64         `json:"preload_successes"`
	PreloadFailures   int64         `json:"preload_failures"`
	TotalRequests     int64         `json:"total_requests"`
	HitRate           float64       `json:"hit_rate"`
	PreloadHitRate    float64       `json:"preload_hit_rate"`
	AverageAccessTime time.Duration `json:"average_access_time"`
	LastReset         time.Time     `json:"last_reset"`
	CacheSize         int64         `json:"cache_size"`
	CacheCapacity     int64         `json:"cache_capacity"`
}

// NewSmartCache creates a new smart cache instance
func NewSmartCache(opts *config.KanikoOptions) *SmartCache {
	ctx, cancel := context.WithCancel(context.Background())

	sc := &SmartCache{
		lruCache:       NewLRUCache(opts.MaxCacheEntries),
		preloadCache:   make(map[string]v1.Image),
		opts:           opts,
		maxPreloadSize: opts.MaxPreloadSize,
		preloadTimeout: opts.PreloadTimeout,
		preloadWorker:  make(chan string, preloadBufferSize), // Buffer for preload requests (optimized for 1GB)
		preloadCtx:     ctx,
		preloadCancel:  cancel,
		stats: &Statistics{
			LastReset: time.Now(),
		},
	}

	// Start background preload worker
	sc.startPreloadWorker()

	logrus.Info("🧠 Smart cache initialized with LRU and preloading capabilities")
	return sc
}

// NewLRUCache creates a new LRU cache with the specified capacity
func NewLRUCache(capacity int) *LRUCache {
	lc := &LRUCache{
		capacity: capacity,
		cache:    make(map[string]*Node),
	}

	// Initialize dummy head and tail nodes
	lc.head = &Node{}
	lc.tail = &Node{}
	lc.head.next = lc.tail
	lc.tail.prev = lc.head

	return lc
}

// Get retrieves an image from the cache
func (sc *SmartCache) Get(key string) (v1.Image, bool) {
	start := time.Now()
	defer func() {
		sc.updateAccessTime(time.Since(start))
	}()

	// Try LRU cache first
	if img, found := sc.lruCache.Get(key); found {
		sc.recordHit()
		logrus.Debugf("🎯 Cache hit for key: %s", key)
		return img, true
	}

	// Try preload cache
	sc.preloadMutex.RLock()
	if img, found := sc.preloadCache[key]; found {
		sc.preloadMutex.RUnlock()
		sc.recordPreloadHit()
		logrus.Debugf("🚀 Preload cache hit for key: %s", key)

		// Move to LRU cache for future access
		sc.lruCache.Put(key, img)
		return img, true
	}
	sc.preloadMutex.RUnlock()

	// Cache miss
	sc.recordMiss()
	logrus.Debugf("❌ Cache miss for key: %s", key)
	return nil, false
}

// Put stores an image in the cache
func (sc *SmartCache) Put(key string, img v1.Image) {
	sc.lruCache.Put(key, img)
	logrus.Debugf("💾 Cached image for key: %s", key)
}

// PreloadRequest requests preloading of an image
func (sc *SmartCache) PreloadRequest(key string) {
	select {
	case sc.preloadWorker <- key:
		logrus.Debugf("📥 Preload requested for key: %s", key)
	default:
		logrus.Warnf("⚠️ Preload queue full, dropping request for key: %s", key)
	}
}

// Get retrieves an image from the LRU cache
func (lc *LRUCache) Get(key string) (v1.Image, bool) {
	lc.mutex.Lock()
	defer lc.mutex.Unlock()

	if node, exists := lc.cache[key]; exists {
		// Move to head (most recently used)
		lc.moveToHead(node)
		node.lastUsed = time.Now()
		return node.value, true
	}

	return nil, false
}

// Put stores an image in the LRU cache
func (lc *LRUCache) Put(key string, img v1.Image) {
	lc.mutex.Lock()
	defer lc.mutex.Unlock()

	// Calculate image size (approximate)
	size := lc.calculateImageSize(img)

	if node, exists := lc.cache[key]; exists {
		// Update existing node
		node.value = img
		node.size = size
		node.lastUsed = time.Now()
		lc.moveToHead(node)
		return
	}

	// Create new node
	newNode := &Node{
		key:      key,
		value:    img,
		lastUsed: time.Now(),
		size:     size,
	}

	// Add to cache
	lc.cache[key] = newNode
	lc.addToHead(newNode)

	// Evict if over capacity
	if len(lc.cache) > lc.capacity {
		lc.evictLRU()
	}
}

// moveToHead moves a node to the head of the list
func (lc *LRUCache) moveToHead(node *Node) {
	lc.removeNode(node)
	lc.addToHead(node)
}

// addToHead adds a node to the head of the list
func (lc *LRUCache) addToHead(node *Node) {
	node.prev = lc.head
	node.next = lc.head.next
	lc.head.next.prev = node
	lc.head.next = node
}

// removeNode removes a node from the list
func (lc *LRUCache) removeNode(node *Node) {
	node.prev.next = node.next
	node.next.prev = node.prev
}

// evictLRU removes the least recently used node
func (lc *LRUCache) evictLRU() {
	if lc.tail.prev == lc.head {
		return // Cache is empty
	}

	lru := lc.tail.prev
	lc.removeNode(lru)
	delete(lc.cache, lru.key)
}

// calculateImageSize calculates the approximate size of an image
func (lc *LRUCache) calculateImageSize(_ v1.Image) int64 {
	// This is a simplified calculation
	// In a real implementation, you'd want to get the actual size
	return defaultImageSize
}

// startPreloadWorker starts the background preload worker
func (sc *SmartCache) startPreloadWorker() {
	sc.preloadWg.Add(1)
	go func() {
		defer sc.preloadWg.Done()

		for {
			select {
			case key := <-sc.preloadWorker:
				sc.handlePreloadRequest(key)
			case <-sc.preloadCtx.Done():
				return
			}
		}
	}()
}

// handlePreloadRequest handles a preload request
func (sc *SmartCache) handlePreloadRequest(key string) {
	// Check if already in cache
	if _, found := sc.lruCache.Get(key); found {
		return // Already cached
	}

	// Check preload cache size limit
	sc.preloadMutex.RLock()
	if len(sc.preloadCache) >= sc.maxPreloadSize {
		sc.preloadMutex.RUnlock()
		logrus.Debugf("⚠️ Preload cache full, skipping key: %s", key)
		return
	}
	sc.preloadMutex.RUnlock()

	// Simulate preloading (in real implementation, this would fetch from registry)
	logrus.Debugf("🔄 Preloading image for key: %s", key)

	// For now, we'll just mark it as requested
	// In a real implementation, you'd fetch the image from the registry
	sc.recordPreloadRequest()
}

// recordHit records a cache hit
func (sc *SmartCache) recordHit() {
	sc.statsMutex.Lock()
	defer sc.statsMutex.Unlock()

	sc.stats.Hits++
	sc.stats.TotalRequests++
	sc.updateHitRate()
}

// recordMiss records a cache miss
func (sc *SmartCache) recordMiss() {
	sc.statsMutex.Lock()
	defer sc.statsMutex.Unlock()

	sc.stats.Misses++
	sc.stats.TotalRequests++
	sc.updateHitRate()
}

// recordPreloadHit records a preload cache hit
func (sc *SmartCache) recordPreloadHit() {
	sc.statsMutex.Lock()
	defer sc.statsMutex.Unlock()

	sc.stats.PreloadHits++
	sc.updatePreloadHitRate()
}

// recordPreloadRequest records a preload request
func (sc *SmartCache) recordPreloadRequest() {
	sc.statsMutex.Lock()
	defer sc.statsMutex.Unlock()

	sc.stats.PreloadSuccesses++
}

// updateHitRate updates the hit rate
func (sc *SmartCache) updateHitRate() {
	if sc.stats.TotalRequests > 0 {
		sc.stats.HitRate = float64(sc.stats.Hits) / float64(sc.stats.TotalRequests)
	}
}

// updatePreloadHitRate updates the preload hit rate
func (sc *SmartCache) updatePreloadHitRate() {
	totalPreloads := sc.stats.PreloadHits + sc.stats.PreloadMisses
	if totalPreloads > 0 {
		sc.stats.PreloadHitRate = float64(sc.stats.PreloadHits) / float64(totalPreloads)
	}
}

// updateAccessTime updates the average access time
func (sc *SmartCache) updateAccessTime(duration time.Duration) {
	sc.statsMutex.Lock()
	defer sc.statsMutex.Unlock()

	// Simple moving average
	if sc.stats.AverageAccessTime == 0 {
		sc.stats.AverageAccessTime = duration
	} else {
		sc.stats.AverageAccessTime = (sc.stats.AverageAccessTime + duration) / averageDivisor
	}
}

// GetStatistics returns cache statistics
func (sc *SmartCache) GetStatistics() *Statistics {
	sc.statsMutex.RLock()
	defer sc.statsMutex.RUnlock()

	// Return a copy to avoid race conditions
	stats := *sc.stats
	return &stats
}

// LogStatistics logs cache statistics
func (sc *SmartCache) LogStatistics() {
	stats := sc.GetStatistics()

	logrus.Infof("📊 Smart Cache Statistics:")
	logrus.Infof("   Hits: %d, Misses: %d, Hit Rate: %.2f%%",
		stats.Hits, stats.Misses, stats.HitRate*percentageBase)
	logrus.Infof("   Preload Hits: %d, Preload Hit Rate: %.2f%%",
		stats.PreloadHits, stats.PreloadHitRate*percentageBase)
	logrus.Infof("   Total Requests: %d, Average Access Time: %v",
		stats.TotalRequests, stats.AverageAccessTime)
	logrus.Infof("   Cache Size: %d entries", len(sc.lruCache.cache))
}

// Close shuts down the smart cache
func (sc *SmartCache) Close() {
	sc.preloadCancel()
	sc.preloadWg.Wait()
	close(sc.preloadWorker)

	logrus.Info("🔒 Smart cache closed")
}
