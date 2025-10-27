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

package snapshot

import (
	"sync"
	"time"
)

// LRUHashCache provides an LRU cache for file hashes with thread-safe operations
type LRUHashCache struct {
	capacity int
	cache    map[string]*HashNode
	head     *HashNode
	tail     *HashNode
	mutex    sync.RWMutex
	stats    *LRUCacheStats
}

// HashNode represents a node in the LRU cache
type HashNode struct {
	key       string
	hash      string
	timestamp time.Time
	prev      *HashNode
	next      *HashNode
}

// LRUCacheStats tracks LRU cache performance
type LRUCacheStats struct {
	Hits       int64     `json:"hits"`
	Misses     int64     `json:"misses"`
	Evictions  int64     `json:"evictions"`
	Inserts    int64     `json:"inserts"`
	HitRate    float64   `json:"hit_rate"`
	StartTime  time.Time `json:"start_time"`
	LastAccess time.Time `json:"last_access"`
}

// NewLRUHashCache creates a new LRU hash cache
func NewLRUHashCache(capacity int) *LRUHashCache {
	cache := &LRUHashCache{
		capacity: capacity,
		cache:    make(map[string]*HashNode),
		stats: &LRUCacheStats{
			StartTime: time.Now(),
		},
	}

	// Initialize dummy head and tail nodes
	cache.head = &HashNode{}
	cache.tail = &HashNode{}
	cache.head.next = cache.tail
	cache.tail.prev = cache.head

	return cache
}

// Get retrieves a hash from the cache
func (lru *LRUHashCache) Get(key string) (string, bool) {
	lru.mutex.Lock()
	defer lru.mutex.Unlock()

	if node, exists := lru.cache[key]; exists {
		// Move to head (most recently used)
		lru.moveToHead(node)
		lru.stats.Hits++
		lru.stats.LastAccess = time.Now()
		lru.updateHitRate()
		return node.hash, true
	}

	lru.stats.Misses++
	lru.updateHitRate()
	return "", false
}

// Put stores a hash in the cache
func (lru *LRUHashCache) Put(key, hash string) {
	lru.mutex.Lock()
	defer lru.mutex.Unlock()

	if node, exists := lru.cache[key]; exists {
		// Update existing node
		node.hash = hash
		node.timestamp = time.Now()
		lru.moveToHead(node)
		return
	}

	// Create new node
	newNode := &HashNode{
		key:       key,
		hash:      hash,
		timestamp: time.Now(),
	}

	// Add to cache
	lru.cache[key] = newNode
	lru.addToHead(newNode)
	lru.stats.Inserts++

	// Check capacity
	if len(lru.cache) > lru.capacity {
		lru.evictTail()
	}
}

// Has checks if a key exists in the cache
func (lru *LRUHashCache) Has(key string) bool {
	lru.mutex.RLock()
	defer lru.mutex.RUnlock()

	_, exists := lru.cache[key]
	return exists
}

// Size returns the current cache size
func (lru *LRUHashCache) Size() int {
	lru.mutex.RLock()
	defer lru.mutex.RUnlock()

	return len(lru.cache)
}

// Clear clears the cache
func (lru *LRUHashCache) Clear() {
	lru.mutex.Lock()
	defer lru.mutex.Unlock()

	lru.cache = make(map[string]*HashNode)
	lru.head.next = lru.tail
	lru.tail.prev = lru.head
}

// GetStats returns cache statistics
func (lru *LRUHashCache) GetStats() *LRUCacheStats {
	lru.mutex.RLock()
	defer lru.mutex.RUnlock()

	// Return a copy to avoid race conditions
	stats := *lru.stats
	return &stats
}

// moveToHead moves a node to the head of the list
func (lru *LRUHashCache) moveToHead(node *HashNode) {
	lru.removeNode(node)
	lru.addToHead(node)
}

// addToHead adds a node to the head of the list
func (lru *LRUHashCache) addToHead(node *HashNode) {
	node.prev = lru.head
	node.next = lru.head.next
	lru.head.next.prev = node
	lru.head.next = node
}

// removeNode removes a node from the list
func (lru *LRUHashCache) removeNode(node *HashNode) {
	node.prev.next = node.next
	node.next.prev = node.prev
}

// evictTail removes the least recently used node
func (lru *LRUHashCache) evictTail() {
	if lru.tail.prev == lru.head {
		return // Cache is empty
	}

	lastNode := lru.tail.prev
	lru.removeNode(lastNode)
	delete(lru.cache, lastNode.key)
	lru.stats.Evictions++
}

// updateHitRate updates the hit rate statistic
func (lru *LRUHashCache) updateHitRate() {
	total := lru.stats.Hits + lru.stats.Misses
	if total > 0 {
		lru.stats.HitRate = float64(lru.stats.Hits) / float64(total)
	}
}

// WarmupCache pre-populates the cache with frequently accessed files
func (lru *LRUHashCache) WarmupCache(files []string, hasher func(string) (string, error)) {
	for _, file := range files {
		if hash, err := hasher(file); err == nil {
			lru.Put(file, hash)
		}
	}
}

// GetCacheEfficiency returns cache efficiency metrics
func (lru *LRUHashCache) GetCacheEfficiency() map[string]interface{} {
	stats := lru.GetStats()

	return map[string]interface{}{
		"hit_rate":    stats.HitRate,
		"hits":        stats.Hits,
		"misses":      stats.Misses,
		"evictions":   stats.Evictions,
		"size":        lru.Size(),
		"capacity":    lru.capacity,
		"utilization": float64(lru.Size()) / float64(lru.capacity),
		"uptime":      time.Since(stats.StartTime),
	}
}
