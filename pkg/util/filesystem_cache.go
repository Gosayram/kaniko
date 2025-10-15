/*
Copyright 2024 Kaniko Contributors

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

package util

import (
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileSystemCache provides caching for filesystem operations
type FileSystemCache struct {
	statCache     map[string]CachedFileInfo
	pathCache     map[string]string
	mutex         sync.RWMutex
	maxSize       int
	ttl           time.Duration
	cleanupTicker *time.Ticker
	stopChan      chan struct{}
}

// CachedFileInfo represents cached file information
type CachedFileInfo struct {
	Info      os.FileInfo
	Timestamp time.Time
	TTL       time.Duration
}

// NewFileSystemCache creates a new filesystem cache
func NewFileSystemCache(maxSize int, ttl time.Duration) *FileSystemCache {
	if maxSize <= 0 {
		maxSize = 1000 // Default cache size
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute // Default TTL
	}

	cache := &FileSystemCache{
		statCache: make(map[string]CachedFileInfo),
		pathCache: make(map[string]string),
		maxSize:   maxSize,
		ttl:       ttl,
		stopChan:  make(chan struct{}),
	}

	// Start cleanup goroutine
	cache.startCleanup()

	return cache
}

// CachedStat returns cached file information
func (fsc *FileSystemCache) CachedStat(path string) (os.FileInfo, error) {
	fsc.mutex.RLock()
	if cached, exists := fsc.statCache[path]; exists {
		// Check if cache entry is still valid
		if time.Since(cached.Timestamp) < cached.TTL {
			fsc.mutex.RUnlock()
			return cached.Info, nil
		}
		// Cache entry expired, remove it
		delete(fsc.statCache, path)
	}
	fsc.mutex.RUnlock()

	// Cache miss, get fresh info
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	// Store in cache
	fsc.mutex.Lock()
	defer fsc.mutex.Unlock()

	// Check cache size limit
	if len(fsc.statCache) >= fsc.maxSize {
		fsc.evictOldest()
	}

	fsc.statCache[path] = CachedFileInfo{
		Info:      info,
		Timestamp: time.Now(),
		TTL:       fsc.ttl,
	}

	return info, nil
}

// CachedLstat returns cached file information (for symlinks)
func (fsc *FileSystemCache) CachedLstat(path string) (os.FileInfo, error) {
	fsc.mutex.RLock()
	if cached, exists := fsc.statCache[path]; exists {
		// Check if cache entry is still valid
		if time.Since(cached.Timestamp) < cached.TTL {
			fsc.mutex.RUnlock()
			return cached.Info, nil
		}
		// Cache entry expired, remove it
		delete(fsc.statCache, path)
	}
	fsc.mutex.RUnlock()

	// Cache miss, get fresh info
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}

	// Store in cache
	fsc.mutex.Lock()
	defer fsc.mutex.Unlock()

	// Check cache size limit
	if len(fsc.statCache) >= fsc.maxSize {
		fsc.evictOldest()
	}

	fsc.statCache[path] = CachedFileInfo{
		Info:      info,
		Timestamp: time.Now(),
		TTL:       fsc.ttl,
	}

	return info, nil
}

// CachedJoin returns cached path joining result
func (fsc *FileSystemCache) CachedJoin(elem ...string) string {
	path := filepath.Join(elem...)

	fsc.mutex.RLock()
	if cached, exists := fsc.pathCache[path]; exists {
		fsc.mutex.RUnlock()
		return cached
	}
	fsc.mutex.RUnlock()

	// Cache miss, store result
	fsc.mutex.Lock()
	defer fsc.mutex.Unlock()

	// Check cache size limit
	if len(fsc.pathCache) >= fsc.maxSize {
		fsc.evictOldestPath()
	}

	fsc.pathCache[path] = path
	return path
}

// CachedAbs returns cached absolute path
func (fsc *FileSystemCache) CachedAbs(path string) (string, error) {
	fsc.mutex.RLock()
	if cached, exists := fsc.pathCache[path]; exists {
		fsc.mutex.RUnlock()
		return cached, nil
	}
	fsc.mutex.RUnlock()

	// Cache miss, get fresh result
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	// Store in cache
	fsc.mutex.Lock()
	defer fsc.mutex.Unlock()

	// Check cache size limit
	if len(fsc.pathCache) >= fsc.maxSize {
		fsc.evictOldestPath()
	}

	fsc.pathCache[path] = absPath
	return absPath, nil
}

// CachedEvalSymlinks returns cached symlink evaluation
func (fsc *FileSystemCache) CachedEvalSymlinks(path string) (string, error) {
	fsc.mutex.RLock()
	if cached, exists := fsc.pathCache[path]; exists {
		fsc.mutex.RUnlock()
		return cached, nil
	}
	fsc.mutex.RUnlock()

	// Cache miss, get fresh result
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}

	// Store in cache
	fsc.mutex.Lock()
	defer fsc.mutex.Unlock()

	// Check cache size limit
	if len(fsc.pathCache) >= fsc.maxSize {
		fsc.evictOldestPath()
	}

	fsc.pathCache[path] = resolvedPath
	return resolvedPath, nil
}

// evictOldest removes the oldest cache entry
func (fsc *FileSystemCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, cached := range fsc.statCache {
		if oldestKey == "" || cached.Timestamp.Before(oldestTime) {
			oldestKey = key
			oldestTime = cached.Timestamp
		}
	}

	if oldestKey != "" {
		delete(fsc.statCache, oldestKey)
	}
}

// evictOldestPath removes the oldest path cache entry
func (fsc *FileSystemCache) evictOldestPath() {
	// For path cache, we'll use a simple FIFO approach
	// In a more sophisticated implementation, you'd track timestamps
	for key := range fsc.pathCache {
		delete(fsc.pathCache, key)
		break
	}
}

// startCleanup starts the cleanup goroutine
func (fsc *FileSystemCache) startCleanup() {
	fsc.cleanupTicker = time.NewTicker(fsc.ttl / 2) // Cleanup every half TTL

	go func() {
		for {
			select {
			case <-fsc.cleanupTicker.C:
				fsc.cleanup()
			case <-fsc.stopChan:
				return
			}
		}
	}()
}

// cleanup removes expired cache entries
func (fsc *FileSystemCache) cleanup() {
	fsc.mutex.Lock()
	defer fsc.mutex.Unlock()

	now := time.Now()
	for key, cached := range fsc.statCache {
		if now.Sub(cached.Timestamp) > cached.TTL {
			delete(fsc.statCache, key)
		}
	}
}

// GetStats returns cache statistics
func (fsc *FileSystemCache) GetStats() map[string]interface{} {
	fsc.mutex.RLock()
	defer fsc.mutex.RUnlock()

	return map[string]interface{}{
		"stat_cache_size": len(fsc.statCache),
		"path_cache_size": len(fsc.pathCache),
		"max_size":        fsc.maxSize,
		"ttl":             fsc.ttl,
	}
}

// Clear clears all cache entries
func (fsc *FileSystemCache) Clear() {
	fsc.mutex.Lock()
	defer fsc.mutex.Unlock()

	fsc.statCache = make(map[string]CachedFileInfo)
	fsc.pathCache = make(map[string]string)
}

// Close stops the cache and cleans up resources
func (fsc *FileSystemCache) Close() {
	if fsc.cleanupTicker != nil {
		fsc.cleanupTicker.Stop()
	}
	close(fsc.stopChan)
}

// Global filesystem cache instance
var (
	globalFSCache *FileSystemCache
	fsCacheOnce   sync.Once
)

// GetGlobalFileSystemCache returns the global filesystem cache
func GetGlobalFileSystemCache() *FileSystemCache {
	fsCacheOnce.Do(func() {
		globalFSCache = NewFileSystemCache(1000, 5*time.Minute)
	})
	return globalFSCache
}

// CachedStat is a convenience function that uses the global cache
func CachedStat(path string) (os.FileInfo, error) {
	return GetGlobalFileSystemCache().CachedStat(path)
}

// CachedLstat is a convenience function that uses the global cache
func CachedLstat(path string) (os.FileInfo, error) {
	return GetGlobalFileSystemCache().CachedLstat(path)
}

// CachedJoin is a convenience function that uses the global cache
func CachedJoin(elem ...string) string {
	return GetGlobalFileSystemCache().CachedJoin(elem...)
}

// CachedAbs is a convenience function that uses the global cache
func CachedAbs(path string) (string, error) {
	return GetGlobalFileSystemCache().CachedAbs(path)
}

// CachedEvalSymlinks is a convenience function that uses the global cache
func CachedEvalSymlinks(path string) (string, error) {
	return GetGlobalFileSystemCache().CachedEvalSymlinks(path)
}
