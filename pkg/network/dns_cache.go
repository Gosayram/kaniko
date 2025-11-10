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

package network

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// DNSCacheEntry represents a cached DNS entry
type DNSCacheEntry struct {
	Addresses []net.IP
	ExpiresAt time.Time
	CreatedAt time.Time
}

// IsExpired checks if the DNS cache entry is expired
func (entry *DNSCacheEntry) IsExpired() bool {
	return time.Now().After(entry.ExpiresAt)
}

// DNSCache provides DNS caching and optimization
type DNSCache struct {
	cache      map[string]*DNSCacheEntry
	mutex      sync.RWMutex
	timeout    time.Duration
	stats      *DNSCacheStats
	statsMutex sync.RWMutex
	stopChan   chan struct{}
}

// DNSCacheStats holds DNS cache statistics
type DNSCacheStats struct {
	Hits      int64     `json:"hits"`
	Misses    int64     `json:"misses"`
	Evictions int64     `json:"evictions"`
	TotalSize int64     `json:"total_size"`
	LastReset time.Time `json:"last_reset"`
}

// NewDNSCache creates a new DNS cache
func NewDNSCache(timeout time.Duration) *DNSCache {
	cache := &DNSCache{
		cache:   make(map[string]*DNSCacheEntry),
		timeout: timeout,
		stats: &DNSCacheStats{
			LastReset: time.Now(),
		},
		stopChan: make(chan struct{}),
	}

	// Start cleanup goroutine
	go cache.cleanup()

	logrus.Info("DNS cache initialized")
	return cache
}

// LookupIP performs DNS lookup with caching
func (dc *DNSCache) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	// Check cache first
	dc.mutex.RLock()
	entry, exists := dc.cache[host]
	dc.mutex.RUnlock()

	if exists && !entry.IsExpired() {
		dc.recordHit()
		logrus.Debugf("DNS cache hit for %s", host)
		return entry.Addresses, nil
	}

	// Cache miss - perform actual lookup
	dc.recordMiss()
	logrus.Debugf("DNS cache miss for %s, performing lookup", host)

	// Perform DNS lookup
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed for %s: %w", host, err)
	}

	// Convert to []net.IP
	ips := make([]net.IP, len(addresses))
	for i, addr := range addresses {
		ips[i] = addr.IP
	}

	// Cache the result
	dc.mutex.Lock()
	dc.cache[host] = &DNSCacheEntry{
		Addresses: ips,
		ExpiresAt: time.Now().Add(dc.timeout),
		CreatedAt: time.Now(),
	}
	dc.mutex.Unlock()

	logrus.Debugf("DNS lookup completed for %s, cached %d addresses", host, len(ips))
	return ips, nil
}

// GetCachedAddresses returns cached addresses for a host (if any)
func (dc *DNSCache) GetCachedAddresses(host string) ([]net.IP, bool) {
	dc.mutex.RLock()
	defer dc.mutex.RUnlock()

	entry, exists := dc.cache[host]
	if !exists || entry.IsExpired() {
		return nil, false
	}

	return entry.Addresses, true
}

// Invalidate removes a host from the cache
func (dc *DNSCache) Invalidate(host string) {
	dc.mutex.Lock()
	defer dc.mutex.Unlock()

	delete(dc.cache, host)
	logrus.Debugf("DNS cache invalidated for %s", host)
}

// Clear removes all entries from the cache
func (dc *DNSCache) Clear() {
	dc.mutex.Lock()
	defer dc.mutex.Unlock()

	dc.cache = make(map[string]*DNSCacheEntry)
	logrus.Info("DNS cache cleared")
}

// GetStats returns DNS cache statistics
func (dc *DNSCache) GetStats() *DNSCacheStats {
	dc.statsMutex.RLock()
	defer dc.statsMutex.RUnlock()

	// Return a copy to avoid race conditions
	stats := *dc.stats
	return &stats
}

// recordHit records a cache hit
func (dc *DNSCache) recordHit() {
	dc.statsMutex.Lock()
	defer dc.statsMutex.Unlock()
	dc.stats.Hits++
}

// recordMiss records a cache miss
func (dc *DNSCache) recordMiss() {
	dc.statsMutex.Lock()
	defer dc.statsMutex.Unlock()
	dc.stats.Misses++
}

// recordEviction records a cache eviction
func (dc *DNSCache) recordEviction() {
	dc.statsMutex.Lock()
	defer dc.statsMutex.Unlock()
	dc.stats.Evictions++
}

// cleanup periodically removes expired entries
func (dc *DNSCache) cleanup() {
	ticker := time.NewTicker(DefaultCleanupInterval) // Cleanup every 5 minutes
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			dc.cleanupExpired()
		case <-dc.stopChan:
			return
		}
	}
}

// cleanupExpired removes expired entries from the cache
func (dc *DNSCache) cleanupExpired() {
	dc.mutex.Lock()
	defer dc.mutex.Unlock()

	now := time.Now()
	expiredCount := 0

	for host, entry := range dc.cache {
		if now.After(entry.ExpiresAt) {
			delete(dc.cache, host)
			expiredCount++
			dc.recordEviction()
		}
	}

	if expiredCount > 0 {
		logrus.Debugf("DNS cache cleanup: removed %d expired entries", expiredCount)
	}
}

// Close closes the DNS cache and stops cleanup goroutine
func (dc *DNSCache) Close() {
	close(dc.stopChan)
	logrus.Info("DNS cache closed")
}

// LogStats logs DNS cache statistics
func (dc *DNSCache) LogStats() {
	stats := dc.GetStats()

	logrus.Infof("DNS Cache Statistics:")
	logrus.Infof("   Hits: %d, Misses: %d", stats.Hits, stats.Misses)
	logrus.Infof("   Evictions: %d", stats.Evictions)
	logrus.Infof("   Total Size: %d entries", stats.TotalSize)

	if stats.Hits+stats.Misses > 0 {
		hitRate := float64(stats.Hits) / float64(stats.Hits+stats.Misses) * percentageBase
		logrus.Infof("   Hit Rate: %.2f%%", hitRate)
	}
}
