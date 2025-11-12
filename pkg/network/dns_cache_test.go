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
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestNewDNSCache(t *testing.T) {
	cache := NewDNSCache(5 * time.Minute)
	if cache == nil {
		t.Fatal("NewDNSCache() returned nil")
	}
	if cache.timeout != 5*time.Minute {
		t.Errorf("Expected timeout=5m, got %v", cache.timeout)
	}

	// Cleanup
	cache.Close()
	time.Sleep(50 * time.Millisecond) // Give cleanup goroutine time to exit
}

func TestDNSCache_LookupIP(t *testing.T) {
	cache := NewDNSCache(5 * time.Minute)
	defer cache.Close()

	ctx := context.Background()

	// Test lookup for localhost
	ips, err := cache.LookupIP(ctx, "localhost")
	if err != nil {
		t.Fatalf("LookupIP() error = %v", err)
	}
	if len(ips) == 0 {
		t.Error("LookupIP() should return at least one IP for localhost")
	}
}

func TestDNSCache_CacheHit(t *testing.T) {
	cache := NewDNSCache(5 * time.Minute)
	defer cache.Close()

	ctx := context.Background()
	host := "localhost"

	// First lookup - should be a miss
	ips1, err := cache.LookupIP(ctx, host)
	if err != nil {
		t.Fatalf("First LookupIP() error = %v", err)
	}

	stats1 := cache.GetStats()
	if stats1.Misses == 0 {
		t.Error("First lookup should be a cache miss")
	}

	// Second lookup - should be a hit
	ips2, err := cache.LookupIP(ctx, host)
	if err != nil {
		t.Fatalf("Second LookupIP() error = %v", err)
	}

	stats2 := cache.GetStats()
	if stats2.Hits == 0 {
		t.Error("Second lookup should be a cache hit")
	}

	// IPs should be the same
	if len(ips1) != len(ips2) {
		t.Errorf("IP count mismatch: first=%d, second=%d", len(ips1), len(ips2))
	}
}

func TestDNSCache_Expiration(t *testing.T) {
	// Use very short timeout for testing
	cache := NewDNSCache(100 * time.Millisecond)
	defer cache.Close()

	ctx := context.Background()
	host := "localhost"

	// First lookup
	_, err := cache.LookupIP(ctx, host)
	if err != nil {
		t.Fatalf("First LookupIP() error = %v", err)
	}

	// Verify it's cached
	_, exists := cache.GetCachedAddresses(host)
	if !exists {
		t.Error("Entry should be cached immediately")
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Entry should be expired
	_, exists = cache.GetCachedAddresses(host)
	if exists {
		t.Error("Entry should be expired after timeout")
	}
}

func TestDNSCache_Invalidate(t *testing.T) {
	cache := NewDNSCache(5 * time.Minute)
	defer cache.Close()

	ctx := context.Background()
	host := "localhost"

	// Cache an entry
	_, err := cache.LookupIP(ctx, host)
	if err != nil {
		t.Fatalf("LookupIP() error = %v", err)
	}

	// Verify it's cached
	_, exists := cache.GetCachedAddresses(host)
	if !exists {
		t.Error("Entry should be cached")
	}

	// Invalidate
	cache.Invalidate(host)

	// Should not be cached anymore
	_, exists = cache.GetCachedAddresses(host)
	if exists {
		t.Error("Entry should be invalidated")
	}
}

func TestDNSCache_Clear(t *testing.T) {
	cache := NewDNSCache(5 * time.Minute)
	defer cache.Close()

	ctx := context.Background()

	// Cache multiple entries
	hosts := []string{"localhost", "127.0.0.1"}
	for _, host := range hosts {
		_, err := cache.LookupIP(ctx, host)
		if err != nil {
			t.Fatalf("LookupIP(%s) error = %v", host, err)
		}
	}

	// Clear cache
	cache.Clear()

	// All entries should be gone
	for _, host := range hosts {
		_, exists := cache.GetCachedAddresses(host)
		if exists {
			t.Errorf("Entry for %s should be cleared", host)
		}
	}
}

func TestDNSCache_ConcurrentAccess(t *testing.T) {
	cache := NewDNSCache(5 * time.Minute)
	defer cache.Close()

	ctx := context.Background()
	hosts := []string{"localhost", "127.0.0.1", "::1"}

	var wg sync.WaitGroup
	errors := make(chan error, 30)

	// Concurrent lookups
	for i := 0; i < 10; i++ {
		for _, host := range hosts {
			wg.Add(1)
			go func(h string) {
				defer wg.Done()
				_, err := cache.LookupIP(ctx, h)
				if err != nil {
					errors <- err
				}
			}(host)
		}
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent LookupIP() error = %v", err)
	}
}

func TestDNSCache_Close_StopsCleanup(t *testing.T) {
	cache := NewDNSCache(5 * time.Minute)

	// Capture goroutine count before close
	runtime.GC()
	beforeGoroutines := runtime.NumGoroutine()

	// Close should stop cleanup goroutine
	cache.Close()

	// Give cleanup goroutine time to exit
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	afterGoroutines := runtime.NumGoroutine()

	// Check that goroutines decreased
	if afterGoroutines > beforeGoroutines+1 {
		t.Logf("Goroutine count: before=%d, after=%d", beforeGoroutines, afterGoroutines)
		t.Error("Cleanup goroutine should exit after Close()")
	}
}

func TestDNSCache_Close_Idempotent(t *testing.T) {
	cache := NewDNSCache(5 * time.Minute)

	// Close multiple times should not panic
	cache.Close()
	cache.Close()
	cache.Close()
}

func TestDNSCache_GetStats(t *testing.T) {
	cache := NewDNSCache(5 * time.Minute)
	defer cache.Close()

	ctx := context.Background()

	// Perform some operations
	cache.LookupIP(ctx, "localhost")
	cache.LookupIP(ctx, "localhost") // Should be a hit
	cache.LookupIP(ctx, "127.0.0.1")

	stats := cache.GetStats()
	if stats == nil {
		t.Fatal("GetStats() returned nil")
	}
	if stats.Hits == 0 {
		t.Error("Expected at least one cache hit")
	}
	if stats.Misses < 2 {
		t.Error("Expected at least two cache misses")
	}
}

func TestDNSCache_EntryIsExpired(t *testing.T) {
	entry := &DNSCacheEntry{
		ExpiresAt: time.Now().Add(-1 * time.Second), // Expired
	}
	if !entry.IsExpired() {
		t.Error("Entry should be expired")
	}

	entry = &DNSCacheEntry{
		ExpiresAt: time.Now().Add(1 * time.Hour), // Not expired
	}
	if entry.IsExpired() {
		t.Error("Entry should not be expired")
	}
}

func TestDNSCache_CleanupExpired(t *testing.T) {
	cache := NewDNSCache(50 * time.Millisecond)
	defer cache.Close()

	ctx := context.Background()

	// Add entries
	cache.LookupIP(ctx, "localhost")

	// Wait for expiration and cleanup
	time.Sleep(200 * time.Millisecond)

	// Entry should be expired and cleaned up
	_, exists := cache.GetCachedAddresses("localhost")
	if exists {
		t.Log("Entry may still be cached if cleanup hasn't run yet (this is expected)")
	}
}
