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
	"fmt"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestResultCache_GetSet(t *testing.T) {
	rc := NewResultCache(100, 10, 5*time.Minute)

	// Create a mock image
	img := &fakeImage{}

	// Set a result
	rc.Set("key1", img, nil)

	// Get the result
	result, found := rc.Get("key1")
	if !found {
		t.Error("Expected to find cached result, but didn't")
	}
	if result == nil {
		t.Error("Expected non-nil result")
	}
	if result.Image != img {
		t.Error("Expected cached image to match")
	}
	if result.Error != nil {
		t.Error("Expected no error")
	}

	// Get non-existent key
	_, found = rc.Get("key2")
	if found {
		t.Error("Expected not to find non-existent key")
	}
}

func TestResultCache_TTL(t *testing.T) {
	// Use very short TTL for testing
	rc := NewResultCache(100, 10, 100*time.Millisecond)

	img := &fakeImage{}

	// Set a result
	rc.Set("key1", img, nil)

	// Get immediately - should be found
	result, found := rc.Get("key1")
	if !found {
		t.Error("Expected to find cached result immediately")
	}
	if result == nil {
		t.Error("Expected non-nil result")
	}

	// Wait for TTL to expire
	time.Sleep(150 * time.Millisecond)

	// Get after expiration - should not be found
	_, found = rc.Get("key1")
	if found {
		t.Error("Expected expired result to not be found")
	}
}

func TestResultCache_ErrorCaching(t *testing.T) {
	rc := NewResultCache(100, 10, 5*time.Minute)

	testErr := &testError{msg: "test error"}

	// Cache an error result
	rc.Set("key1", nil, testErr)

	// Get the error result
	result, found := rc.Get("key1")
	if !found {
		t.Error("Expected to find cached error result")
	}
	if result.Error != testErr {
		t.Errorf("Expected cached error to match, got %v", result.Error)
	}
	if result.Image != nil {
		t.Error("Expected nil image for error result")
	}
}

func TestResultCache_MaxEntries(t *testing.T) {
	maxEntries := 5
	rc := NewResultCache(maxEntries, 100, 5*time.Minute)

	img := &fakeImage{}

	// Add more entries than max
	for i := 0; i < maxEntries+3; i++ {
		rc.Set(fmt.Sprintf("key%d", i), img, nil)
	}

	// Check that we don't exceed max entries
	stats := rc.GetStats()
	entries := stats["entries"].(int)
	if entries > maxEntries {
		t.Errorf("Expected at most %d entries, got %d", maxEntries, entries)
	}

	// Verify that oldest entries were evicted
	// Newest entries should still be present
	_, found := rc.Get(fmt.Sprintf("key%d", maxEntries+2))
	if !found {
		t.Error("Expected newest entry to still be present")
	}
}

func TestResultCache_MaxMemory(t *testing.T) {
	// Use small memory limit (1 MB)
	maxMemoryMB := 1
	rc := NewResultCache(1000, maxMemoryMB, 5*time.Minute)

	img := &fakeImage{}

	// Add entries until memory limit is reached
	// Each entry is estimated at ~200 bytes + key + digest
	// So we should be able to add roughly 5000 entries before hitting 1MB
	// But eviction should kick in before that
	for i := 0; i < 100; i++ {
		rc.Set(fmt.Sprintf("key%d", i), img, nil)
	}

	// Check memory usage
	stats := rc.GetStats()
	memoryBytes := stats["memory_bytes"].(int64)
	maxMemoryBytes := int64(maxMemoryMB) * 1024 * 1024

	if memoryBytes > maxMemoryBytes {
		t.Errorf("Expected memory usage (%d) to be <= max (%d)", memoryBytes, maxMemoryBytes)
	}

	// Verify that some entries are still present
	stats = rc.GetStats()
	entries := stats["entries"].(int)
	if entries == 0 {
		t.Error("Expected some entries to be present")
	}
}

func TestResultCache_Eviction(t *testing.T) {
	maxEntries := 3
	rc := NewResultCache(maxEntries, 10, 5*time.Minute)

	img := &fakeImage{}

	// Add entries up to limit
	rc.Set("key1", img, nil)
	rc.Set("key2", img, nil)
	rc.Set("key3", img, nil)

	// Verify all are present
	for i := 1; i <= 3; i++ {
		_, found := rc.Get(fmt.Sprintf("key%d", i))
		if !found {
			t.Errorf("Expected key%d to be present", i)
		}
	}

	// Add one more - should evict oldest
	rc.Set("key4", img, nil)

	// key1 should be evicted
	_, found := rc.Get("key1")
	if found {
		t.Error("Expected key1 to be evicted")
	}

	// key4 should be present
	_, found = rc.Get("key4")
	if !found {
		t.Error("Expected key4 to be present")
	}
}

func TestResultCache_Clear(t *testing.T) {
	rc := NewResultCache(100, 10, 5*time.Minute)

	img := &fakeImage{}

	// Add some entries
	rc.Set("key1", img, nil)
	rc.Set("key2", img, nil)

	// Verify entries are present
	stats := rc.GetStats()
	if stats["entries"].(int) != 2 {
		t.Errorf("Expected 2 entries, got %d", stats["entries"].(int))
	}

	// Clear cache
	rc.Clear()

	// Verify cache is empty
	stats = rc.GetStats()
	if stats["entries"].(int) != 0 {
		t.Errorf("Expected 0 entries after clear, got %d", stats["entries"].(int))
	}
	if stats["memory_bytes"].(int64) != 0 {
		t.Errorf("Expected 0 memory after clear, got %d", stats["memory_bytes"].(int64))
	}
}

func TestResultCache_Stats(t *testing.T) {
	rc := NewResultCache(100, 10, 5*time.Minute)

	img := &fakeImage{}

	// Add some entries
	rc.Set("key1", img, nil)
	rc.Set("key2", img, nil)

	stats := rc.GetStats()

	// Verify stats structure
	requiredKeys := []string{"entries", "max_entries", "memory_bytes", "max_memory_mb", "expired_count", "ttl_seconds"}
	for _, key := range requiredKeys {
		if _, exists := stats[key]; !exists {
			t.Errorf("Expected stat key %s to exist", key)
		}
	}

	// Verify values
	if stats["entries"].(int) != 2 {
		t.Errorf("Expected 2 entries, got %d", stats["entries"].(int))
	}
	if stats["max_entries"].(int) != 100 {
		t.Errorf("Expected max_entries=100, got %d", stats["max_entries"].(int))
	}
}

func TestResultCache_ConcurrentAccess(t *testing.T) {
	rc := NewResultCache(100, 10, 5*time.Minute)

	img := &fakeImage{}

	// Concurrent writes
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			rc.Set(fmt.Sprintf("key%d", idx), img, nil)
			done <- true
		}(i)
	}

	// Wait for all writes
	for i := 0; i < 10; i++ {
		<-done
	}

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func(idx int) {
			_, _ = rc.Get(fmt.Sprintf("key%d", idx))
			done <- true
		}(i)
	}

	// Wait for all reads
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify no panic occurred and cache is in valid state
	stats := rc.GetStats()
	if stats["entries"].(int) < 0 {
		t.Error("Expected non-negative entry count")
	}
}

// testError is a simple error type for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

// fakeImage implements v1.Image for testing
type fakeImage struct{}

func (f *fakeImage) Layers() ([]v1.Layer, error)             { return nil, nil }
func (f *fakeImage) MediaType() (types.MediaType, error)     { return "", nil }
func (f *fakeImage) Size() (int64, error)                    { return 0, nil }
func (f *fakeImage) ConfigName() (v1.Hash, error)            { return v1.Hash{}, nil }
func (f *fakeImage) ConfigFile() (*v1.ConfigFile, error)     { return &v1.ConfigFile{}, nil }
func (f *fakeImage) RawConfigFile() ([]byte, error)          { return []byte{}, nil }
func (f *fakeImage) Digest() (v1.Hash, error)                { return v1.NewHash("sha256:abc123") }
func (f *fakeImage) Manifest() (*v1.Manifest, error)         { return &v1.Manifest{}, nil }
func (f *fakeImage) RawManifest() ([]byte, error)            { return []byte{}, nil }
func (f *fakeImage) LayerByDigest(v1.Hash) (v1.Layer, error) { return nil, nil }
func (f *fakeImage) LayerByDiffID(v1.Hash) (v1.Layer, error) { return nil, nil }
