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
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

// TestLayerMetadata_basic tests basic LayerMetadata functionality
func TestLayerMetadata_basic(t *testing.T) {
	metadata := &LayerMetadata{
		Digest:  "sha256:abc123",
		Size:    1024,
		Created: time.Now(),
		TTL:     time.Now().Add(5 * time.Minute),
	}

	if metadata.Digest != "sha256:abc123" {
		t.Errorf("Expected digest sha256:abc123, got %s", metadata.Digest)
	}
	if metadata.Size != 1024 {
		t.Errorf("Expected size 1024, got %d", metadata.Size)
	}
}

// TestFastCacheManager_metadataStorage tests that FastCacheManager stores metadata
func TestFastCacheManager_metadataStorage(t *testing.T) {
	fcm := NewFastCacheManager()

	// Create a test image
	img, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		Config: v1.Config{},
	})
	if err != nil {
		t.Fatalf("Failed to create test image: %v", err)
	}

	digest, err := img.Digest()
	if err != nil {
		t.Fatalf("Failed to get digest: %v", err)
	}

	size, _ := img.Size()

	record := &CacheRecord{
		Key:     "test-key",
		Digest:  digest.String(),
		Image:   img,
		Present: true,
		Metadata: &LayerMetadata{
			Digest:  digest.String(),
			Size:    size,
			Created: time.Now(),
			TTL:     time.Now().Add(5 * time.Minute),
		},
	}

	// Store metadata
	err = fcm.Set("test-key", record)
	if err != nil {
		t.Fatalf("Failed to set cache record: %v", err)
	}

	// Retrieve metadata
	retrieved, err := fcm.Get("test-key")
	if err != nil {
		t.Fatalf("Failed to get cache record: %v", err)
	}

	if retrieved.Metadata == nil {
		t.Fatal("Expected metadata, got nil")
	}

	if retrieved.Metadata.Digest != digest.String() {
		t.Errorf("Expected digest %s, got %s", digest.String(), retrieved.Metadata.Digest)
	}

	if retrieved.Metadata.Size != size {
		t.Errorf("Expected size %d, got %d", size, retrieved.Metadata.Size)
	}

	// Image should be nil in fast cache (metadata only)
	if retrieved.Image != nil {
		t.Error("Expected Image to be nil in fast cache (metadata only)")
	}
}

// TestFastCacheManager_TTLExpiration tests TTL expiration in FastCacheManager
func TestFastCacheManager_TTLExpiration(t *testing.T) {
	fcm := NewFastCacheManager()

	// Create metadata with expired TTL
	expiredMetadata := &LayerMetadata{
		Digest:  "sha256:expired",
		Size:    1024,
		Created: time.Now().Add(-10 * time.Minute),
		TTL:     time.Now().Add(-1 * time.Minute), // Expired
	}

	record := &CacheRecord{
		Key:      "expired-key",
		Digest:   "sha256:expired",
		Metadata: expiredMetadata,
	}

	err := fcm.Set("expired-key", record)
	if err != nil {
		t.Fatalf("Failed to set cache record: %v", err)
	}

	// Should return cache miss due to expiration
	_, err = fcm.Get("expired-key")
	if err != ErrCacheMiss {
		t.Errorf("Expected ErrCacheMiss for expired metadata, got %v", err)
	}
}

// TestFastCacheManager_ProbeWithTTL tests Probe with TTL check
func TestFastCacheManager_ProbeWithTTL(t *testing.T) {
	fcm := NewFastCacheManager()

	// Create metadata with valid TTL
	validMetadata := &LayerMetadata{
		Digest:  "sha256:valid",
		Size:    1024,
		Created: time.Now(),
		TTL:     time.Now().Add(5 * time.Minute),
	}

	record := &CacheRecord{
		Key:      "valid-key",
		Digest:   "sha256:valid",
		Metadata: validMetadata,
	}

	err := fcm.Set("valid-key", record)
	if err != nil {
		t.Fatalf("Failed to set cache record: %v", err)
	}

	// Probe should return true for valid metadata
	exists, err := fcm.Probe("valid-key")
	if err != nil {
		t.Fatalf("Probe failed: %v", err)
	}
	if !exists {
		t.Error("Expected Probe to return true for valid metadata")
	}

	// Create expired metadata
	expiredMetadata := &LayerMetadata{
		Digest:  "sha256:expired",
		Size:    1024,
		Created: time.Now().Add(-10 * time.Minute),
		TTL:     time.Now().Add(-1 * time.Minute), // Expired
	}

	expiredRecord := &CacheRecord{
		Key:      "expired-probe-key",
		Digest:   "sha256:expired",
		Metadata: expiredMetadata,
	}

	err = fcm.Set("expired-probe-key", expiredRecord)
	if err != nil {
		t.Fatalf("Failed to set expired cache record: %v", err)
	}

	// Probe should return false for expired metadata
	exists, err = fcm.Probe("expired-probe-key")
	if err != nil {
		t.Fatalf("Probe failed: %v", err)
	}
	if exists {
		t.Error("Expected Probe to return false for expired metadata")
	}
}

// TestSlowCacheManager_metadataExtraction tests that SlowCacheManager extracts metadata
func TestSlowCacheManager_metadataExtraction(t *testing.T) {
	// Create a mock layer cache
	mockCache := &mockLayerCacheForMetadata{
		images: make(map[string]v1.Image),
	}

	// Create test image
	img, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		Config: v1.Config{},
	})
	if err != nil {
		t.Fatalf("Failed to create test image: %v", err)
	}

	mockCache.images["test-key"] = img

	scm := NewSlowCacheManager(mockCache)

	// Get record (should extract metadata)
	record, err := scm.Get("test-key")
	if err != nil {
		t.Fatalf("Failed to get cache record: %v", err)
	}

	if record.Metadata == nil {
		t.Fatal("Expected metadata, got nil")
	}

	if record.Image == nil {
		t.Error("Expected Image to be present in slow cache")
	}

	// Verify metadata was extracted
	if record.Metadata.Digest == "" {
		t.Error("Expected digest in metadata")
	}
}

// mockLayerCacheForMetadata is a simple mock for testing metadata extraction
type mockLayerCacheForMetadata struct {
	images map[string]v1.Image
}

func (m *mockLayerCacheForMetadata) RetrieveLayer(key string) (v1.Image, error) {
	img, exists := m.images[key]
	if !exists {
		return nil, ErrCacheMiss
	}
	return img, nil
}

func (m *mockLayerCacheForMetadata) RetrieveLayersBatch(keys []string) map[string]LayerResult {
	results := make(map[string]LayerResult)
	for _, key := range keys {
		img, err := m.RetrieveLayer(key)
		results[key] = LayerResult{
			Image: img,
			Error: err,
		}
	}
	return results
}
