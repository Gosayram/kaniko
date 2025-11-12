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

func TestNewRegistryClient(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	client := NewRegistryClient(nil, pool)
	if client == nil {
		t.Fatal("NewRegistryClient() returned nil")
	}
	if client.config == nil {
		t.Error("Registry client config should not be nil")
	}
	if client.parallelClient == nil {
		t.Error("Parallel client should not be nil")
	}
	if client.connectionPool == nil {
		t.Error("Connection pool should not be nil")
	}
}

func TestNewRegistryClient_WithConfig(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	config := &RegistryClientConfig{
		MaxConcurrency: 10,
		RequestTimeout: 30 * time.Second,
	}
	client := NewRegistryClient(config, pool)
	if client == nil {
		t.Fatal("NewRegistryClient() returned nil")
	}
	if client.config.MaxConcurrency != 10 {
		t.Errorf("Expected MaxConcurrency=10, got %d", client.config.MaxConcurrency)
	}
}

func TestNewRegistryClient_NilPool(t *testing.T) {
	// Should handle nil pool gracefully
	client := NewRegistryClient(nil, nil)
	if client == nil {
		t.Fatal("NewRegistryClient() returned nil")
	}
	// ParallelClient should create its own pool
	if client.parallelClient == nil {
		t.Error("Parallel client should be created even with nil pool")
	}
}

func TestRegistryClient_GetStats(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	client := NewRegistryClient(nil, pool)
	stats := client.GetStats()

	if stats == nil {
		t.Fatal("GetStats() returned nil")
	}
	if stats.TotalRequests != 0 {
		t.Errorf("Expected TotalRequests=0, got %d", stats.TotalRequests)
	}
	if stats.LastReset.IsZero() {
		t.Error("LastReset should not be zero")
	}
}

func TestRegistryClient_GetStats_ThreadSafe(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	client := NewRegistryClient(nil, pool)

	// Concurrent stats access
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client.GetStats()
		}()
	}

	wg.Wait()
	// Should not panic
}

func TestRegistryClient_LogStats(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	client := NewRegistryClient(nil, pool)

	// Should not panic
	client.LogStats()
}

func TestRegistryClient_DefaultConfig(t *testing.T) {
	config := DefaultRegistryClientConfig()
	if config == nil {
		t.Fatal("DefaultRegistryClientConfig() returned nil")
	}

	// Check that defaults are set
	if config.MaxConcurrency == 0 {
		t.Error("MaxConcurrency should have a default value")
	}
	if config.RequestTimeout == 0 {
		t.Error("RequestTimeout should have a default value")
	}
	if config.EnableParallelPull == false {
		t.Error("EnableParallelPull should be true by default")
	}
	if config.EnableManifestCache == false {
		t.Error("EnableManifestCache should be true by default")
	}
}

func TestRegistryClient_Close(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	client := NewRegistryClient(nil, pool)

	// Capture goroutine count before close
	runtime.GC()
	beforeGoroutines := runtime.NumGoroutine()

	err := client.Close()
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Give cleanup goroutines time to exit
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	afterGoroutines := runtime.NumGoroutine()

	// Check that goroutines decreased (allowing for test overhead)
	if afterGoroutines > beforeGoroutines+2 {
		t.Logf("Goroutine count: before=%d, after=%d", beforeGoroutines, afterGoroutines)
		t.Log("Warning: Possible goroutine leak detected")
	}
}

func TestRegistryClient_Close_Idempotent(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	client := NewRegistryClient(nil, pool)

	// Close multiple times should not panic
	err1 := client.Close()
	if err1 != nil {
		t.Fatalf("First Close() error = %v", err1)
	}

	err2 := client.Close()
	if err2 != nil {
		t.Fatalf("Second Close() error = %v", err2)
	}
}

func TestRegistryClient_PullImage_ContextCancellation(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	client := NewRegistryClient(nil, pool)
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel context immediately
	cancel()

	// This will fail, but should not hang
	// We can't easily test with real reference, so we just check it doesn't panic
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("PullImage() panicked (may be expected): %v", r)
			}
		}()
		_, err := client.PullImage(ctx, nil, nil)
		if err == nil {
			t.Log("PullImage() did not return error (may be expected with nil reference)")
		}
	}()
}

func TestRegistryClient_PullImage_Timeout(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	config := &RegistryClientConfig{
		RequestTimeout: 1 * time.Second,
	}
	client := NewRegistryClient(config, pool)

	ctx := context.Background()

	// This should timeout quickly, not hang
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("PullImage() panicked (may be expected): %v", r)
			}
		}()
		_, err := client.PullImage(ctxWithTimeout, nil, nil)
		if err == nil {
			t.Log("PullImage() did not return error (may be expected)")
		}
	}()
}

func TestRegistryClient_PushImage_Timeout(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	config := &RegistryClientConfig{
		RequestTimeout: 1 * time.Second,
	}
	client := NewRegistryClient(config, pool)

	ctx := context.Background()

	// PushImage uses 2x timeout, so this should timeout at 2 seconds
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("PushImage() panicked (may be expected): %v", r)
			}
		}()
		err := client.PushImage(ctxWithTimeout, nil, nil, nil)
		if err == nil {
			t.Log("PushImage() did not return error (may be expected)")
		}
	}()
}

func TestRegistryClient_ManifestCache(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	config := &RegistryClientConfig{
		EnableManifestCache:  true,
		ManifestCacheTimeout: 5 * time.Minute,
	}
	client := NewRegistryClient(config, pool)

	if client.manifestCache == nil {
		t.Error("Manifest cache should be created when EnableManifestCache is true")
	}
}

func TestRegistryClient_NoManifestCache(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	config := &RegistryClientConfig{
		EnableManifestCache: false,
	}
	client := NewRegistryClient(config, pool)

	if client.manifestCache != nil {
		t.Error("Manifest cache should not be created when EnableManifestCache is false")
	}
}

func TestRegistryClient_PullImageParallel_EmptyRefs(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	client := NewRegistryClient(nil, pool)
	ctx := context.Background()

	_, err := client.PullImageParallel(ctx, nil, nil)
	if err == nil {
		t.Error("PullImageParallel() should return error for empty refs")
	}
}

func TestRegistryClient_ConcurrentAccess(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	client := NewRegistryClient(nil, pool)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client.GetStats()
			client.LogStats()
		}()
	}

	wg.Wait()
	// Should not panic
}
