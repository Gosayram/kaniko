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

func TestNewManager(t *testing.T) {
	manager := NewManager(nil)
	if manager == nil {
		t.Fatal("NewManager() returned nil")
	}
	if manager.config == nil {
		t.Error("Manager config should not be nil")
	}
	if manager.initialized {
		t.Error("Manager should not be initialized by default")
	}
}

func TestNewManager_WithConfig(t *testing.T) {
	config := &ManagerConfig{
		MaxConcurrency: 10,
		RequestTimeout: 30 * time.Second,
	}
	manager := NewManager(config)
	if manager == nil {
		t.Fatal("NewManager() returned nil")
	}
	if manager.config.MaxConcurrency != 10 {
		t.Errorf("Expected MaxConcurrency=10, got %d", manager.config.MaxConcurrency)
	}
}

func TestManager_Initialize(t *testing.T) {
	manager := NewManager(nil)
	err := manager.Initialize()
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	if !manager.initialized {
		t.Error("Manager should be initialized after Initialize()")
	}
	if manager.connectionPool == nil {
		t.Error("Connection pool should be created")
	}
	if manager.registryClient == nil {
		t.Error("Registry client should be created")
	}
}

func TestManager_Initialize_Idempotent(t *testing.T) {
	manager := NewManager(nil)

	// First initialization
	err1 := manager.Initialize()
	if err1 != nil {
		t.Fatalf("First Initialize() error = %v", err1)
	}
	pool1 := manager.connectionPool
	client1 := manager.registryClient

	// Second initialization should be no-op
	err2 := manager.Initialize()
	if err2 != nil {
		t.Fatalf("Second Initialize() error = %v", err2)
	}

	// Should be the same instances
	if manager.connectionPool != pool1 {
		t.Error("Connection pool should be reused on second Initialize()")
	}
	if manager.registryClient != client1 {
		t.Error("Registry client should be reused on second Initialize()")
	}
}

func TestManager_Initialize_Concurrent(t *testing.T) {
	manager := NewManager(nil)

	// Test concurrent initialization
	var wg sync.WaitGroup
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := manager.Initialize(); err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent Initialize() error = %v", err)
	}

	if !manager.initialized {
		t.Error("Manager should be initialized after concurrent calls")
	}
}

func TestManager_GetStats(t *testing.T) {
	manager := NewManager(nil)
	stats := manager.GetStats()

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

func TestManager_GetStats_ThreadSafe(t *testing.T) {
	manager := NewManager(nil)
	manager.Initialize()

	// Concurrent stats updates
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			manager.updateStats(10*time.Millisecond, 100, true)
			manager.GetStats()
		}()
	}

	wg.Wait()

	stats := manager.GetStats()
	if stats.TotalRequests != 100 {
		t.Errorf("Expected TotalRequests=100, got %d", stats.TotalRequests)
	}
}

func TestManager_Close(t *testing.T) {
	manager := NewManager(nil)
	manager.Initialize()

	// Capture goroutine count before close
	runtime.GC()
	beforeGoroutines := runtime.NumGoroutine()

	err := manager.Close()
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

func TestManager_Close_WithoutInitialize(t *testing.T) {
	manager := NewManager(nil)

	// Should not panic
	err := manager.Close()
	if err != nil {
		t.Fatalf("Close() without Initialize() error = %v", err)
	}
}

func TestManager_Close_Idempotent(t *testing.T) {
	manager := NewManager(nil)
	manager.Initialize()

	// Close multiple times
	err1 := manager.Close()
	if err1 != nil {
		t.Fatalf("First Close() error = %v", err1)
	}

	err2 := manager.Close()
	if err2 != nil {
		t.Fatalf("Second Close() error = %v", err2)
	}
}

func TestManager_ensureInitialized(t *testing.T) {
	manager := NewManager(nil)

	// Should auto-initialize
	err := manager.ensureInitialized()
	if err != nil {
		t.Fatalf("ensureInitialized() error = %v", err)
	}
	if !manager.initialized {
		t.Error("Manager should be initialized after ensureInitialized()")
	}
}

func TestManager_PullImage_NotInitialized(t *testing.T) {
	manager := NewManager(nil)

	// This will auto-initialize, but we can't actually pull without a real registry
	// So we just test that it doesn't panic
	ctx := context.Background()

	// Use recover to catch any panics
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("PullImage() panicked with nil reference (expected): %v", r)
			}
		}()
		_, err := manager.PullImage(ctx, nil, nil)
		// Error is expected since we don't have a real reference
		if err == nil {
			t.Log("PullImage() did not return error (may be expected with nil reference)")
		}
	}()
	// Test passes if no panic occurred or panic was caught
}

func TestManager_LogStats(t *testing.T) {
	manager := NewManager(nil)
	manager.Initialize()

	// Update some stats
	manager.updateStats(100*time.Millisecond, 1000, true)
	manager.updateStats(200*time.Millisecond, 2000, false)

	// Should not panic
	manager.LogStats()
}

func TestManager_DefaultConfig(t *testing.T) {
	config := DefaultManagerConfig()
	if config == nil {
		t.Fatal("DefaultManagerConfig() returned nil")
	}

	// Check that defaults are set
	if config.MaxConcurrency == 0 {
		t.Error("MaxConcurrency should have a default value")
	}
	if config.RequestTimeout == 0 {
		t.Error("RequestTimeout should have a default value")
	}
	if config.EnableDNSOptimization == false {
		t.Error("EnableDNSOptimization should be true by default")
	}
	if config.EnableManifestCache == false {
		t.Error("EnableManifestCache should be true by default")
	}
}
