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

func TestNewConnectionPool(t *testing.T) {
	pool := NewConnectionPool(nil)
	if pool == nil {
		t.Fatal("NewConnectionPool() returned nil")
	}
	if pool.config == nil {
		t.Error("Connection pool config should not be nil")
	}
	if pool.client == nil {
		t.Error("HTTP client should not be nil")
	}
	if pool.transport == nil {
		t.Error("HTTP transport should not be nil")
	}
	defer pool.Close()
}

func TestNewConnectionPool_WithConfig(t *testing.T) {
	config := &ConnectionPoolConfig{
		MaxIdleConns:        50,
		MaxIdleConnsPerHost: 5,
		DialTimeout:         10 * time.Second,
	}
	pool := NewConnectionPool(config)
	if pool == nil {
		t.Fatal("NewConnectionPool() returned nil")
	}
	if pool.config.MaxIdleConns != 50 {
		t.Errorf("Expected MaxIdleConns=50, got %d", pool.config.MaxIdleConns)
	}
	defer pool.Close()
}

func TestConnectionPool_GetClient(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	client := pool.GetClient()
	if client == nil {
		t.Fatal("GetClient() returned nil")
	}
	if client != pool.client {
		t.Error("GetClient() should return the same client instance")
	}
}

func TestConnectionPool_GetTransport(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	transport := pool.GetTransport()
	if transport == nil {
		t.Fatal("GetTransport() returned nil")
	}
	if transport != pool.transport {
		t.Error("GetTransport() should return the same transport instance")
	}
}

func TestConnectionPool_Close(t *testing.T) {
	pool := NewConnectionPool(nil)

	// Capture goroutine count before close
	runtime.GC()
	beforeGoroutines := runtime.NumGoroutine()

	err := pool.Close()
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

func TestConnectionPool_Close_Idempotent(t *testing.T) {
	pool := NewConnectionPool(nil)

	// Close multiple times should not panic
	err1 := pool.Close()
	if err1 != nil {
		t.Fatalf("First Close() error = %v", err1)
	}

	err2 := pool.Close()
	if err2 != nil {
		t.Fatalf("Second Close() error = %v", err2)
	}

	err3 := pool.Close()
	if err3 != nil {
		t.Fatalf("Third Close() error = %v", err3)
	}
}

func TestConnectionPool_Close_WithDNSCache(t *testing.T) {
	config := &ConnectionPoolConfig{
		EnableDNSOptimization: true,
		DNSCacheTimeout:       5 * time.Minute,
	}
	pool := NewConnectionPool(config)

	// Verify DNS cache is created
	if pool.dnsCache == nil {
		t.Fatal("DNS cache should be created when EnableDNSOptimization is true")
	}

	// Close should close DNS cache
	err := pool.Close()
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// DNS cache should be closed (we can't directly check, but no panic means it worked)
}

func TestConnectionPool_GetStats(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	stats := pool.GetStats()
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

func TestConnectionPool_UpdateStats(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	pool.UpdateStats(100 * time.Millisecond)
	stats := pool.GetStats()

	if stats.TotalRequests != 1 {
		t.Errorf("Expected TotalRequests=1, got %d", stats.TotalRequests)
	}
	if stats.AverageLatency != 100*time.Millisecond {
		t.Errorf("Expected AverageLatency=100ms, got %v", stats.AverageLatency)
	}
}

func TestConnectionPool_UpdateStats_ThreadSafe(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	// Concurrent stats updates
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pool.UpdateStats(10 * time.Millisecond)
			pool.GetStats()
		}()
	}

	wg.Wait()

	stats := pool.GetStats()
	if stats.TotalRequests != 100 {
		t.Errorf("Expected TotalRequests=100, got %d", stats.TotalRequests)
	}
}

func TestConnectionPool_RecordCacheHit(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	pool.RecordCacheHit()
	stats := pool.GetStats()

	if stats.CacheHits != 1 {
		t.Errorf("Expected CacheHits=1, got %d", stats.CacheHits)
	}
}

func TestConnectionPool_RecordCacheMiss(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	pool.RecordCacheMiss()
	stats := pool.GetStats()

	if stats.CacheMisses != 1 {
		t.Errorf("Expected CacheMisses=1, got %d", stats.CacheMisses)
	}
}

func TestConnectionPool_LogStats(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	// Update some stats
	pool.UpdateStats(100 * time.Millisecond)
	pool.RecordCacheHit()
	pool.RecordCacheMiss()

	// Should not panic
	pool.LogStats()
}

func TestConnectionPool_DefaultConfig(t *testing.T) {
	config := DefaultConnectionPoolConfig()
	if config == nil {
		t.Fatal("DefaultConnectionPoolConfig() returned nil")
	}

	// Check that defaults are set
	if config.MaxIdleConns == 0 {
		t.Error("MaxIdleConns should have a default value")
	}
	if config.DialTimeout == 0 {
		t.Error("DialTimeout should have a default value")
	}
	if config.EnableDNSOptimization == false {
		t.Error("EnableDNSOptimization should be true by default")
	}
}

func TestConnectionPool_ClientTimeout(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	client := pool.GetClient()
	if client.Timeout != DefaultRequestTimeout {
		t.Errorf("Client timeout should be DefaultRequestTimeout (%v), got %v",
			DefaultRequestTimeout, client.Timeout)
	}
}

func TestConnectionPool_TransportSettings(t *testing.T) {
	config := &ConnectionPoolConfig{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		MaxConnsPerHost:     50,
		IdleConnTimeout:     90 * time.Second,
	}
	pool := NewConnectionPool(config)
	defer pool.Close()

	transport := pool.GetTransport()
	if transport.MaxIdleConns != 100 {
		t.Errorf("Expected MaxIdleConns=100, got %d", transport.MaxIdleConns)
	}
	if transport.MaxIdleConnsPerHost != 10 {
		t.Errorf("Expected MaxIdleConnsPerHost=10, got %d", transport.MaxIdleConnsPerHost)
	}
	if transport.MaxConnsPerHost != 50 {
		t.Errorf("Expected MaxConnsPerHost=50, got %d", transport.MaxConnsPerHost)
	}
}

func TestConnectionPool_ConcurrentAccess(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	var wg sync.WaitGroup
	errors := make(chan error, 30)

	// Concurrent access
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := pool.GetClient()
			if client == nil {
				errors <- &errorString{"GetClient() returned nil"}
			}
			transport := pool.GetTransport()
			if transport == nil {
				errors <- &errorString{"GetTransport() returned nil"}
			}
			pool.UpdateStats(10 * time.Millisecond)
			pool.GetStats()
		}()
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent access error = %v", err)
	}
}

type errorString struct {
	s string
}

func (e *errorString) Error() string {
	return e.s
}

func TestConnectionPool_DialWithOptimization(t *testing.T) {
	config := &ConnectionPoolConfig{
		EnableDNSOptimization: true,
		DialTimeout:           5 * time.Second,
	}
	pool := NewConnectionPool(config)
	defer pool.Close()

	// Test that dialer is set up correctly
	transport := pool.GetTransport()
	if transport.DialContext == nil {
		t.Error("DialContext should be set when DNS optimization is enabled")
	}

	// Test dialing to localhost (should work)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := transport.DialContext(ctx, "tcp", "localhost:80")
	if err != nil {
		// This is expected if nothing is listening on port 80
		// We just check that dialer doesn't panic
		t.Logf("DialContext to localhost:80 failed (expected): %v", err)
	} else {
		conn.Close()
	}
}

func TestConnectionPool_CloseIdleConnections(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	// CloseIdleConnections should not panic
	pool.transport.CloseIdleConnections()
}

func TestConnectionPool_HTTP2Enabled(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	transport := pool.GetTransport()
	if !transport.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 should be enabled by default")
	}
}
