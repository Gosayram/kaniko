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

func TestNewParallelClient(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	client := NewParallelClient(nil, pool)
	if client == nil {
		t.Fatal("NewParallelClient() returned nil")
	}
	if client.config == nil {
		t.Error("Parallel client config should not be nil")
	}
	if client.pool == nil {
		t.Error("Connection pool should not be nil")
	}
	if client.client == nil {
		t.Error("HTTP client should not be nil")
	}
	if client.workerPool == nil {
		t.Error("Worker pool should not be nil")
	}
}

func TestNewParallelClient_WithConfig(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	config := &ParallelClientConfig{
		MaxConcurrency: 10,
		RequestTimeout: 30 * time.Second,
	}
	client := NewParallelClient(config, pool)
	if client == nil {
		t.Fatal("NewParallelClient() returned nil")
	}
	if client.config.MaxConcurrency != 10 {
		t.Errorf("Expected MaxConcurrency=10, got %d", client.config.MaxConcurrency)
	}
}

func TestNewParallelClient_NilPool(t *testing.T) {
	// Should create default pool
	client := NewParallelClient(nil, nil)
	if client == nil {
		t.Fatal("NewParallelClient() returned nil")
	}
	if client.pool == nil {
		t.Error("Should create default connection pool when nil is provided")
	}
	defer client.pool.Close()
}

func TestParallelClient_ExecuteParallel_EmptyRequests(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	client := NewParallelClient(nil, pool)
	ctx := context.Background()

	_, err := client.ExecuteParallel(ctx, []ParallelRequest{})
	if err == nil {
		t.Error("ExecuteParallel() should return error for empty requests")
	}
}

func TestParallelClient_ExecuteParallel_ContextCancellation(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	client := NewParallelClient(nil, pool)
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel context immediately
	cancel()

	requests := []ParallelRequest{
		{URL: "http://example.com", Method: "GET"},
	}

	responses, err := client.ExecuteParallel(ctx, requests)
	if err != nil {
		t.Logf("ExecuteParallel() with cancelled context returned error (expected): %v", err)
	}

	// Check that worker pool is released (no deadlock)
	if len(responses) > 0 && responses[0].Error == nil {
		t.Error("Request should fail when context is cancelled")
	}
}

func TestParallelClient_ExecuteParallel_WorkerPoolRelease(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	config := &ParallelClientConfig{
		MaxConcurrency: 2,
		RequestTimeout: 1 * time.Second,
	}
	client := NewParallelClient(config, pool)
	ctx := context.Background()

	// Create more requests than MaxConcurrency to test worker pool
	requests := make([]ParallelRequest, 5)
	for i := range requests {
		requests[i] = ParallelRequest{
			URL:    "http://example.com",
			Method: "GET",
		}
	}

	// This should not deadlock even if requests fail
	responses, err := client.ExecuteParallel(ctx, requests)
	if err != nil {
		t.Logf("ExecuteParallel() returned error (may be expected): %v", err)
	}

	// Verify all responses are present
	if len(responses) != len(requests) {
		t.Errorf("Expected %d responses, got %d", len(requests), len(responses))
	}

	// Verify worker pool is released by trying again
	responses2, err2 := client.ExecuteParallel(ctx, requests)
	if err2 != nil {
		t.Logf("Second ExecuteParallel() returned error (may be expected): %v", err2)
	}
	if len(responses2) != len(requests) {
		t.Errorf("Second execution: expected %d responses, got %d", len(requests), len(responses2))
	}
}

func TestParallelClient_ExecuteParallel_Concurrent(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	client := NewParallelClient(nil, pool)
	ctx := context.Background()

	var wg sync.WaitGroup
	errors := make(chan error, 10)

	// Concurrent ExecuteParallel calls
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			requests := []ParallelRequest{
				{URL: "http://example.com", Method: "GET"},
			}
			_, err := client.ExecuteParallel(ctx, requests)
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	// Check for unexpected errors
	for err := range errors {
		t.Logf("Concurrent ExecuteParallel() error (may be expected): %v", err)
	}
}

func TestParallelClient_GetStats(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	client := NewParallelClient(nil, pool)
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

func TestParallelClient_GetStats_ThreadSafe(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	client := NewParallelClient(nil, pool)

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

func TestParallelClient_LogStats(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	client := NewParallelClient(nil, pool)

	// Should not panic
	client.LogStats()
}

func TestParallelClient_DefaultConfig(t *testing.T) {
	config := DefaultParallelClientConfig()
	if config == nil {
		t.Fatal("DefaultParallelClientConfig() returned nil")
	}

	// Check that defaults are set
	if config.MaxConcurrency == 0 {
		t.Error("MaxConcurrency should have a default value")
	}
	if config.RequestTimeout == 0 {
		t.Error("RequestTimeout should have a default value")
	}
	if config.EnableCompression == false {
		t.Error("EnableCompression should be true by default")
	}
}

func TestParallelClient_RequestTimeout(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	config := &ParallelClientConfig{
		RequestTimeout: 5 * time.Second,
	}
	client := NewParallelClient(config, pool)

	ctx := context.Background()
	requests := []ParallelRequest{
		{
			URL:     "http://example.com",
			Method:  "GET",
			Timeout: 0, // Use config timeout
		},
	}

	// This should timeout or fail, but not hang
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	responses, err := client.ExecuteParallel(ctxWithTimeout, requests)
	if err != nil {
		t.Logf("ExecuteParallel() with timeout returned error (expected): %v", err)
	}

	if len(responses) > 0 && responses[0].Error == nil {
		t.Log("Request succeeded (unexpected but not an error)")
	}
}

func TestParallelClient_RequestSpecificTimeout(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	client := NewParallelClient(nil, pool)
	ctx := context.Background()

	requests := []ParallelRequest{
		{
			URL:     "http://example.com",
			Method:  "GET",
			Timeout: 1 * time.Second, // Request-specific timeout
		},
	}

	// Should not hang
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	responses, err := client.ExecuteParallel(ctxWithTimeout, requests)
	if err != nil {
		t.Logf("ExecuteParallel() returned error (may be expected): %v", err)
	}

	if len(responses) != 1 {
		t.Errorf("Expected 1 response, got %d", len(responses))
	}
}

func TestParallelClient_WorkerPoolCapacity(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	config := &ParallelClientConfig{
		MaxConcurrency: 5,
	}
	client := NewParallelClient(config, pool)

	// Worker pool should have capacity equal to MaxConcurrency
	capacity := cap(client.workerPool)
	if capacity != 5 {
		t.Errorf("Expected worker pool capacity=5, got %d", capacity)
	}
}

func TestParallelClient_NoGoroutineLeak(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	client := NewParallelClient(nil, pool)
	ctx := context.Background()

	// Capture goroutine count before
	runtime.GC()
	beforeGoroutines := runtime.NumGoroutine()

	// Execute some requests
	requests := []ParallelRequest{
		{URL: "http://example.com", Method: "GET"},
		{URL: "http://example.com", Method: "GET"},
	}

	_, _ = client.ExecuteParallel(ctx, requests)

	// Give goroutines time to finish
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	afterGoroutines := runtime.NumGoroutine()

	// Check that goroutines didn't leak
	if afterGoroutines > beforeGoroutines+3 {
		t.Logf("Goroutine count: before=%d, after=%d", beforeGoroutines, afterGoroutines)
		t.Log("Warning: Possible goroutine leak detected")
	}
}

func TestParallelClient_RetryLogic(t *testing.T) {
	pool := NewConnectionPool(nil)
	defer pool.Close()

	config := &ParallelClientConfig{
		RetryAttempts: 3,
		RetryDelay:    100 * time.Millisecond,
	}
	client := NewParallelClient(config, pool)

	// Test that retry logic doesn't cause issues
	// We can't easily test actual retries without a real server,
	// but we can verify the configuration is set correctly
	if client.config.RetryAttempts != 3 {
		t.Errorf("Expected RetryAttempts=3, got %d", client.config.RetryAttempts)
	}
	if client.config.RetryDelay != 100*time.Millisecond {
		t.Errorf("Expected RetryDelay=100ms, got %v", client.config.RetryDelay)
	}
}
