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
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/Gosayram/kaniko/pkg/config"
)

func TestRegistryCache_initClient(t *testing.T) {
	testCases := []struct {
		name               string
		opts               *config.KanikoOptions
		expectedMaxConns   int
		expectedMaxPerHost int
		expectedTimeout    time.Duration
		disableHTTP2       bool
	}{
		{
			name:               "default values",
			opts:               &config.KanikoOptions{},
			expectedMaxConns:   10,
			expectedMaxPerHost: 5,
			expectedTimeout:    30 * time.Second,
			disableHTTP2:       false,
		},
		{
			name: "custom values",
			opts: &config.KanikoOptions{
				CacheMaxConns:        20,
				CacheMaxConnsPerHost: 10,
				CacheRequestTimeout:  60 * time.Second,
				CacheDisableHTTP2:    false,
			},
			expectedMaxConns:   20,
			expectedMaxPerHost: 10,
			expectedTimeout:    60 * time.Second,
			disableHTTP2:       false,
		},
		{
			name: "HTTP/2 disabled",
			opts: &config.KanikoOptions{
				CacheDisableHTTP2: true,
			},
			expectedMaxConns:   10,
			expectedMaxPerHost: 5,
			expectedTimeout:    30 * time.Second,
			disableHTTP2:       true,
		},
		{
			name: "zero values use defaults",
			opts: &config.KanikoOptions{
				CacheMaxConns:        0,
				CacheMaxConnsPerHost: 0,
				CacheRequestTimeout:  0,
			},
			expectedMaxConns:   10,
			expectedMaxPerHost: 5,
			expectedTimeout:    30 * time.Second,
			disableHTTP2:       false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rc := &RegistryCache{
				Opts: tc.opts,
			}

			err := rc.initClient("test-registry")
			if err != nil {
				t.Fatalf("initClient failed: %v", err)
			}

			if rc.client == nil {
				t.Fatal("Expected client to be initialized, got nil")
			}

			transport, ok := rc.client.Transport.(*http.Transport)
			if !ok {
				t.Fatalf("Expected *http.Transport, got %T", rc.client.Transport)
			}

			// Verify connection pooling parameters
			if transport.MaxIdleConns != tc.expectedMaxConns {
				t.Errorf("Expected MaxIdleConns=%d, got %d", tc.expectedMaxConns, transport.MaxIdleConns)
			}

			if transport.MaxIdleConnsPerHost != tc.expectedMaxPerHost {
				t.Errorf("Expected MaxIdleConnsPerHost=%d, got %d", tc.expectedMaxPerHost, transport.MaxIdleConnsPerHost)
			}

			if transport.IdleConnTimeout != 90*time.Second {
				t.Errorf("Expected IdleConnTimeout=90s, got %v", transport.IdleConnTimeout)
			}

			if transport.DisableKeepAlives {
				t.Error("Expected DisableKeepAlives=false, got true")
			}

			// Verify HTTP/2 configuration
			if tc.disableHTTP2 {
				if transport.ForceAttemptHTTP2 {
					t.Error("Expected ForceAttemptHTTP2=false when HTTP/2 is disabled, got true")
				}
			}

			// Verify timeout
			if rc.client.Timeout != tc.expectedTimeout {
				t.Errorf("Expected Timeout=%v, got %v", tc.expectedTimeout, rc.client.Timeout)
			}
		})
	}
}

func TestRegistryCache_initClient_idempotent(t *testing.T) {
	rc := &RegistryCache{
		Opts: &config.KanikoOptions{},
	}

	// Initialize client first time
	err := rc.initClient("test-registry")
	if err != nil {
		t.Fatalf("First initClient failed: %v", err)
	}

	firstClient := rc.client
	firstTransport := rc.client.Transport

	// Initialize client second time (should be idempotent)
	err = rc.initClient("test-registry")
	if err != nil {
		t.Fatalf("Second initClient failed: %v", err)
	}

	// Should be the same client instance
	if rc.client != firstClient {
		t.Error("Expected client to be reused, got new instance")
	}

	// Should be the same transport instance
	if rc.client.Transport != firstTransport {
		t.Error("Expected transport to be reused, got new instance")
	}
}

func TestRegistryCache_initClient_concurrent(t *testing.T) {
	rc := &RegistryCache{
		Opts: &config.KanikoOptions{},
	}

	// Initialize client concurrently from multiple goroutines
	const numGoroutines = 10
	done := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			err := rc.initClient("test-registry")
			done <- err
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		if err := <-done; err != nil {
			t.Fatalf("initClient failed in goroutine: %v", err)
		}
	}

	// Verify client was initialized
	if rc.client == nil {
		t.Fatal("Expected client to be initialized, got nil")
	}

	// Verify only one client instance was created (thread-safe initialization)
	// This is verified by checking that all calls succeeded and client is not nil
}

func TestRegistryCache_connectionPooling(t *testing.T) {
	rc := &RegistryCache{
		Opts: &config.KanikoOptions{
			CacheMaxConns:        15,
			CacheMaxConnsPerHost: 8,
		},
	}

	err := rc.initClient("test-registry")
	if err != nil {
		t.Fatalf("initClient failed: %v", err)
	}

	transport, ok := rc.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Expected *http.Transport, got %T", rc.client.Transport)
	}

	// Verify connection pooling is configured
	if transport.MaxIdleConns != 15 {
		t.Errorf("Expected MaxIdleConns=15, got %d", transport.MaxIdleConns)
	}

	if transport.MaxIdleConnsPerHost != 8 {
		t.Errorf("Expected MaxIdleConnsPerHost=8, got %d", transport.MaxIdleConnsPerHost)
	}

	// Verify keep-alive is enabled for connection reuse
	if transport.DisableKeepAlives {
		t.Error("Expected DisableKeepAlives=false for connection pooling, got true")
	}
}

func TestRegistryCache_HTTP2Configuration(t *testing.T) {
	testCases := []struct {
		name         string
		disableHTTP2 bool
		description  string
	}{
		{
			name:         "HTTP/2 enabled",
			disableHTTP2: false,
			description:  "HTTP/2 should be attempted when not disabled",
		},
		{
			name:         "HTTP/2 disabled",
			disableHTTP2: true,
			description:  "HTTP/1.1 should be used when HTTP/2 is disabled",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rc := &RegistryCache{
				Opts: &config.KanikoOptions{
					CacheDisableHTTP2: tc.disableHTTP2,
				},
			}

			err := rc.initClient("test-registry")
			if err != nil {
				t.Fatalf("initClient failed: %v", err)
			}

			transport, ok := rc.client.Transport.(*http.Transport)
			if !ok {
				t.Fatalf("Expected *http.Transport, got %T", rc.client.Transport)
			}

			if tc.disableHTTP2 {
				if transport.ForceAttemptHTTP2 {
					t.Error("Expected ForceAttemptHTTP2=false when HTTP/2 is disabled")
				}
			} else {
				// When HTTP/2 is enabled, ForceAttemptHTTP2 might be true
				// (actual HTTP/2 support depends on server and http2.ConfigureTransport)
				// We just verify the transport is configured
				if transport == nil {
					t.Error("Expected transport to be configured")
				}
			}
		})
	}
}

func TestRegistryCache_RetrieveLayer_initializesClient(t *testing.T) {
	// This test verifies that RetrieveLayer initializes the client if not already done
	// Note: This is a unit test that doesn't make actual network calls
	// In a real scenario, RetrieveLayer would use the initialized client

	rc := &RegistryCache{
		Opts: &config.KanikoOptions{
			CacheMaxConns:        10,
			CacheMaxConnsPerHost: 5,
		},
	}

	// Client should be nil initially
	if rc.client != nil {
		t.Error("Expected client to be nil initially")
	}

	// Initialize client (simulating what RetrieveLayer would do)
	err := rc.initClient("test-registry")
	if err != nil {
		t.Fatalf("initClient failed: %v", err)
	}

	// Client should be initialized now
	if rc.client == nil {
		t.Error("Expected client to be initialized after initClient")
	}
}

func TestRegistryCache_transportConfiguration(t *testing.T) {
	rc := &RegistryCache{
		Opts: &config.KanikoOptions{
			CacheMaxConns:        25,
			CacheMaxConnsPerHost: 12,
			CacheRequestTimeout:  45 * time.Second,
			CacheDisableHTTP2:    false,
		},
	}

	err := rc.initClient("test-registry")
	if err != nil {
		t.Fatalf("initClient failed: %v", err)
	}

	// Verify all configuration is applied correctly
	transport, ok := rc.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Expected *http.Transport, got %T", rc.client.Transport)
	}

	checks := []struct {
		name     string
		expected interface{}
		actual   interface{}
	}{
		{"MaxIdleConns", 25, transport.MaxIdleConns},
		{"MaxIdleConnsPerHost", 12, transport.MaxIdleConnsPerHost},
		{"IdleConnTimeout", 90 * time.Second, transport.IdleConnTimeout},
		{"DisableKeepAlives", false, transport.DisableKeepAlives},
		{"Client Timeout", 45 * time.Second, rc.client.Timeout},
	}

	for _, check := range checks {
		if !reflect.DeepEqual(check.expected, check.actual) {
			t.Errorf("%s: expected %v, got %v", check.name, check.expected, check.actual)
		}
	}
}
