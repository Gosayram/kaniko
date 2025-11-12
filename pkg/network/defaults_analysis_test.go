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
	"testing"
	"time"
)

// TestDefaultValues_Consistency checks consistency of default values
func TestDefaultValues_Consistency(t *testing.T) {
	config := DefaultManagerConfig()

	// Check that timeouts don't conflict
	if config.RequestTimeout <= 0 {
		t.Error("RequestTimeout should be positive")
	}

	// RequestTimeout should be greater than ResponseTimeout
	if config.RequestTimeout < DefaultResponseTimeout {
		t.Errorf("RequestTimeout (%v) should be >= ResponseTimeout (%v)",
			config.RequestTimeout, DefaultResponseTimeout)
	}

	// Check concurrency
	if config.MaxConcurrency <= 0 {
		t.Error("MaxConcurrency should be positive")
	}
	if config.MaxConcurrency > 100 {
		t.Errorf("MaxConcurrency (%d) seems too high, may cause resource exhaustion",
			config.MaxConcurrency)
	}
}

// TestDefaultValues_TimeoutConflicts checks timeout conflicts with other operations
func TestDefaultValues_TimeoutConflicts(t *testing.T) {
	config := DefaultManagerConfig()

	// ResolveEnvAndWildcards uses 5 minute timeout
	resolveTimeout := 5 * time.Minute

	// Network timeouts should be less to avoid blocking file operations
	if config.RequestTimeout > resolveTimeout {
		t.Errorf("RequestTimeout (%v) should be less than ResolveEnvAndWildcards timeout (%v) to avoid blocking",
			config.RequestTimeout, resolveTimeout)
	}

	// DialTimeout should be reasonable
	if DefaultDialTimeout > 1*time.Minute {
		t.Errorf("DialTimeout (%v) seems too high, may cause hangs",
			DefaultDialTimeout)
	}
}

// TestDefaultValues_ConcurrencyConflicts checks concurrency conflicts
func TestDefaultValues_ConcurrencyConflicts(t *testing.T) {
	config := DefaultManagerConfig()

	// Check that MaxConcurrency is not too high
	// High concurrency may conflict with file operations
	if config.MaxConcurrency > 20 {
		t.Errorf("MaxConcurrency (%d) may be too high and conflict with file operations",
			config.MaxConcurrency)
	}

	// Check connection pool limits
	if config.MaxIdleConnsPerHost > config.MaxIdleConns {
		t.Errorf("MaxIdleConnsPerHost (%d) should be <= MaxIdleConns (%d)",
			config.MaxIdleConnsPerHost, config.MaxIdleConns)
	}

	if config.MaxConnsPerHost > config.MaxIdleConns*5 {
		t.Errorf("MaxConnsPerHost (%d) seems too high compared to MaxIdleConns (%d)",
			config.MaxConnsPerHost, config.MaxIdleConns)
	}
}

// TestDefaultValues_CacheTimeouts checks cache timeouts
func TestDefaultValues_CacheTimeouts(t *testing.T) {
	config := DefaultManagerConfig()

	// DNS cache timeout should be reasonable
	if config.DNSCacheTimeout > 30*time.Minute {
		t.Errorf("DNSCacheTimeout (%v) seems too high, may cause stale DNS entries",
			config.DNSCacheTimeout)
	}

	// Manifest cache timeout should be reasonable
	if config.ManifestCacheTimeout > 1*time.Hour {
		t.Errorf("ManifestCacheTimeout (%v) seems too high, may cause stale manifests",
			config.ManifestCacheTimeout)
	}

	// Cleanup interval should be less than cache timeouts (or equal, but not ideal)
	if DefaultCleanupInterval > config.DNSCacheTimeout {
		t.Errorf("CleanupInterval (%v) should be <= DNSCacheTimeout (%v) to ensure cleanup happens",
			DefaultCleanupInterval, config.DNSCacheTimeout)
	}
}

// TestDefaultValues_ResourceLimits checks resource limits
func TestDefaultValues_ResourceLimits(t *testing.T) {
	config := DefaultManagerConfig()

	// Check that limits are not too high
	if config.MaxIdleConns > 1000 {
		t.Errorf("MaxIdleConns (%d) seems too high, may cause memory issues",
			config.MaxIdleConns)
	}

	if config.MaxIdleConnsPerHost > 100 {
		t.Errorf("MaxIdleConnsPerHost (%d) seems too high, may cause connection exhaustion",
			config.MaxIdleConnsPerHost)
	}

	if config.MaxConnsPerHost > 200 {
		t.Errorf("MaxConnsPerHost (%d) seems too high, may cause connection exhaustion",
			config.MaxConnsPerHost)
	}
}

// TestDefaultValues_RetrySettings checks retry settings
func TestDefaultValues_RetrySettings(t *testing.T) {
	config := DefaultManagerConfig()

	// RetryAttempts should be reasonable
	if config.RetryAttempts < 1 {
		t.Error("RetryAttempts should be at least 1")
	}
	if config.RetryAttempts > 10 {
		t.Errorf("RetryAttempts (%d) seems too high, may cause excessive delays",
			config.RetryAttempts)
	}

	// RetryDelay should be reasonable
	if config.RetryDelay < 100*time.Millisecond {
		t.Errorf("RetryDelay (%v) seems too short, may cause thundering herd",
			config.RetryDelay)
	}
	if config.RetryDelay > 30*time.Second {
		t.Errorf("RetryDelay (%v) seems too long, may cause excessive delays",
			config.RetryDelay)
	}
}
