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

// TestConflicts_RequestTimeoutVsResolveEnv checks timeout conflict
// ResolveEnvAndWildcards uses 5 minutes, network timeouts should be less
func TestConflicts_RequestTimeoutVsResolveEnv(t *testing.T) {
	config := DefaultManagerConfig()

	// ResolveEnvAndWildcards timeout from pkg/util/command_util.go
	resolveTimeout := 5 * time.Minute

	// Network RequestTimeout should be less to avoid blocking file operations
	// If network operation takes longer, it may block ResolveEnvAndWildcards
	if config.RequestTimeout >= resolveTimeout {
		t.Errorf("CRITICAL: RequestTimeout (%v) >= ResolveEnvAndWildcards timeout (%v). "+
			"This can cause hangs when network operations block file operations!",
			config.RequestTimeout, resolveTimeout)
	}

	// DialTimeout and ResponseTimeout should also be reasonable
	if DefaultDialTimeout >= resolveTimeout {
		t.Errorf("DialTimeout (%v) >= ResolveEnvAndWildcards timeout (%v)",
			DefaultDialTimeout, resolveTimeout)
	}

	if DefaultResponseTimeout >= resolveTimeout {
		t.Errorf("ResponseTimeout (%v) >= ResolveEnvAndWildcards timeout (%v)",
			DefaultResponseTimeout, resolveTimeout)
	}
}

// TestConflicts_ConcurrencyVsFileOps checks concurrency conflict
// High network operation concurrency may conflict with file operations
func TestConflicts_ConcurrencyVsFileOps(t *testing.T) {
	config := DefaultManagerConfig()

	// MaxConcurrency in network should not be too high
	// Otherwise it may conflict with file operations in ResolveEnvAndWildcards
	if config.MaxConcurrency > 10 {
		t.Errorf("WARNING: MaxConcurrency (%d) may be too high and conflict with file operations. "+
			"Consider reducing to <= 10 for better stability.",
			config.MaxConcurrency)
	}

	// Connection pool limits should also be reasonable
	totalPossibleConns := config.MaxConnsPerHost * config.MaxConcurrency
	if totalPossibleConns > 500 {
		t.Errorf("WARNING: Total possible connections (%d = MaxConnsPerHost * MaxConcurrency) "+
			"may be too high and cause resource exhaustion",
			totalPossibleConns)
	}
}

// TestConflicts_CacheCleanupVsOperations checks cleanup operation conflicts
func TestConflicts_CacheCleanupVsOperations(t *testing.T) {
	// Cleanup interval should not be too frequent to avoid interfering with operations
	if DefaultCleanupInterval < 1*time.Minute {
		t.Errorf("CleanupInterval (%v) is too frequent, may interfere with operations",
			DefaultCleanupInterval)
	}

	// But not too infrequent to avoid accumulating garbage
	if DefaultCleanupInterval > 30*time.Minute {
		t.Errorf("CleanupInterval (%v) is too infrequent, may cause memory leaks",
			DefaultCleanupInterval)
	}
}

// TestConflicts_DefaultVsBuildConfig checks default value mismatch
// between network/constants.go and build.go
func TestConflicts_DefaultVsBuildConfig(t *testing.T) {
	config := DefaultManagerConfig()

	// build.go uses different values:
	// MaxConcurrency = 15 (in network defaultMaxConcurrency = 5)
	// RequestTimeoutMin = 5 minutes (in network DefaultRequestTimeout = 60 seconds)

	// This may cause problems if DefaultManagerConfig is used directly
	// instead of configuration from build.go

	// Check that default values are reasonable
	// defaultMaxConcurrency = 5 (from constants.go)
	expectedMaxConcurrency := 5
	if config.MaxConcurrency != expectedMaxConcurrency {
		t.Errorf("MaxConcurrency (%d) should match expected default (%d)",
			config.MaxConcurrency, expectedMaxConcurrency)
	}

	// RequestTimeout in DefaultManagerConfig uses DefaultResponseTimeout (30s)
	// but should use DefaultRequestTimeout (60s) for consistency
	if config.RequestTimeout != DefaultRequestTimeout {
		t.Errorf("WARNING: RequestTimeout (%v) != DefaultRequestTimeout (%v). "+
			"This inconsistency may cause issues! RequestTimeout uses DefaultResponseTimeout instead.",
			config.RequestTimeout, DefaultRequestTimeout)
	}
}

// TestConflicts_RetryVsTimeout checks that retry doesn't exceed timeouts
func TestConflicts_RetryVsTimeout(t *testing.T) {
	config := DefaultManagerConfig()

	// Maximum retry time should not exceed RequestTimeout
	maxRetryTime := time.Duration(config.RetryAttempts) * config.RetryDelay
	if maxRetryTime > config.RequestTimeout {
		t.Errorf("WARNING: Max retry time (%v = RetryAttempts * RetryDelay) > RequestTimeout (%v). "+
			"This can cause operations to exceed timeout!",
			maxRetryTime, config.RequestTimeout)
	}

	// With margin: retry should complete before 80% of timeout
	maxRetryTimeWithMargin := maxRetryTime * 120 / 100
	if maxRetryTimeWithMargin > config.RequestTimeout*80/100 {
		t.Errorf("WARNING: Max retry time with margin (%v) > 80%% of RequestTimeout (%v). "+
			"Consider reducing retry attempts or delay.",
			maxRetryTimeWithMargin, config.RequestTimeout*80/100)
	}
}
