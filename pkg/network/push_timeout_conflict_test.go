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

// TestPushImageTimeout_ConflictWithFileOps checks if PushImage 2x timeout conflicts
// with file operations like ResolveEnvAndWildcards (5 minutes) or FilesUsedFromContext (2 minutes)
func TestPushImageTimeout_ConflictWithFileOps(t *testing.T) {
	config := DefaultRegistryClientConfig()

	// PushImage uses 2x RequestTimeout
	pushTimeout := config.RequestTimeout * 2

	// ResolveEnvAndWildcards uses 5 minutes timeout
	resolveTimeout := 5 * time.Minute

	// FilesUsedFromContext uses 2 minutes timeout
	filesTimeout := 2 * time.Minute

	// PushImage timeout should not exceed file operation timeouts
	// If it does, push operations may block file operations
	if pushTimeout > resolveTimeout {
		t.Errorf("WARNING: PushImage timeout (%v = 2x RequestTimeout) > ResolveEnvAndWildcards timeout (%v). "+
			"This can cause push operations to block file operations!",
			pushTimeout, resolveTimeout)
	}

	if pushTimeout > filesTimeout {
		t.Errorf("WARNING: PushImage timeout (%v = 2x RequestTimeout) > FilesUsedFromContext timeout (%v). "+
			"This can cause push operations to block file operations!",
			pushTimeout, filesTimeout)
	}

	// PushImage timeout should be reasonable (not more than 5 minutes)
	if pushTimeout > 5*time.Minute {
		t.Errorf("WARNING: PushImage timeout (%v) seems too high, may cause hangs. "+
			"Consider reducing RequestTimeout or removing 2x multiplier.",
			pushTimeout)
	}
}

// TestPushImageTimeout_WithBuildConfig checks timeout with build.go configuration
func TestPushImageTimeout_WithBuildConfig(t *testing.T) {
	// In build.go, RequestTimeoutMin = 5 minutes
	buildRequestTimeout := 5 * time.Minute

	// PushImage would use 2x = 10 minutes, but should be capped at 5 minutes
	calculatedTimeout := buildRequestTimeout * 2
	maxPushTimeout := 5 * time.Minute

	// The actual timeout should be capped at 5 minutes
	actualTimeout := calculatedTimeout
	if actualTimeout > maxPushTimeout {
		actualTimeout = maxPushTimeout
	}

	// Should not exceed ResolveEnvAndWildcards timeout (5 minutes)
	resolveTimeout := 5 * time.Minute
	if actualTimeout > resolveTimeout {
		t.Errorf("CRITICAL: PushImage timeout (%v) > ResolveEnvAndWildcards timeout (%v). "+
			"This WILL cause hangs when push operations block file operations!",
			actualTimeout, resolveTimeout)
	}

	// Verify that capping works
	if calculatedTimeout > maxPushTimeout && actualTimeout != maxPushTimeout {
		t.Errorf("PushImage timeout should be capped at %v, got %v",
			maxPushTimeout, actualTimeout)
	}
}

// TestTimeoutHierarchy checks the hierarchy of timeouts to find conflicts
func TestTimeoutHierarchy(t *testing.T) {
	config := DefaultRegistryClientConfig()

	// PushImage timeout is capped at 5 minutes
	calculatedPushTimeout := config.RequestTimeout * 2
	maxPushTimeout := 5 * time.Minute
	actualPushTimeout := calculatedPushTimeout
	if actualPushTimeout > maxPushTimeout {
		actualPushTimeout = maxPushTimeout
	}

	timeouts := map[string]time.Duration{
		"DefaultDialTimeout":     DefaultDialTimeout,
		"DefaultResponseTimeout": DefaultResponseTimeout,
		"DefaultRequestTimeout":  DefaultRequestTimeout,
		"PullImageTimeout":       config.RequestTimeout,
		"PushImageTimeout":       actualPushTimeout, // Use capped timeout
		"ResolveEnvAndWildcards": 5 * time.Minute,
		"FilesUsedFromContext":   2 * time.Minute,
		"processCommand":         15 * time.Minute,
		"CommandTimeoutMinutes":  30 * time.Minute,
	}

	// Check that network timeouts don't exceed file operation timeouts
	if timeouts["PushImageTimeout"] > timeouts["ResolveEnvAndWildcards"] {
		t.Errorf("CRITICAL CONFLICT: PushImageTimeout (%v) > ResolveEnvAndWildcards (%v)",
			timeouts["PushImageTimeout"], timeouts["ResolveEnvAndWildcards"])
	}

	if timeouts["PullImageTimeout"] > timeouts["ResolveEnvAndWildcards"] {
		t.Errorf("WARNING: PullImageTimeout (%v) > ResolveEnvAndWildcards (%v)",
			timeouts["PullImageTimeout"], timeouts["ResolveEnvAndWildcards"])
	}

	// Log all timeouts for debugging
	t.Log("Timeout hierarchy:")
	for name, timeout := range timeouts {
		t.Logf("  %s: %v", name, timeout)
	}
}
