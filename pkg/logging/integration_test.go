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

package logging

import (
	"errors"
	"testing"
	"time"
)

func TestIntegrationManager_NewIntegrationManager(t *testing.T) {
	im := NewIntegrationManager()
	if im == nil {
		t.Fatal("NewIntegrationManager() returned nil")
	}
	if !im.enabled {
		t.Error("NewIntegrationManager() enabled should be true by default")
	}
}

func TestIntegrationManager_EnableDisableStructuredLogging(t *testing.T) {
	im := NewIntegrationManager()

	// Should be enabled by default
	if !im.enabled {
		t.Error("Structured logging should be enabled by default")
	}

	// Disable
	im.DisableStructuredLogging()
	if im.enabled {
		t.Error("Structured logging should be disabled after DisableStructuredLogging()")
	}

	// Enable again
	im.EnableStructuredLogging()
	if !im.enabled {
		t.Error("Structured logging should be enabled after EnableStructuredLogging()")
	}
}

func TestIntegrationManager_LogBuildStart(t *testing.T) {
	im := NewIntegrationManager()

	// Test with enabled logging
	im.LogBuildStart("build-123", "/path/to/Dockerfile", 3)

	// Test with disabled logging
	im.DisableStructuredLogging()
	im.LogBuildStart("build-456", "/path/to/Dockerfile", 5)
}

func TestIntegrationManager_LogBuildComplete(t *testing.T) {
	im := NewIntegrationManager()

	// Test successful build
	im.LogBuildComplete("build-123", 5*time.Second, true)

	// Test failed build
	im.LogBuildComplete("build-456", 10*time.Second, false)

	// Test with disabled logging
	im.DisableStructuredLogging()
	im.LogBuildComplete("build-789", 2*time.Second, true)
}

func TestIntegrationManager_LogStageStart(t *testing.T) {
	im := NewIntegrationManager()

	im.LogStageStart(0, "stage-1", "base-image:latest")
	im.LogStageStart(1, "stage-2", "stage-1")

	im.DisableStructuredLogging()
	im.LogStageStart(2, "stage-3", "stage-2")
}

func TestIntegrationManager_LogStageComplete(t *testing.T) {
	im := NewIntegrationManager()

	// Test successful stage
	im.LogStageComplete(0, "stage-1", 1*time.Second, true)

	// Test failed stage
	im.LogStageComplete(1, "stage-2", 2*time.Second, false)

	im.DisableStructuredLogging()
	im.LogStageComplete(2, "stage-3", 500*time.Millisecond, true)
}

func TestIntegrationManager_LogCommandStart(t *testing.T) {
	im := NewIntegrationManager()

	im.LogCommandStart(0, "RUN apt-get update", "stage-1")
	im.LogCommandStart(1, "COPY file.txt /app/", "stage-1")

	im.DisableStructuredLogging()
	im.LogCommandStart(2, "ENV VAR=value", "stage-2")
}

func TestIntegrationManager_LogCommandComplete(t *testing.T) {
	im := NewIntegrationManager()

	// Test successful command
	im.LogCommandComplete(0, "RUN apt-get update", 100*time.Millisecond, true)

	// Test failed command
	im.LogCommandComplete(1, "COPY file.txt /app/", 200*time.Millisecond, false)

	im.DisableStructuredLogging()
	im.LogCommandComplete(2, "ENV VAR=value", 50*time.Millisecond, true)
}

func TestIntegrationManager_LogCacheOperation(t *testing.T) {
	im := NewIntegrationManager()

	im.LogCacheOperation("get", "cache-key-123", true, 10*time.Millisecond)
	im.LogCacheOperation("set", "cache-key-456", false, 20*time.Millisecond)

	im.DisableStructuredLogging()
	im.LogCacheOperation("check", "cache-key-789", true, 5*time.Millisecond)
}

func TestIntegrationManager_LogNetworkOperation(t *testing.T) {
	im := NewIntegrationManager()

	// Test successful operation
	im.LogNetworkOperation("GET", "https://registry.example.com/v2/", 200, 100*time.Millisecond, true)

	// Test failed operation
	im.LogNetworkOperation("POST", "https://registry.example.com/v2/", 401, 50*time.Millisecond, false)

	im.DisableStructuredLogging()
	im.LogNetworkOperation("PUT", "https://registry.example.com/v2/", 201, 200*time.Millisecond, true)
}

func TestIntegrationManager_LogSnapshotOperation(t *testing.T) {
	im := NewIntegrationManager()

	// Test successful operation
	im.LogSnapshotOperation("take", 100, 500*time.Millisecond, true)

	// Test failed operation
	im.LogSnapshotOperation("restore", 50, 250*time.Millisecond, false)

	im.DisableStructuredLogging()
	im.LogSnapshotOperation("cleanup", 0, 10*time.Millisecond, true)
}

func TestIntegrationManager_LogError(t *testing.T) {
	im := NewIntegrationManager()

	testErr := errors.New("test error")
	im.LogError("component", "operation", testErr, map[string]interface{}{
		"key1": "value1",
		"key2": 42,
	})

	im.DisableStructuredLogging()
	im.LogError("component2", "operation2", testErr, nil)
}

func TestIntegrationManager_LogPerformance(t *testing.T) {
	im := NewIntegrationManager()

	im.LogPerformance("component", "metric", 123.45, "ms")
	im.LogPerformance("component", "throughput", 1000.0, "ops/s")

	im.DisableStructuredLogging()
	im.LogPerformance("network", "latency", 50.5, "ms")
}

func TestIntegrationManager_LogStatistics(t *testing.T) {
	im := NewIntegrationManager()

	// Should not panic
	im.LogStatistics()

	im.DisableStructuredLogging()
	im.LogStatistics()
}

func TestIntegrationManager_Close(t *testing.T) {
	im := NewIntegrationManager()

	// Should not panic
	im.Close()

	// Close again (should not panic)
	im.Close()
}

func TestIntegrationManager_GetStructuredLogger(t *testing.T) {
	im := NewIntegrationManager()

	logger := im.GetStructuredLogger()
	if logger == nil {
		t.Fatal("GetStructuredLogger() returned nil")
	}
}

func TestIntegrationManager_GetEnhancedLogger(t *testing.T) {
	im := NewIntegrationManager()

	logger := im.GetEnhancedLogger()
	if logger == nil {
		t.Fatal("GetEnhancedLogger() returned nil")
	}
}
