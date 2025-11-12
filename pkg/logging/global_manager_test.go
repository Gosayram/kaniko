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
)

func TestGlobalManager_GetGlobalManager(t *testing.T) {
	manager1 := GetGlobalManager()
	manager2 := GetGlobalManager()

	if manager1 != manager2 {
		t.Error("GetGlobalManager() should return the same instance (singleton)")
	}
}

func TestGlobalManager_Initialize(t *testing.T) {
	manager := GetGlobalManager()

	// Test initialization
	err := manager.Initialize("info", "kaniko", true)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	if !manager.IsInitialized() {
		t.Error("IsInitialized() should return true after Initialize()")
	}

	// Test double initialization (should not error)
	err = manager.Initialize("debug", "json", false)
	if err != nil {
		t.Errorf("Initialize() on already initialized manager should not error, got %v", err)
	}

	// Cleanup
	manager.Close()
}

func TestGlobalManager_IsInitialized(t *testing.T) {
	manager := GetGlobalManager()

	// Initialize and check
	manager.Initialize("info", "kaniko", false)
	if !manager.IsInitialized() {
		t.Error("IsInitialized() should return true after Initialize()")
	}

	// Close and check
	manager.Close()
	// After Close, initialized should be false
	if manager.IsInitialized() {
		t.Error("IsInitialized() should return false after Close()")
	}
}

func TestGlobalManager_LogBuildStart(t *testing.T) {
	manager := GetGlobalManager()

	// Test without initialization
	manager.LogBuildStart("build-123", "/path/to/Dockerfile", 3)

	// Test with initialization
	manager.Initialize("info", "kaniko", true)
	manager.LogBuildStart("build-456", "/path/to/Dockerfile", 5)

	manager.Close()
}

func TestGlobalManager_LogBuildComplete(t *testing.T) {
	manager := GetGlobalManager()

	// Test without initialization
	manager.LogBuildComplete("build-123", 1000, true)
	manager.LogBuildComplete("build-123", 2000, false)

	// Test with initialization
	manager.Initialize("info", "kaniko", true)
	manager.LogBuildComplete("build-456", 1500, true)

	manager.Close()
}

func TestGlobalManager_LogStageStart(t *testing.T) {
	manager := GetGlobalManager()

	manager.LogStageStart(0, "stage-1", "base-image:latest")
	manager.LogStageStart(1, "stage-2", "stage-1")

	manager.Initialize("info", "kaniko", true)
	manager.LogStageStart(2, "stage-3", "stage-2")

	manager.Close()
}

func TestGlobalManager_LogStageComplete(t *testing.T) {
	manager := GetGlobalManager()

	manager.LogStageComplete(0, "stage-1", 500, true)
	manager.LogStageComplete(1, "stage-2", 750, false)

	manager.Initialize("info", "kaniko", true)
	manager.LogStageComplete(2, "stage-3", 1000, true)

	manager.Close()
}

func TestGlobalManager_LogCommandStart(t *testing.T) {
	manager := GetGlobalManager()

	manager.LogCommandStart(0, "RUN apt-get update", "stage-1")
	manager.LogCommandStart(1, "COPY file.txt /app/", "stage-1")

	manager.Initialize("info", "kaniko", true)
	manager.LogCommandStart(2, "ENV VAR=value", "stage-2")

	manager.Close()
}

func TestGlobalManager_LogCommandComplete(t *testing.T) {
	manager := GetGlobalManager()

	manager.LogCommandComplete(0, "RUN apt-get update", 100, true)
	manager.LogCommandComplete(1, "COPY file.txt /app/", 200, false)

	manager.Initialize("info", "kaniko", true)
	manager.LogCommandComplete(2, "ENV VAR=value", 50, true)

	manager.Close()
}

func TestGlobalManager_LogCacheOperation(t *testing.T) {
	manager := GetGlobalManager()

	manager.LogCacheOperation("get", "cache-key-123", true, 10)
	manager.LogCacheOperation("set", "cache-key-456", false, 20)

	manager.Initialize("info", "kaniko", true)
	manager.LogCacheOperation("check", "cache-key-789", true, 5)

	manager.Close()
}

func TestGlobalManager_LogNetworkOperation(t *testing.T) {
	manager := GetGlobalManager()

	manager.LogNetworkOperation("GET", "https://registry.example.com/v2/", 200, 100, true)
	manager.LogNetworkOperation("POST", "https://registry.example.com/v2/", 401, 50, false)

	manager.Initialize("info", "kaniko", true)
	manager.LogNetworkOperation("PUT", "https://registry.example.com/v2/", 201, 200, true)

	manager.Close()
}

func TestGlobalManager_LogSnapshotOperation(t *testing.T) {
	manager := GetGlobalManager()

	manager.LogSnapshotOperation("take", 100, 500, true)
	manager.LogSnapshotOperation("restore", 50, 250, false)

	manager.Initialize("info", "kaniko", true)
	manager.LogSnapshotOperation("cleanup", 0, 10, true)

	manager.Close()
}

func TestGlobalManager_LogError(t *testing.T) {
	manager := GetGlobalManager()

	testErr := errors.New("test error")
	manager.LogError("component", "operation", testErr, map[string]interface{}{
		"key1": "value1",
		"key2": 42,
	})

	manager.Initialize("info", "kaniko", true)
	manager.LogError("component2", "operation2", testErr, nil)

	manager.Close()
}

func TestGlobalManager_LogPerformance(t *testing.T) {
	manager := GetGlobalManager()

	manager.LogPerformance("component", "metric", 123.45, "ms")
	manager.LogPerformance("component", "throughput", 1000.0, "ops/s")

	manager.Initialize("info", "kaniko", true)
	manager.LogPerformance("network", "latency", 50.5, "ms")

	manager.Close()
}

func TestGlobalManager_LogStatistics(t *testing.T) {
	manager := GetGlobalManager()

	// Without initialization (should not panic)
	manager.LogStatistics()

	// With initialization
	manager.Initialize("info", "kaniko", true)
	manager.LogStatistics()

	manager.Close()
}

func TestGlobalManager_Close(t *testing.T) {
	manager := GetGlobalManager()

	manager.Initialize("info", "kaniko", true)
	if !manager.IsInitialized() {
		t.Error("Manager should be initialized")
	}

	manager.Close()
	if manager.IsInitialized() {
		t.Error("Manager should not be initialized after Close()")
	}

	// Close again (should not panic)
	manager.Close()
}

func TestGlobalManager_GetIntegrationManager(t *testing.T) {
	manager := GetGlobalManager()

	im := manager.GetIntegrationManager()
	if im == nil {
		t.Fatal("GetIntegrationManager() returned nil")
	}

	// Should return the same instance
	im2 := manager.GetIntegrationManager()
	if im != im2 {
		t.Error("GetIntegrationManager() should return the same instance")
	}
}

func TestGlobalManager_GetAsyncLogger(t *testing.T) {
	manager := GetGlobalManager()

	// Close first to ensure clean state
	manager.Close()

	// Before initialization, async logger should be nil
	al := manager.GetAsyncLogger()
	if al != nil {
		t.Error("GetAsyncLogger() should return nil before initialization")
	}

	// After initialization
	manager.Initialize("info", "kaniko", true)
	al = manager.GetAsyncLogger()
	if al == nil {
		t.Error("GetAsyncLogger() should return non-nil after initialization")
	}

	manager.Close()
}
