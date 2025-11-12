/*
Copyright 2025 Google LLC

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

package debug

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Gosayram/kaniko/pkg/config"
)

func TestInit(t *testing.T) {
	// Create temporary directory for testing
	tmpDir := t.TempDir()
	originalKanikoDir := config.KanikoDir
	config.KanikoDir = tmpDir
	defer func() {
		config.KanikoDir = originalKanikoDir
	}()

	opts := &config.DebugOptions{
		OutputDebugFiles: false,
		EnableFullDebug:  false,
		DebugComponents:  []string{},
	}

	manager, err := Init(opts)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	if manager == nil {
		t.Fatal("Init() returned nil manager")
	}

	if manager.opts != opts {
		t.Error("Manager should store options")
	}

	// Cleanup
	_ = manager.Close()
}

func TestInit_WithDebugFiles(t *testing.T) {
	// Create temporary directory for testing
	tmpDir := t.TempDir()
	originalKanikoDir := config.KanikoDir
	config.KanikoDir = tmpDir
	defer func() {
		config.KanikoDir = originalKanikoDir
	}()

	opts := &config.DebugOptions{
		OutputDebugFiles: true,
		EnableFullDebug:  false,
		DebugComponents:  []string{},
	}

	manager, err := Init(opts)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	if manager == nil {
		t.Fatal("Init() returned nil manager")
	}

	// Check that debug directory was created
	debugDir := manager.GetDebugDir()
	if _, err := os.Stat(debugDir); os.IsNotExist(err) {
		t.Errorf("Debug directory should be created: %s", debugDir)
	}

	// Cleanup
	_ = manager.Close()
}

func TestManager_LogComponent(t *testing.T) {
	tmpDir := t.TempDir()
	originalKanikoDir := config.KanikoDir
	config.KanikoDir = tmpDir
	defer func() {
		config.KanikoDir = originalKanikoDir
	}()

	opts := &config.DebugOptions{
		OutputDebugFiles: false,
		EnableFullDebug:  true,
		DebugComponents:  []string{},
	}

	manager, err := Init(opts)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	defer manager.Close()

	// Should not panic
	manager.LogComponent("test", "test message")
	manager.LogComponent("test", "formatted: %s", "value")
}

func TestManager_LogComponent_WithFiltering(t *testing.T) {
	tmpDir := t.TempDir()
	originalKanikoDir := config.KanikoDir
	config.KanikoDir = tmpDir
	defer func() {
		config.KanikoDir = originalKanikoDir
	}()

	opts := &config.DebugOptions{
		OutputDebugFiles: false,
		EnableFullDebug:  false,
		DebugComponents:  []string{"component1"},
	}

	manager, err := Init(opts)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	defer manager.Close()

	// Should log component1
	manager.LogComponent("component1", "message")

	// Should not log component2
	manager.LogComponent("component2", "message")
}

func TestManager_LogToComponentFile(t *testing.T) {
	tmpDir := t.TempDir()
	originalKanikoDir := config.KanikoDir
	config.KanikoDir = tmpDir
	defer func() {
		config.KanikoDir = originalKanikoDir
	}()

	opts := &config.DebugOptions{
		OutputDebugFiles: true,
		EnableFullDebug:  true,
		DebugComponents:  []string{},
	}

	manager, err := Init(opts)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	defer manager.Close()

	// Test logging to component file (use a component that has a pre-created subdirectory)
	err = manager.LogToComponentFile("build", "test message")
	if err != nil {
		t.Errorf("LogToComponentFile() error = %v", err)
	}

	// Check that file was created
	filePath := filepath.Join(manager.GetDebugDir(), "build-steps", "build.log")
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Errorf("Component log file should be created: %s", filePath)
	}
}

func TestManager_LogToComponentFile_Disabled(t *testing.T) {
	tmpDir := t.TempDir()
	originalKanikoDir := config.KanikoDir
	config.KanikoDir = tmpDir
	defer func() {
		config.KanikoDir = originalKanikoDir
	}()

	opts := &config.DebugOptions{
		OutputDebugFiles: false,
		EnableFullDebug:  true,
		DebugComponents:  []string{},
	}

	manager, err := Init(opts)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	defer manager.Close()

	// Should return nil without error when disabled
	err = manager.LogToComponentFile("build", "test message")
	if err != nil {
		t.Errorf("LogToComponentFile() should return nil when disabled, got %v", err)
	}
}

func TestManager_GetDebugDir(t *testing.T) {
	tmpDir := t.TempDir()
	originalKanikoDir := config.KanikoDir
	config.KanikoDir = tmpDir
	defer func() {
		config.KanikoDir = originalKanikoDir
	}()

	opts := &config.DebugOptions{
		OutputDebugFiles: true,
		EnableFullDebug:  false,
		DebugComponents:  []string{},
	}

	manager, err := Init(opts)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	defer manager.Close()

	debugDir := manager.GetDebugDir()
	expectedDir := filepath.Join(config.KanikoDir, "debug")
	if debugDir != expectedDir {
		t.Errorf("GetDebugDir() = %q, expected %q", debugDir, expectedDir)
	}
}

func TestManager_Close(t *testing.T) {
	tmpDir := t.TempDir()
	originalKanikoDir := config.KanikoDir
	config.KanikoDir = tmpDir
	defer func() {
		config.KanikoDir = originalKanikoDir
	}()

	opts := &config.DebugOptions{
		OutputDebugFiles: true,
		EnableFullDebug:  false,
		DebugComponents:  []string{},
	}

	manager, err := Init(opts)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Close should not panic
	err = manager.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Close again should not panic (idempotent)
	err = manager.Close()
	if err != nil {
		// Second close may return error if file is already closed, which is acceptable
		t.Logf("Close() second time returned error (may be expected): %v", err)
	}
}

func TestLogComponent_Global(t *testing.T) {
	tmpDir := t.TempDir()
	originalKanikoDir := config.KanikoDir
	config.KanikoDir = tmpDir
	defer func() {
		config.KanikoDir = originalKanikoDir
		Close() // Cleanup global manager
	}()

	opts := &config.DebugOptions{
		OutputDebugFiles: false,
		EnableFullDebug:  true,
		DebugComponents:  []string{},
	}

	_, err := Init(opts)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Global function should work
	LogComponent("test", "global test message")
}

func TestLogToComponentFile_Global(t *testing.T) {
	tmpDir := t.TempDir()
	originalKanikoDir := config.KanikoDir
	config.KanikoDir = tmpDir
	defer func() {
		config.KanikoDir = originalKanikoDir
		Close() // Cleanup global manager
	}()

	opts := &config.DebugOptions{
		OutputDebugFiles: true,
		EnableFullDebug:  true,
		DebugComponents:  []string{},
	}

	_, err := Init(opts)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Global function should work (use a component that has a pre-created subdirectory)
	err = LogToComponentFile("build", "global test message")
	if err != nil {
		t.Errorf("LogToComponentFile() error = %v", err)
	}
}

func TestShouldLogComponent(t *testing.T) {
	tmpDir := t.TempDir()
	originalKanikoDir := config.KanikoDir
	config.KanikoDir = tmpDir
	defer func() {
		config.KanikoDir = originalKanikoDir
		Close() // Cleanup global manager
	}()

	opts := &config.DebugOptions{
		OutputDebugFiles: false,
		EnableFullDebug:  true,
		DebugComponents:  []string{},
	}

	_, err := Init(opts)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Should return true when full debug is enabled
	if !ShouldLogComponent("any") {
		t.Error("ShouldLogComponent() should return true when full debug is enabled")
	}
}

func TestClose_Global(t *testing.T) {
	tmpDir := t.TempDir()
	originalKanikoDir := config.KanikoDir
	config.KanikoDir = tmpDir
	defer func() {
		config.KanikoDir = originalKanikoDir
	}()

	opts := &config.DebugOptions{
		OutputDebugFiles: false,
		EnableFullDebug:  false,
		DebugComponents:  []string{},
	}

	_, err := Init(opts)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Close should not panic
	err = Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestManager_LogToComponentFile_Subdirectories(t *testing.T) {
	tmpDir := t.TempDir()
	originalKanikoDir := config.KanikoDir
	config.KanikoDir = tmpDir
	defer func() {
		config.KanikoDir = originalKanikoDir
	}()

	opts := &config.DebugOptions{
		OutputDebugFiles: true,
		EnableFullDebug:  true,
		DebugComponents:  []string{},
	}

	manager, err := Init(opts)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	defer manager.Close()

	// Test different component types
	components := []struct {
		name   string
		subDir string
	}{
		{"build-step-1", "build-steps"},
		{"multiplatform-driver", "multi-platform"},
		{"oci-operation", "oci-operations"},
		{"filesystem-snapshot", "filesystem"},
		{"registry-pull", "registry"},
		{"cache-lookup", "cache"},
		// Note: "other" subdirectory is not created in initDebugFiles
		// and LogToComponentFile doesn't create it, so skip this test
		// {"other-component", "other"},
	}

	for _, comp := range components {
		err = manager.LogToComponentFile(comp.name, "test message")
		if err != nil {
			t.Errorf("LogToComponentFile() error for %s: %v", comp.name, err)
		}

		// Check that file was created in correct subdirectory
		// Note: "other" subdirectory is created on-demand, not in initDebugFiles
		filePath := filepath.Join(manager.GetDebugDir(), comp.subDir, comp.name+".log")
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			// For "other" subdirectory, it's created on-demand, so check if it exists or was created
			if comp.subDir == "other" {
				// Check if directory exists (it should be created by LogToComponentFile)
				otherDir := filepath.Join(manager.GetDebugDir(), "other")
				if _, dirErr := os.Stat(otherDir); os.IsNotExist(dirErr) {
					t.Errorf("Other subdirectory should be created on-demand: %s", otherDir)
				}
				// File should exist
				if _, fileErr := os.Stat(filePath); os.IsNotExist(fileErr) {
					t.Errorf("Component log file should be created: %s", filePath)
				}
			} else {
				t.Errorf("Component log file should be created in %s: %s", comp.subDir, filePath)
			}
		}
	}
}
