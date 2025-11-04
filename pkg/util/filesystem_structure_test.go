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

package util

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFilesystemStructureAnalyzer_DetectDirectories(t *testing.T) {
	// Create a temporary directory structure
	tmpDir, err := os.MkdirTemp("", "kaniko-fs-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create some test directories
	testDirs := []string{
		"etc",
		"var",
		"usr/bin",
		"usr/local/bin",
		"tmp",
		"var/cache",
		"var/tmp",
		"lib",
		"usr/lib",
	}

	for _, dir := range testDirs {
		fullPath := filepath.Join(tmpDir, dir)
		if err := os.MkdirAll(fullPath, 0755); err != nil {
			t.Fatalf("Failed to create test dir %s: %v", fullPath, err)
		}
	}

	// Create analyzer
	analyzer := NewFilesystemStructureAnalyzer(tmpDir)
	if err := analyzer.Analyze(); err != nil {
		t.Fatalf("Failed to analyze: %v", err)
	}

	// Check system directories
	systemDirs := analyzer.GetSystemDirectories()
	if len(systemDirs) == 0 {
		t.Error("Expected at least some system directories")
	}

	// Check cache directories
	cacheDirs := analyzer.GetCacheDirectories()
	if len(cacheDirs) == 0 {
		t.Error("Expected at least some cache directories")
	}

	// Check temp directories
	tempDirs := analyzer.GetTempDirectories()
	if len(tempDirs) == 0 {
		t.Error("Expected at least some temp directories")
	}

	// Check bin directories
	binDirs := analyzer.GetBinDirectories()
	if len(binDirs) == 0 {
		t.Error("Expected at least some bin directories")
	}

	// Check lib directories
	libDirs := analyzer.GetLibDirectories()
	if len(libDirs) == 0 {
		t.Error("Expected at least some lib directories")
	}

	// Check IsSystemDirectory
	if !analyzer.IsSystemDirectory("/etc/test") {
		t.Error("Expected /etc/test to be detected as system directory")
	}

	// Check patterns
	patterns := analyzer.GetDirectoryPatterns()
	if len(patterns) == 0 {
		t.Error("Expected at least some patterns")
	}
}

func TestFallbackFilesystemStructure(t *testing.T) {
	fallback := &fallbackFilesystemStructure{}

	// Test all getters return non-empty slices
	if len(fallback.GetSystemDirectories()) == 0 {
		t.Error("Fallback should return system directories")
	}
	if len(fallback.GetCacheDirectories()) == 0 {
		t.Error("Fallback should return cache directories")
	}
	if len(fallback.GetTempDirectories()) == 0 {
		t.Error("Fallback should return temp directories")
	}
	if len(fallback.GetBinDirectories()) == 0 {
		t.Error("Fallback should return bin directories")
	}
	if len(fallback.GetLibDirectories()) == 0 {
		t.Error("Fallback should return lib directories")
	}
	if len(fallback.GetDirectoryPatterns()) == 0 {
		t.Error("Fallback should return patterns")
	}

	// Test IsSystemDirectory
	if !fallback.IsSystemDirectory("/etc/test") {
		t.Error("Expected /etc/test to be detected as system directory")
	}
	if fallback.IsSystemDirectory("/some/random/path") {
		t.Error("Expected /some/random/path NOT to be detected as system directory")
	}
}

func TestGetFilesystemStructure_WithoutInitialization(t *testing.T) {
	// Reset global state
	globalFSAMutex.Lock()
	oldFS := globalFilesystemStructure
	globalFilesystemStructure = nil
	globalFSAMutex.Unlock()

	// Should return fallback
	fs := GetFilesystemStructure()
	if _, ok := fs.(*fallbackFilesystemStructure); !ok {
		t.Error("Expected fallback when not initialized")
	}

	// Restore
	globalFSAMutex.Lock()
	globalFilesystemStructure = oldFS
	globalFSAMutex.Unlock()
}

func TestInitializeFilesystemStructure(t *testing.T) {
	// Create a temporary directory structure
	tmpDir, err := os.MkdirTemp("", "kaniko-fs-init-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create some test directories
	testDirs := []string{"etc", "var", "tmp", "usr/bin"}
	for _, dir := range testDirs {
		fullPath := filepath.Join(tmpDir, dir)
		if err := os.MkdirAll(fullPath, 0755); err != nil {
			t.Fatalf("Failed to create test dir %s: %v", fullPath, err)
		}
	}

	// Reset global state
	globalFSAMutex.Lock()
	oldFS := globalFilesystemStructure
	globalFilesystemStructure = nil
	globalFSAMutex.Unlock()

	// Initialize
	if err := InitializeFilesystemStructure(tmpDir); err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}

	// Get and verify it's not fallback
	fs := GetFilesystemStructure()
	if _, ok := fs.(*fallbackFilesystemStructure); ok {
		t.Error("Expected dynamic analyzer, got fallback")
	}

	// Verify it works
	if len(fs.GetSystemDirectories()) == 0 {
		t.Error("Expected system directories")
	}

	// Restore
	globalFSAMutex.Lock()
	globalFilesystemStructure = oldFS
	globalFSAMutex.Unlock()
}
