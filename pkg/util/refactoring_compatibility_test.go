/*
Copyright 2018 Google LLC

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

	"github.com/karrick/godirwalk"
)

// TestRefactoringCompatibility tests that our refactoring maintains compatibility
// with existing functionality
func TestRefactoringCompatibility(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "refactor_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create some test files
	testFiles := []string{
		"file1.txt",
		"file2.txt",
		"subdir/file3.txt",
		"subdir/file4.txt",
	}

	for _, file := range testFiles {
		fullPath := filepath.Join(tmpDir, file)
		dir := filepath.Dir(fullPath)

		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("Failed to create directory %s: %v", dir, err)
		}

		if err := os.WriteFile(fullPath, []byte("test content"), 0644); err != nil {
			t.Fatalf("Failed to create file %s: %v", fullPath, err)
		}
	}

	// Test GetFSInfoMap functionality
	t.Run("GetFSInfoMap_Compatibility", func(t *testing.T) {
		existing := make(map[string]os.FileInfo)
		fileMap, _ := GetFSInfoMap(tmpDir, existing)

		if len(fileMap) == 0 {
			t.Error("GetFSInfoMap should return files")
		}

		// Verify that all test files are found
		for _, file := range testFiles {
			fullPath := filepath.Join(tmpDir, file)
			if _, exists := fileMap[fullPath]; !exists {
				t.Errorf("File %s should be found by GetFSInfoMap", fullPath)
			}
		}
	})

	// Test WalkFS functionality
	t.Run("WalkFS_Compatibility", func(t *testing.T) {
		existingPaths := make(map[string]struct{})
		changeFunc := func(path string) (bool, error) {
			// Simple change detection - always return true for testing
			return true, nil
		}

		filesAdded, deletedFiles := WalkFS(tmpDir, existingPaths, changeFunc)

		if len(filesAdded) == 0 {
			t.Error("WalkFS should return added files")
		}

		// Verify that all test files are found
		for _, file := range testFiles {
			fullPath := filepath.Join(tmpDir, file)
			found := false
			for _, added := range filesAdded {
				if added == fullPath {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("File %s should be found by WalkFS", fullPath)
			}
		}

		// deletedFiles should be empty since we started with empty existingPaths
		if len(deletedFiles) != 0 {
			t.Error("deletedFiles should be empty when starting with empty existingPaths")
		}
	})

	// Test that both functions produce consistent results
	t.Run("Consistency_Between_Functions", func(t *testing.T) {
		existing := make(map[string]os.FileInfo)
		fileMap, _ := GetFSInfoMap(tmpDir, existing)

		existingPaths := make(map[string]struct{})
		changeFunc := func(path string) (bool, error) {
			return true, nil
		}
		filesAdded, _ := WalkFS(tmpDir, existingPaths, changeFunc)

		// Both functions should find the same number of files
		if len(fileMap) != len(filesAdded) {
			t.Errorf("GetFSInfoMap found %d files, WalkFS found %d files", len(fileMap), len(filesAdded))
		}

		// Both functions should find the same files
		for path := range fileMap {
			found := false
			for _, added := range filesAdded {
				if added == path {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("File %s found by GetFSInfoMap but not by WalkFS", path)
			}
		}
	})
}

// TestCommonFunctionsIntegration tests that our new common functions work correctly
// with the existing codebase
func TestCommonFunctionsIntegration(t *testing.T) {
	// Test CheckPathAgainstIgnoreList with different scenarios
	t.Run("CheckPathAgainstIgnoreList_Integration", func(t *testing.T) {
		testCases := []struct {
			path           string
			useCleanedPath bool
			expectIgnore   bool
		}{
			{"/some/path", false, false},
			{"/some/path", true, false},
			{"/tmp/path", false, false},
			{"/tmp/path", true, false},
		}

		for _, tc := range testCases {
			result := CheckPathAgainstIgnoreList(tc.path, tc.useCleanedPath)
			if result.ShouldIgnore != tc.expectIgnore {
				t.Errorf("CheckPathAgainstIgnoreList(%s, %v) should ignore=%v, got ignore=%v",
					tc.path, tc.useCleanedPath, tc.expectIgnore, result.ShouldIgnore)
			}
		}
	})

	// Test CreateCommonCallback integration
	t.Run("CreateCommonCallback_Integration", func(t *testing.T) {
		// Test callback that processes files
		processedFiles := make([]string, 0)
		processFile := func(path string, ent *godirwalk.Dirent) error {
			processedFiles = append(processedFiles, path)
			return nil
		}

		// Test with no ignore
		ignoreResult := CommonIgnoreCheckResult{
			ShouldIgnore:  false,
			ShouldSkipDir: false,
		}

		callback := CreateCommonCallback(ignoreResult, processFile)

		// Test the callback
		err := callback("/test/path", nil)
		if err != nil {
			t.Errorf("Callback should not return error, got: %v", err)
		}

		if len(processedFiles) != 1 {
			t.Errorf("Expected 1 processed file, got %d", len(processedFiles))
		}

		if processedFiles[0] != "/test/path" {
			t.Errorf("Expected processed file to be '/test/path', got '%s'", processedFiles[0])
		}
	})
}
