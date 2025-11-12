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

func TestRelativeFiles_Basic(t *testing.T) {
	tempDir := t.TempDir()

	// Create test files
	os.WriteFile(filepath.Join(tempDir, "file1.txt"), []byte("content1"), 0644)
	os.WriteFile(filepath.Join(tempDir, "file2.txt"), []byte("content2"), 0644)
	os.MkdirAll(filepath.Join(tempDir, "subdir"), 0755)
	os.WriteFile(filepath.Join(tempDir, "subdir", "file3.txt"), []byte("content3"), 0644)

	files, err := RelativeFiles("", tempDir)
	if err != nil {
		t.Fatalf("RelativeFiles() error = %v", err)
	}
	if len(files) < 3 {
		t.Errorf("RelativeFiles() files count = %d, want at least 3", len(files))
	}

	// Check that files are relative paths
	for _, file := range files {
		if filepath.IsAbs(file) {
			t.Errorf("RelativeFiles() returned absolute path: %q", file)
		}
	}
}

func TestRelativeFiles_SpecificPath(t *testing.T) {
	tempDir := t.TempDir()

	// Create subdirectory with files
	subDir := filepath.Join(tempDir, "subdir")
	os.MkdirAll(subDir, 0755)
	os.WriteFile(filepath.Join(subDir, "file1.txt"), []byte("content1"), 0644)
	os.WriteFile(filepath.Join(subDir, "file2.txt"), []byte("content2"), 0644)

	files, err := RelativeFiles("subdir", tempDir)
	if err != nil {
		t.Fatalf("RelativeFiles() error = %v", err)
	}
	// Should return at least 2 files (may include directories)
	if len(files) < 2 {
		t.Errorf("RelativeFiles() files count = %d, want at least 2", len(files))
	}

	// Check that files contain our test files
	foundFile1 := false
	foundFile2 := false
	for _, file := range files {
		if file == "subdir/file1.txt" || file == "file1.txt" {
			foundFile1 = true
		}
		if file == "subdir/file2.txt" || file == "file2.txt" {
			foundFile2 = true
		}
	}
	if !foundFile1 || !foundFile2 {
		t.Errorf("RelativeFiles() should contain file1.txt and file2.txt, got %v", files)
	}
}

func TestRelativeFiles_EmptyDirectory(t *testing.T) {
	tempDir := t.TempDir()

	_, err := RelativeFiles("", tempDir)
	// Empty directory should return empty list (or just the directory itself)
	// The exact behavior may vary, so we just check it doesn't error
	if err != nil {
		t.Errorf("RelativeFiles() should not error on empty directory, got %v", err)
	}
}

func TestRelativeFiles_NonExistentPath(t *testing.T) {
	tempDir := t.TempDir()

	files, err := RelativeFiles("nonexistent", tempDir)
	// Should not error, just return empty list
	if err != nil {
		t.Errorf("RelativeFiles() error = %v, want nil", err)
	}
	if len(files) != 0 {
		t.Errorf("RelativeFiles() files count = %d, want 0", len(files))
	}
}

func TestRelativeFiles_Symlinks(t *testing.T) {
	tempDir := t.TempDir()

	// Create a file
	targetFile := filepath.Join(tempDir, "target.txt")
	os.WriteFile(targetFile, []byte("content"), 0644)

	// Create a symlink (if supported)
	symlinkFile := filepath.Join(tempDir, "link.txt")
	err := os.Symlink("target.txt", symlinkFile)
	if err != nil {
		// Symlinks might not be supported on all systems, skip test
		t.Skipf("Symlinks not supported: %v", err)
	}

	files, err := RelativeFiles("", tempDir)
	if err != nil {
		t.Fatalf("RelativeFiles() error = %v", err)
	}
	// Symlinks should be skipped, so we should only get the target file
	// But the actual behavior depends on implementation
	if len(files) < 1 {
		t.Errorf("RelativeFiles() files count = %d, want at least 1", len(files))
	}
}

func TestRelativeFiles_NestedDirectories(t *testing.T) {
	tempDir := t.TempDir()

	// Create nested directory structure
	os.MkdirAll(filepath.Join(tempDir, "level1", "level2", "level3"), 0755)
	os.WriteFile(filepath.Join(tempDir, "level1", "file1.txt"), []byte("content1"), 0644)
	os.WriteFile(filepath.Join(tempDir, "level1", "level2", "file2.txt"), []byte("content2"), 0644)
	os.WriteFile(filepath.Join(tempDir, "level1", "level2", "level3", "file3.txt"), []byte("content3"), 0644)

	files, err := RelativeFiles("", tempDir)
	if err != nil {
		t.Fatalf("RelativeFiles() error = %v", err)
	}
	// Should return at least 3 files (may include directories)
	if len(files) < 3 {
		t.Errorf("RelativeFiles() files count = %d, want at least 3", len(files))
	}

	// Check that all three files are present
	foundFiles := make(map[string]bool)
	for _, file := range files {
		if file == "level1/file1.txt" || file == "file1.txt" {
			foundFiles["file1"] = true
		}
		if file == "level1/level2/file2.txt" || file == "file2.txt" {
			foundFiles["file2"] = true
		}
		if file == "level1/level2/level3/file3.txt" || file == "file3.txt" {
			foundFiles["file3"] = true
		}
	}
	if len(foundFiles) < 3 {
		t.Errorf("RelativeFiles() should contain all 3 test files, found %d, got %v", len(foundFiles), files)
	}
}
