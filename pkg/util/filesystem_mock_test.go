/*
Copyright 2024 Kaniko Contributors

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
	"time"
)

func TestMockFileSystem_BasicOperations(t *testing.T) {
	mfs := NewMockFileSystem()

	// Test WriteFile
	content := []byte("test content")
	err := mfs.WriteFile("/test/file.txt", content, 0644)
	if err != nil {
		t.Errorf("WriteFile failed: %v", err)
	}

	// Test ReadFile
	readContent, err := mfs.ReadFile("/test/file.txt")
	if err != nil {
		t.Errorf("ReadFile failed: %v", err)
	}
	if string(readContent) != "test content" {
		t.Errorf("Expected 'test content', got '%s'", string(readContent))
	}

	// Test Mkdir
	err = mfs.Mkdir("/test/dir", 0755)
	if err != nil {
		t.Errorf("Mkdir failed: %v", err)
	}

	// Test MkdirAll
	err = mfs.MkdirAll("/test/nested/dir", 0755)
	if err != nil {
		t.Errorf("MkdirAll failed: %v", err)
	}

	// Test Symlink
	err = mfs.Symlink("/test/file.txt", "/test/link.txt")
	if err != nil {
		t.Errorf("Symlink failed: %v", err)
	}

	// Test Readlink
	target, err := mfs.Readlink("/test/link.txt")
	if err != nil {
		t.Errorf("Readlink failed: %v", err)
	}
	if target != "/test/file.txt" {
		t.Errorf("Expected '/test/file.txt', got '%s'", target)
	}
}

func TestMockFileSystem_ErrorHandling(t *testing.T) {
	mfs := NewMockFileSystem()

	// Test setting an error
	testError := os.ErrPermission
	mfs.SetError("readfile", "/test/file.txt", testError)

	// Test that the error is returned
	_, err := mfs.ReadFile("/test/file.txt")
	if err != testError {
		t.Errorf("Expected error %v, got %v", testError, err)
	}

	// Test that other operations still work
	content := []byte("test")
	err = mfs.WriteFile("/test/file2.txt", content, 0644)
	if err != nil {
		t.Errorf("WriteFile should not fail: %v", err)
	}
}

func TestMockFileSystem_DirectoryOperations(t *testing.T) {
	mfs := NewMockFileSystem()

	// Set up directory contents
	entries := []string{"file1.txt", "file2.txt", "subdir"}
	mfs.SetDirectory("/test", entries)

	// Test ReadDir
	dirEntries, err := mfs.ReadDir("/test")
	if err != nil {
		t.Errorf("ReadDir failed: %v", err)
	}

	if len(dirEntries) != len(entries) {
		t.Errorf("Expected %d entries, got %d", len(entries), len(dirEntries))
	}

	// Check entry names
	for i, entry := range dirEntries {
		if entry.Name() != entries[i] {
			t.Errorf("Expected entry name '%s', got '%s'", entries[i], entry.Name())
		}
	}
}

func TestMockFileSystem_FilePermissions(t *testing.T) {
	mfs := NewMockFileSystem()

	// Test Chmod
	err := mfs.Chmod("/test/file.txt", 0755)
	if err != nil {
		t.Errorf("Chmod failed: %v", err)
	}

	// Test Chown
	err = mfs.Chown("/test/file.txt", 1000, 1000)
	if err != nil {
		t.Errorf("Chown failed: %v", err)
	}

	// Verify ownership was set
	ownership, exists := mfs.Ownership["/test/file.txt"]
	if !exists {
		t.Errorf("Ownership not set")
	}
	if ownership.UID != 1000 || ownership.GID != 1000 {
		t.Errorf("Expected UID=1000, GID=1000, got UID=%d, GID=%d", ownership.UID, ownership.GID)
	}
}

func TestMockFileSystem_RemoveOperations(t *testing.T) {
	mfs := NewMockFileSystem()

	// Set up some files
	mfs.SetFile("/test/file1.txt", []byte("content1"))
	mfs.SetFile("/test/file2.txt", []byte("content2"))
	mfs.SetDirectory("/test/dir", []string{"file.txt"})

	// Test Remove
	err := mfs.Remove("/test/file1.txt")
	if err != nil {
		t.Errorf("Remove failed: %v", err)
	}

	// Verify file was removed
	if _, exists := mfs.Files["/test/file1.txt"]; exists {
		t.Errorf("File should have been removed")
	}

	// Test RemoveAll
	err = mfs.RemoveAll("/test")
	if err != nil {
		t.Errorf("RemoveAll failed: %v", err)
	}

	// Verify all files were removed
	if len(mfs.Files) != 0 {
		t.Errorf("Expected no files, got %d", len(mfs.Files))
	}
}

func TestMockFileSystem_StatOperations(t *testing.T) {
	mfs := NewMockFileSystem()

	// Test Stat on non-existent file
	_, err := mfs.Stat("/nonexistent/file.txt")
	if err == nil {
		t.Errorf("Expected error for non-existent file")
	}

	// Test Stat on existing file
	mfs.SetFile("/test/file.txt", []byte("content"))
	info, err := mfs.Stat("/test/file.txt")
	if err != nil {
		t.Errorf("Stat failed: %v", err)
	}
	if info.Name() != "file.txt" {
		t.Errorf("Expected name 'file.txt', got '%s'", info.Name())
	}
}

func TestMockFileSystem_TimeOperations(t *testing.T) {
	mfs := NewMockFileSystem()

	// Test Chtimes
	now := time.Now()
	err := mfs.Chtimes("/test/file.txt", now, now)
	if err != nil {
		t.Errorf("Chtimes failed: %v", err)
	}
}

func TestRealFileSystem_Integration(t *testing.T) {
	// Test that RealFileSystem works with actual file system
	fs := NewRealFileSystem()
	tempDir := t.TempDir()

	// Test WriteFile
	content := []byte("test content")
	err := fs.WriteFile(filepath.Join(tempDir, "test.txt"), content, 0644)
	if err != nil {
		t.Errorf("RealFileSystem WriteFile failed: %v", err)
	}

	// Test ReadFile
	readContent, err := fs.ReadFile(filepath.Join(tempDir, "test.txt"))
	if err != nil {
		t.Errorf("RealFileSystem ReadFile failed: %v", err)
	}
	if string(readContent) != "test content" {
		t.Errorf("Expected 'test content', got '%s'", string(readContent))
	}

	// Test Mkdir
	err = fs.Mkdir(filepath.Join(tempDir, "testdir"), 0755)
	if err != nil {
		t.Errorf("RealFileSystem Mkdir failed: %v", err)
	}

	// Test Stat
	info, err := fs.Stat(filepath.Join(tempDir, "test.txt"))
	if err != nil {
		t.Errorf("RealFileSystem Stat failed: %v", err)
	}
	if info.Name() != "test.txt" {
		t.Errorf("Expected name 'test.txt', got '%s'", info.Name())
	}
}

func TestMockFileSystem_ComplexScenarios(t *testing.T) {
	mfs := NewMockFileSystem()

	// Test complex file system setup
	mfs.SetFile("/app/config.json", []byte(`{"key": "value"}`))
	mfs.SetFile("/app/main.go", []byte("package main"))
	mfs.SetDirectory("/app", []string{"config.json", "main.go", "src"})
	mfs.SetDirectory("/app/src", []string{"utils.go"})
	mfs.SetFile("/app/src/utils.go", []byte("package utils"))

	// Test reading nested file
	content, err := mfs.ReadFile("/app/src/utils.go")
	if err != nil {
		t.Errorf("ReadFile failed: %v", err)
	}
	if string(content) != "package utils" {
		t.Errorf("Expected 'package utils', got '%s'", string(content))
	}

	// Test reading directory
	entries, err := mfs.ReadDir("/app")
	if err != nil {
		t.Errorf("ReadDir failed: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("Expected 3 entries, got %d", len(entries))
	}
}

func TestMockFileSystem_ErrorRecovery(t *testing.T) {
	mfs := NewMockFileSystem()

	// Set up a file
	mfs.SetFile("/test/file.txt", []byte("content"))

	// Set an error for one operation
	mfs.SetError("readfile", "/test/file.txt", os.ErrPermission)

	// First read should fail
	_, err := mfs.ReadFile("/test/file.txt")
	if err != os.ErrPermission {
		t.Errorf("Expected ErrPermission, got %v", err)
	}

	// Remove the error
	delete(mfs.Errors, "readfile:/test/file.txt")

	// Second read should succeed
	content, err := mfs.ReadFile("/test/file.txt")
	if err != nil {
		t.Errorf("ReadFile should succeed after error removal: %v", err)
	}
	if string(content) != "content" {
		t.Errorf("Expected 'content', got '%s'", string(content))
	}
}
