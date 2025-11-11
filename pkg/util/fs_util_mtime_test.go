/*
Copyright 2025 Gosayram

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

	"github.com/Gosayram/kaniko/testutil"
)

func TestCopyFile_PreservesMtime(t *testing.T) {
	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "source.txt")
	destFile := filepath.Join(tmpDir, "dest.txt")

	// Create source file with specific mtime
	content := []byte("test content")
	if err := os.WriteFile(srcFile, content, 0644); err != nil {
		t.Fatalf("Failed to create source file: %v", err)
	}

	// Set a specific mtime (1 hour ago)
	expectedMtime := time.Now().Add(-1 * time.Hour).Truncate(time.Second)
	if err := os.Chtimes(srcFile, expectedMtime, expectedMtime); err != nil {
		t.Fatalf("Failed to set mtime on source file: %v", err)
	}

	// Verify source file has the expected mtime
	srcInfo, err := os.Stat(srcFile)
	if err != nil {
		t.Fatalf("Failed to stat source file: %v", err)
	}
	testutil.CheckDeepEqual(t, expectedMtime.Unix(), srcInfo.ModTime().Unix())

	// Copy the file
	srcF, err := os.Open(srcFile)
	if err != nil {
		t.Fatalf("Failed to open source file: %v", err)
	}
	defer srcF.Close()

	// Use CopyFile which should preserve mtime
	_, err = CopyFile(srcFile, destFile, FileContext{}, 0, 0, 0644, true)
	if err != nil {
		t.Fatalf("CopyFile failed: %v", err)
	}

	// Verify destination file has the same mtime
	destInfo, err := os.Stat(destFile)
	if err != nil {
		t.Fatalf("Failed to stat destination file: %v", err)
	}

	// Check that mtime is preserved (within 1 second tolerance)
	srcMtime := srcInfo.ModTime().Unix()
	destMtime := destInfo.ModTime().Unix()
	if srcMtime != destMtime {
		t.Errorf("mtime not preserved: source=%d, dest=%d", srcMtime, destMtime)
	}
}

func TestCopyFile_PreservesMtimeWithDifferentTimes(t *testing.T) {
	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "source.txt")
	destFile := filepath.Join(tmpDir, "dest.txt")

	// Create source file
	content := []byte("test content")
	if err := os.WriteFile(srcFile, content, 0644); err != nil {
		t.Fatalf("Failed to create source file: %v", err)
	}

	// Set mtime to a specific time in the past
	expectedMtime := time.Date(2020, 1, 1, 12, 0, 0, 0, time.UTC)
	if err := os.Chtimes(srcFile, expectedMtime, expectedMtime); err != nil {
		t.Fatalf("Failed to set mtime on source file: %v", err)
	}

	// Copy the file
	_, err := CopyFile(srcFile, destFile, FileContext{}, 0, 0, 0644, true)
	if err != nil {
		t.Fatalf("CopyFile failed: %v", err)
	}

	// Verify mtime is preserved
	destInfo, err := os.Stat(destFile)
	if err != nil {
		t.Fatalf("Failed to stat destination file: %v", err)
	}

	// Check that mtime matches (within 1 second)
	srcInfo, _ := os.Stat(srcFile)
	if srcInfo.ModTime().Unix() != destInfo.ModTime().Unix() {
		t.Errorf("mtime not preserved: source=%v, dest=%v", srcInfo.ModTime(), destInfo.ModTime())
	}
}
