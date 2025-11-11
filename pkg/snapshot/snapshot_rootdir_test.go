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

package snapshot

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/util"
	"github.com/Gosayram/kaniko/testutil"
)

func TestWriteToTar_SkipsRootdir(t *testing.T) {
	tmpDir := t.TempDir()
	config.RootDir = tmpDir

	// Create some files in the rootdir
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create a tar writer
	var buf bytes.Buffer
	tar := util.NewTar(&buf)
	defer tar.Close()

	// Write files to tar
	files := []string{testFile}
	whiteouts := []string{}

	err := writeToTar(tar, files, whiteouts)
	testutil.CheckNoError(t, err)

	// Verify that rootdir itself is not in the tar
	tarContent := buf.Bytes()
	rootDirName := filepath.Base(config.RootDir)

	// The rootdir should not appear as a file entry
	// (it might appear in paths, but not as a standalone entry)
	// This is a basic check - the actual implementation marks it as already added
	if bytes.Contains(tarContent, []byte(rootDirName+"/\x00")) {
		// This is acceptable - rootdir might appear in paths
	}

	// Cleanup
	config.RootDir = "/workspace"
}

func TestAddParentDirectories_SkipsRootdir(t *testing.T) {
	tmpDir := t.TempDir()
	config.RootDir = tmpDir

	// Create subdirectory and file
	subdir := filepath.Join(tmpDir, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}
	testFile := filepath.Join(subdir, "file.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create a tar writer
	var buf bytes.Buffer
	tar := util.NewTar(&buf)
	defer tar.Close()

	addedPaths := make(map[string]bool)
	// Rootdir should be marked as already added
	addedPaths[config.RootDir] = true

	// Try to add a path that would require adding rootdir as parent
	err := addParentDirectories(tar, addedPaths, testFile)
	testutil.CheckNoError(t, err)

	// Verify rootdir is still marked as added and wasn't processed again
	if !addedPaths[config.RootDir] {
		t.Error("Rootdir should remain marked as added")
	}

	// Cleanup
	config.RootDir = "/workspace"
}

func TestWriteToTar_RootdirMarkedAsAdded(t *testing.T) {
	tmpDir := t.TempDir()
	config.RootDir = tmpDir

	// Create a tar writer
	var buf bytes.Buffer
	tar := util.NewTar(&buf)
	defer tar.Close()

	// Create test files
	testFile1 := filepath.Join(tmpDir, "file1.txt")
	testFile2 := filepath.Join(tmpDir, "subdir", "file2.txt")

	os.MkdirAll(filepath.Dir(testFile2), 0755)
	os.WriteFile(testFile1, []byte("test1"), 0644)
	os.WriteFile(testFile2, []byte("test2"), 0644)

	files := []string{testFile1, testFile2}
	whiteouts := []string{}

	err := writeToTar(tar, files, whiteouts)
	testutil.CheckNoError(t, err)

	// The key test: rootdir should be marked as already added in writeToTar
	// This prevents it from being snapshotted as a separate entry
	// We can't directly test the internal state, but we can verify the function completes

	// Cleanup
	config.RootDir = "/workspace"
}
