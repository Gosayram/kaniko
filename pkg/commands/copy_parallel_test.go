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

package commands

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"

	"github.com/Gosayram/kaniko/pkg/util"
)

func TestCopySourcesParallel(t *testing.T) {
	// Create temporary directory for testing
	tempDir := t.TempDir()

	// Create test files
	testFiles := []string{"file1.txt", "file2.txt", "file3.txt", "file4.txt", "file5.txt"}
	for _, file := range testFiles {
		filePath := filepath.Join(tempDir, file)
		if err := os.WriteFile(filePath, []byte("test content for "+file), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", file, err)
		}
	}

	// Create destination directory
	destDir := filepath.Join(tempDir, "dest")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		t.Fatalf("Failed to create destination directory: %v", err)
	}

	// Create CopyCommand
	cmd := &CopyCommand{
		cmd: &instructions.CopyCommand{
			SourcesAndDest: instructions.SourcesAndDest{
				SourcePaths: testFiles,
				DestPath:    "dest/",
			},
		},
		fileContext: util.FileContext{Root: tempDir},
	}

	// Test parallel copying
	start := time.Now()
	err := cmd.copySourcesParallel(testFiles, "dest/", &v1.Config{}, 1000, 1000, 0644, true)
	duration := time.Since(start)

	if err != nil {
		t.Errorf("Parallel copy failed: %v", err)
	}

	// Verify files were copied
	for _, file := range testFiles {
		destPath := filepath.Join(destDir, file)
		if _, err := os.Stat(destPath); os.IsNotExist(err) {
			t.Errorf("File %s was not copied", file)
		}
	}

	// Parallel execution should be faster than sequential for multiple files
	if duration > time.Second {
		t.Errorf("Parallel copy took too long: %v", duration)
	}

	t.Logf("Parallel copy completed in %v", duration)
}

func TestCopySourcesSequential(t *testing.T) {
	// Create temporary directory for testing
	tempDir := t.TempDir()

	// Create test files (small number to trigger sequential processing)
	testFiles := []string{"file1.txt", "file2.txt"}
	for _, file := range testFiles {
		filePath := filepath.Join(tempDir, file)
		if err := os.WriteFile(filePath, []byte("test content for "+file), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", file, err)
		}
	}

	// Create destination directory
	destDir := filepath.Join(tempDir, "dest")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		t.Fatalf("Failed to create destination directory: %v", err)
	}

	// Create CopyCommand
	cmd := &CopyCommand{
		cmd: &instructions.CopyCommand{
			SourcesAndDest: instructions.SourcesAndDest{
				SourcePaths: testFiles,
				DestPath:    "dest/",
			},
		},
		fileContext: util.FileContext{Root: tempDir},
	}

	// Test sequential copying (should be used for small number of files)
	err := cmd.copySources(testFiles, "dest/", &v1.Config{}, 1000, 1000, 0644, true)

	if err != nil {
		t.Errorf("Sequential copy failed: %v", err)
	}

	// Verify files were copied
	for _, file := range testFiles {
		destPath := filepath.Join(destDir, file)
		if _, err := os.Stat(destPath); os.IsNotExist(err) {
			t.Errorf("File %s was not copied", file)
		}
	}
}

func TestCopySourcesErrorHandling(t *testing.T) {
	// Create temporary directory for testing
	tempDir := t.TempDir()

	// Create test files with one non-existent file
	testFiles := []string{"file1.txt", "nonexistent.txt", "file3.txt"}

	// Create only some files
	for _, file := range []string{"file1.txt", "file3.txt"} {
		filePath := filepath.Join(tempDir, file)
		if err := os.WriteFile(filePath, []byte("test content for "+file), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", file, err)
		}
	}

	// Create destination directory
	destDir := filepath.Join(tempDir, "dest")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		t.Fatalf("Failed to create destination directory: %v", err)
	}

	// Create CopyCommand
	cmd := &CopyCommand{
		cmd: &instructions.CopyCommand{
			SourcesAndDest: instructions.SourcesAndDest{
				SourcePaths: testFiles,
				DestPath:    "dest/",
			},
		},
		fileContext: util.FileContext{Root: tempDir},
	}

	// Test error handling in parallel copying
	err := cmd.copySourcesParallel(testFiles, "dest/", &v1.Config{}, 1000, 1000, 0644, true)

	// Should return an error due to non-existent file
	if err == nil {
		t.Error("Expected error for non-existent file, but got none")
	}

	t.Logf("Error handling test passed: %v", err)
}
