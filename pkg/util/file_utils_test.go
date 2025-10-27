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
	"github.com/pkg/errors"
)

func TestIsFileInfoSame(t *testing.T) {
	// Create a temporary file for testing
	tmpFile, err := os.CreateTemp("", "test_file")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Get file info twice
	fi1, err := os.Lstat(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to get file info: %v", err)
	}

	// Test with same file info
	if !IsFileInfoSame(fi1, fi1) {
		t.Error("IsFileInfoSame should return true for identical file info")
	}

	// Create a different file for testing different file info
	tmpFile2, err := os.CreateTemp("", "test_file2")
	if err != nil {
		t.Fatalf("Failed to create second temp file: %v", err)
	}
	defer os.Remove(tmpFile2.Name())
	defer tmpFile2.Close()

	fi2, err := os.Lstat(tmpFile2.Name())
	if err != nil {
		t.Fatalf("Failed to get second file info: %v", err)
	}

	// Test with different file info (different files)
	if IsFileInfoSame(fi1, fi2) {
		t.Error("IsFileInfoSame should return false for different file info")
	}

	// Test with nil file info
	if IsFileInfoSame(nil, fi1) {
		t.Error("IsFileInfoSame should return false when one file info is nil")
	}

	if IsFileInfoSame(fi1, nil) {
		t.Error("IsFileInfoSame should return false when one file info is nil")
	}

	if !IsFileInfoSame(nil, nil) {
		t.Error("IsFileInfoSame should return true when both file info are nil")
	}
}

func TestSafeFileInfoSame(t *testing.T) {
	// Create a temporary file for testing
	tmpFile, err := os.CreateTemp("", "test_file")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Get file info
	fi1, err := os.Lstat(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to get file info: %v", err)
	}

	// Test with same file info
	if !SafeFileInfoSame(fi1, fi1) {
		t.Error("SafeFileInfoSame should return true for identical file info")
	}

	// Test with nil file info
	if SafeFileInfoSame(nil, fi1) {
		t.Error("SafeFileInfoSame should return false when one file info is nil")
	}

	if SafeFileInfoSame(fi1, nil) {
		t.Error("SafeFileInfoSame should return false when one file info is nil")
	}

	if !SafeFileInfoSame(nil, nil) {
		t.Error("SafeFileInfoSame should return true when both file info are nil")
	}
}

func TestCheckPathAgainstIgnoreList(t *testing.T) {
	// Test with a path that should not be ignored
	result := CheckPathAgainstIgnoreList("/some/path", false)
	if result.ShouldIgnore {
		t.Error("Path should not be ignored")
	}
	if result.ShouldSkipDir {
		t.Error("Should not skip directory")
	}

	// Test with cleaned path
	result = CheckPathAgainstIgnoreList("/some/path", true)
	if result.ShouldIgnore {
		t.Error("Path should not be ignored with cleaned path check")
	}
	if result.ShouldSkipDir {
		t.Error("Should not skip directory with cleaned path check")
	}
}

func TestCreateCommonCallback(t *testing.T) {
	// Create a test callback that always returns nil
	processFile := func(path string, ent *godirwalk.Dirent) error {
		return nil
	}

	// Test with ignore result that should ignore
	ignoreResult := CommonIgnoreCheckResult{
		ShouldIgnore:  true,
		ShouldSkipDir: false,
	}

	callback := CreateCommonCallback(ignoreResult, processFile)

	// Test the callback
	err := callback("/test/path", nil)
	if err != nil {
		t.Errorf("Callback should return nil error, got: %v", err)
	}

	// Test with ignore result that should skip directory
	ignoreResult.ShouldSkipDir = true
	callback = CreateCommonCallback(ignoreResult, processFile)

	// Test the callback - should return filepath.SkipDir
	err = callback("/test/path", nil)
	if err != filepath.SkipDir {
		t.Errorf("Callback should return filepath.SkipDir, got: %v", err)
	}

	// Test with ignore result that should not ignore
	ignoreResult = CommonIgnoreCheckResult{
		ShouldIgnore:  false,
		ShouldSkipDir: false,
	}

	callback = CreateCommonCallback(ignoreResult, processFile)

	// Test the callback - should call processFile
	err = callback("/test/path", nil)
	if err != nil {
		t.Errorf("Callback should return nil error, got: %v", err)
	}
}

func TestDefaultFileProcessorOptions(t *testing.T) {
	options := DefaultFileProcessorOptions()

	if options.IncludeHiddenFiles {
		t.Error("Default should not include hidden files")
	}

	if options.MaxDepth != MaxSearchDepth {
		t.Errorf("Expected MaxDepth to be %d, got %d", MaxSearchDepth, options.MaxDepth)
	}

	if options.FollowSymlinks {
		t.Error("Default should not follow symlinks")
	}

	if options.BufferSize != DefaultBufferSize {
		t.Errorf("Expected BufferSize to be %d, got %d", DefaultBufferSize, options.BufferSize)
	}
}

func TestFileOperationResult(t *testing.T) {
	result := FileOperationResult{
		Success:        true,
		Error:          nil,
		FilesProcessed: 10,
		FilesChanged:   5,
	}

	if !result.Success {
		t.Error("Success should be true")
	}

	if result.Error != nil {
		t.Error("Error should be nil")
	}

	if result.FilesProcessed != 10 {
		t.Errorf("Expected FilesProcessed to be 10, got %d", result.FilesProcessed)
	}

	if result.FilesChanged != 5 {
		t.Errorf("Expected FilesChanged to be 5, got %d", result.FilesChanged)
	}
}

// Test new common utilities
func TestCommonWalkOptions(t *testing.T) {
	opts := DefaultWalkOptions()

	if !opts.Unsorted {
		t.Error("Default should have Unsorted=true")
	}

	if opts.Callback != nil {
		t.Error("Default callback should be nil")
	}
}

func TestCreateWalkOptions(t *testing.T) {
	callback := func(path string, ent *godirwalk.Dirent) error {
		return nil
	}

	opts := CommonWalkOptions{
		Unsorted: true,
		Callback: callback,
	}

	godirwalkOpts := CreateWalkOptions(opts)

	if !godirwalkOpts.Unsorted {
		t.Error("Unsorted should be true")
	}

	if godirwalkOpts.Callback == nil {
		t.Error("Callback should not be nil")
	}
}

func TestCommonIgnoreHandling(t *testing.T) {
	handling := DefaultIgnoreHandling()

	if handling.UseCleanedPath {
		t.Error("Default should not use cleaned path")
	}

	if !handling.LogIgnored {
		t.Error("Default should log ignored files")
	}

	if handling.LogMessage == "" {
		t.Error("Default should have log message")
	}
}

func TestGetProcessorIgnoreHandling(t *testing.T) {
	// Test delete processor
	deleteHandling := GetProcessorIgnoreHandling(FileProcessorTypeDelete)
	if deleteHandling.UseCleanedPath {
		t.Error("Delete processor should not use cleaned path")
	}
	if !deleteHandling.LogIgnored {
		t.Error("Delete processor should log ignored files")
	}
	if deleteHandling.LogMessage != "Not deleting %s, as it's ignored" {
		t.Errorf("Expected delete message, got: %s", deleteHandling.LogMessage)
	}

	// Test ownership processor
	ownershipHandling := GetProcessorIgnoreHandling(FileProcessorTypeOwnership)
	if ownershipHandling.UseCleanedPath {
		t.Error("Ownership processor should not use cleaned path")
	}
	if !ownershipHandling.LogIgnored {
		t.Error("Ownership processor should log ignored files")
	}
	if ownershipHandling.LogMessage != "Not copying ownership for %s, as it's ignored" {
		t.Errorf("Expected ownership message, got: %s", ownershipHandling.LogMessage)
	}

	// Test stat processor
	statHandling := GetProcessorIgnoreHandling(FileProcessorTypeStat)
	if !statHandling.UseCleanedPath {
		t.Error("Stat processor should use cleaned path")
	}
	if statHandling.LogIgnored {
		t.Error("Stat processor should not log ignored files")
	}
}

func TestCreateIgnoreCallback(t *testing.T) {
	processedFiles := make([]string, 0)
	processFile := func(path string, ent *godirwalk.Dirent) error {
		processedFiles = append(processedFiles, path)
		return nil
	}

	handling := CommonIgnoreHandling{
		UseCleanedPath: false,
		LogIgnored:     true,
		LogMessage:     "Test: ignoring %s",
	}

	callback := CreateIgnoreCallback(handling, processFile)

	// Test processing a file (should not be ignored)
	err := callback("/test/path", nil)
	if err != nil {
		t.Errorf("Callback should not return error, got: %v", err)
	}

	if len(processedFiles) != 1 {
		t.Errorf("Expected 1 processed file, got %d", len(processedFiles))
	}
}

func TestCommonErrorHandler(t *testing.T) {
	handler := DefaultErrorHandler()

	if !handler.LogErrors {
		t.Error("Default should log errors")
	}

	if handler.ContinueOnError {
		t.Error("Default should not continue on error")
	}
}

func TestHandleFileOperationError(t *testing.T) {
	handler := DefaultErrorHandler()

	// Test with no error
	err := HandleFileOperationError(nil, handler, "test", "/path")
	if err != nil {
		t.Errorf("Should return nil for no error, got: %v", err)
	}

	// Test with error
	testErr := errors.New("test error")
	err = HandleFileOperationError(testErr, handler, "test", "/path")
	if err != testErr {
		t.Errorf("Should return original error, got: %v", err)
	}

	// Test with continue on error
	handler.ContinueOnError = true
	err = HandleFileOperationError(testErr, handler, "test", "/path")
	if err != nil {
		t.Errorf("Should return nil when ContinueOnError=true, got: %v", err)
	}
}
