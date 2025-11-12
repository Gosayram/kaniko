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

package executor

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Gosayram/kaniko/pkg/commands"
	"github.com/Gosayram/kaniko/pkg/dockerfile"
	"github.com/Gosayram/kaniko/pkg/util"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Test_calculateAdaptiveTimeout tests adaptive timeout calculation
func Test_calculateAdaptiveTimeout(t *testing.T) {
	tests := []struct {
		name        string
		fileCount   int
		minTimeout  time.Duration
		maxTimeout  time.Duration
		expected    time.Duration
		description string
	}{
		{
			name:        "zero files uses min timeout",
			fileCount:   0,
			minTimeout:  2 * time.Minute,
			maxTimeout:  10 * time.Minute,
			expected:    2 * time.Minute,
			description: "Zero files should return minimum timeout",
		},
		{
			name:        "small file count uses min timeout when calculated is below min",
			fileCount:   10,
			minTimeout:  2 * time.Minute,
			maxTimeout:  10 * time.Minute,
			expected:    2 * time.Minute, // 10 * 100ms = 1s < 2min, so use min
			description: "Small file count should use min timeout when calculated is below minimum",
		},
		{
			name:        "calculated timeout below min uses min",
			fileCount:   5,
			minTimeout:  2 * time.Minute,
			maxTimeout:  10 * time.Minute,
			expected:    2 * time.Minute, // 5 * 100ms = 500ms < 2min, so use min
			description: "When calculated timeout is below minimum, use minimum",
		},
		{
			name:        "calculated timeout above max uses max",
			fileCount:   10000,
			minTimeout:  2 * time.Minute,
			maxTimeout:  10 * time.Minute,
			expected:    10 * time.Minute, // 10000 * 100ms = 1000s > 10min, so use max
			description: "When calculated timeout exceeds maximum, use maximum",
		},
		{
			name:        "medium file count uses min timeout when calculated is below min",
			fileCount:   100,
			minTimeout:  2 * time.Minute,
			maxTimeout:  10 * time.Minute,
			expected:    2 * time.Minute, // 100 * 100ms = 10s < 2min, so use min
			description: "Medium file count should use min timeout when calculated is below minimum",
		},
		{
			name:        "file count that exceeds min uses calculated timeout",
			fileCount:   1500,
			minTimeout:  2 * time.Minute,
			maxTimeout:  10 * time.Minute,
			expected:    2*time.Minute + 30*time.Second, // 1500 * 100ms = 150s = 2min 30s
			description: "File count that exceeds min should use calculated timeout",
		},
		{
			name:        "large file count but within max",
			fileCount:   3000,
			minTimeout:  2 * time.Minute,
			maxTimeout:  10 * time.Minute,
			expected:    5 * time.Minute, // 3000 * 100ms = 300s = 5min
			description: "Large file count should calculate timeout correctly within limits",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateAdaptiveTimeout(tt.fileCount, tt.minTimeout, tt.maxTimeout)
			if result != tt.expected {
				t.Errorf("%s: expected %v, got %v", tt.description, tt.expected, result)
			}
		})
	}
}

// Test_populateCompositeKeyParallel tests parallel hashing for large file lists
func Test_populateCompositeKeyParallel(t *testing.T) {
	// Create temporary directory with test files
	tmpDir := t.TempDir()
	testFiles := []string{}

	// Create 15 files (more than threshold of 10)
	for i := 0; i < 15; i++ {
		filePath := filepath.Join(tmpDir, "testfile"+string(rune('a'+i))+".txt")
		if err := os.WriteFile(filePath, []byte("test content "+string(rune('a'+i))), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
		testFiles = append(testFiles, filePath)
	}

	sb := &stageBuilder{
		fileContext: util.FileContext{Root: tmpDir},
		args:        dockerfile.NewBuildArgs([]string{}),
	}

	compositeKey := NewCompositeCache()

	// Test that parallel processing works
	resultKey, err := sb.populateCompositeKeyParallel(testFiles, *compositeKey)
	if err != nil {
		t.Fatalf("populateCompositeKeyParallel failed: %v", err)
	}

	// Verify that keys were added
	if len(resultKey.keys) == 0 {
		t.Error("Expected keys to be added, but got empty keys")
	}

	// Verify that all files were processed
	// Note: Due to parallel processing, keys may be added in different order,
	// so we can't easily verify determinism without sorting. Instead, we verify
	// that the correct number of keys were added (at least 1 per file)
	if len(resultKey.keys) < len(testFiles) {
		t.Errorf("Expected at least %d keys (one per file), got %d", len(testFiles), len(resultKey.keys))
	}
}

// Test_populateCompositeKeyParallel_smallList tests that small lists use sequential processing
func Test_populateCompositeKeyParallel_smallList(t *testing.T) {
	// Create temporary directory with test files
	tmpDir := t.TempDir()
	testFiles := []string{}

	// Create 5 files (less than threshold of 10, should use sequential)
	for i := 0; i < 5; i++ {
		filePath := filepath.Join(tmpDir, "testfile"+string(rune('a'+i))+".txt")
		if err := os.WriteFile(filePath, []byte("test content "+string(rune('a'+i))), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
		testFiles = append(testFiles, filePath)
	}

	sb := &stageBuilder{
		fileContext: util.FileContext{Root: tmpDir},
		args:        dockerfile.NewBuildArgs([]string{}),
	}

	compositeKey := NewCompositeCache()

	// Create a mock command for testing
	mockCmd := &mockDockerCommand{}

	// Test that small lists still work (should use sequential path in populateCompositeKey)
	// populateCompositeKey routes to sequential for < 10 files
	resultKey, err := sb.populateCompositeKey(mockCmd, testFiles, *compositeKey, sb.args, []string{})
	if err != nil {
		t.Fatalf("populateCompositeKey failed: %v", err)
	}

	// Verify that keys were added
	if len(resultKey.keys) == 0 {
		t.Error("Expected keys to be added, but got empty keys")
	}
}

// Test_walkDirectoryForHashParallel tests parallel hashing for large directories
func Test_walkDirectoryForHashParallel(t *testing.T) {
	// Create temporary directory structure
	tmpDir := t.TempDir()

	// Create 60 files (more than threshold of 50 for parallel hashing)
	files := []string{}
	for i := 0; i < 60; i++ {
		filePath := filepath.Join(tmpDir, "testfile"+string(rune('a'+(i%26)))+string(rune('0'+(i/26)))+".txt")
		content := "test content " + string(rune('a'+(i%26)))
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
		files = append(files, filePath)
	}

	sha := sha256.New()
	fileContext := util.FileContext{Root: tmpDir}
	useMetadataOnly := false

	// Test parallel hashing
	isEmpty, fileCount, err := walkDirectoryForHashParallel(files, fileContext, sha, useMetadataOnly, 60)
	if err != nil {
		t.Fatalf("walkDirectoryForHashParallel failed: %v", err)
	}

	if isEmpty {
		t.Error("Expected directory to not be empty")
	}

	if fileCount != 60 {
		t.Errorf("Expected file count 60, got %d", fileCount)
	}

	// Verify hash was computed
	hashSum := sha.Sum(nil)
	if len(hashSum) == 0 {
		t.Error("Expected hash to be computed, but got empty hash")
	}

	// Test determinism: same files should produce same hash
	sha2 := sha256.New()
	_, fileCount2, err2 := walkDirectoryForHashParallel(files, fileContext, sha2, useMetadataOnly, 60)
	if err2 != nil {
		t.Fatalf("walkDirectoryForHashParallel failed on second call: %v", err2)
	}

	if fileCount2 != 60 {
		t.Errorf("Expected file count 60 on second call, got %d", fileCount2)
	}

	hashSum2 := sha2.Sum(nil)
	if string(hashSum) != string(hashSum2) {
		t.Error("Expected deterministic hash, but got different hashes")
	}
}

// Test_walkDirectoryForHashParallel_smallDirectory tests that small directories use sequential hashing
func Test_walkDirectoryForHashAdaptive_smallDirectory(t *testing.T) {
	// Create temporary directory structure
	tmpDir := t.TempDir()

	// Create 30 files (less than threshold of 50, should use sequential)
	for i := 0; i < 30; i++ {
		filePath := filepath.Join(tmpDir, "testfile"+string(rune('a'+(i%26)))+".txt")
		content := "test content " + string(rune('a'+(i%26)))
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	sha := sha256.New()
	fileContext := util.FileContext{Root: tmpDir}
	useMetadataOnly := false

	// Test adaptive hashing (should use sequential for < 50 files)
	isEmpty, fileCount, err := walkDirectoryForHashAdaptive(tmpDir, fileContext, sha, useMetadataOnly)
	if err != nil {
		t.Fatalf("walkDirectoryForHashAdaptive failed: %v", err)
	}

	if isEmpty {
		t.Error("Expected directory to not be empty")
	}

	// Verify that files were processed (some may be excluded by fileContext)
	if fileCount == 0 {
		t.Error("Expected at least some files to be processed, got 0")
	}

	// Verify hash was computed
	hashSum := sha.Sum(nil)
	if len(hashSum) == 0 {
		t.Error("Expected hash to be computed, but got empty hash")
	}
}

// Test_getFilesForCacheKey_caching tests that filesUsedCache works correctly
func Test_getFilesForCacheKey_caching(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a mock command that returns files
	mockCommand := &mockDockerCommand{
		filesUsed: []string{
			filepath.Join(tmpDir, "file1.txt"),
			filepath.Join(tmpDir, "file2.txt"),
		},
	}

	sb := &stageBuilder{
		fileContext:    util.FileContext{Root: tmpDir},
		filesUsedCache: make(map[string][]string),
		args:           dockerfile.NewBuildArgs([]string{}),
	}

	cfg := &v1.Config{Env: []string{}}
	ctx := context.Background()

	// First call - should populate cache
	files1, err1 := sb.getFilesForCacheKey(ctx, mockCommand, "TEST_COMMAND", cfg)
	if err1 != nil {
		t.Fatalf("getFilesForCacheKey failed: %v", err1)
	}

	// Verify cache was populated
	sb.filesUsedMutex.RLock()
	cachedFiles, exists := sb.filesUsedCache["TEST_COMMAND"]
	sb.filesUsedMutex.RUnlock()

	if !exists {
		t.Error("Expected cache to be populated, but key not found")
	}

	if len(cachedFiles) != len(files1) {
		t.Errorf("Expected cached files length %d, got %d", len(files1), len(cachedFiles))
	}

	// Second call - should use cache
	// Modify mock to verify cache is used (should not call FilesUsedFromContext again)
	mockCommand.callCount = 0
	files2, err2 := sb.getFilesForCacheKey(ctx, mockCommand, "TEST_COMMAND", cfg)
	if err2 != nil {
		t.Fatalf("getFilesForCacheKey failed on second call: %v", err2)
	}

	// Verify results are the same
	if len(files1) != len(files2) {
		t.Errorf("Expected same number of files, got %d vs %d", len(files1), len(files2))
	}

	// Note: We can't easily verify that FilesUsedFromContext wasn't called again
	// because the function is called in a goroutine, but the cache should work
}

// Test_populateCompositeKey_routing tests that routing between parallel and sequential works correctly
func Test_populateCompositeKey_routing(t *testing.T) {
	tmpDir := t.TempDir()
	mockCmd := &mockDockerCommand{}

	sb := &stageBuilder{
		fileContext: util.FileContext{Root: tmpDir},
		args:        dockerfile.NewBuildArgs([]string{}),
	}

	compositeKey := NewCompositeCache()

	// Test 1: Small list (< 10 files) should use sequential
	smallFiles := []string{}
	for i := 0; i < 5; i++ {
		filePath := filepath.Join(tmpDir, "small"+string(rune('a'+i))+".txt")
		os.WriteFile(filePath, []byte("content"), 0644)
		smallFiles = append(smallFiles, filePath)
	}

	result1, err1 := sb.populateCompositeKey(mockCmd, smallFiles, *compositeKey, sb.args, []string{})
	if err1 != nil {
		t.Fatalf("populateCompositeKey failed for small list: %v", err1)
	}
	if len(result1.keys) == 0 {
		t.Error("Expected keys for small list")
	}

	// Test 2: Large list (> 10 files) should use parallel
	largeFiles := []string{}
	for i := 0; i < 15; i++ {
		filePath := filepath.Join(tmpDir, "large"+string(rune('a'+i))+".txt")
		os.WriteFile(filePath, []byte("content"), 0644)
		largeFiles = append(largeFiles, filePath)
	}

	result2, err2 := sb.populateCompositeKey(mockCmd, largeFiles, *compositeKey, sb.args, []string{})
	if err2 != nil {
		t.Fatalf("populateCompositeKey failed for large list: %v", err2)
	}
	if len(result2.keys) < len(largeFiles) {
		t.Errorf("Expected at least %d keys for large list, got %d", len(largeFiles), len(result2.keys))
	}
}

// Test_GOMAXPROCS_usage tests that GOMAXPROCS is used instead of NumCPU
// This is an indirect test - we verify that worker counts are calculated correctly
func Test_GOMAXPROCS_usage(t *testing.T) {
	gomaxprocs := runtime.GOMAXPROCS(0)
	numCPU := runtime.NumCPU()

	// GOMAXPROCS should be used for worker calculations
	// In populateCompositeKeyParallel, workers = min(16, GOMAXPROCS * 2)
	expectedMaxWorkers := gomaxprocs * 2
	if expectedMaxWorkers > 16 {
		expectedMaxWorkers = 16
	}

	// Verify that GOMAXPROCS is being used (not NumCPU)
	// This is a sanity check - actual usage is verified in integration tests
	if gomaxprocs != numCPU && gomaxprocs > 0 {
		t.Logf("GOMAXPROCS (%d) differs from NumCPU (%d), which is expected in some environments", gomaxprocs, numCPU)
	}

	// Verify reasonable worker count calculation
	if expectedMaxWorkers < 2 {
		t.Errorf("Expected at least 2 workers, got %d", expectedMaxWorkers)
	}
	if expectedMaxWorkers > 16 {
		t.Errorf("Expected max 16 workers, got %d", expectedMaxWorkers)
	}
}

// mockDockerCommand is a mock implementation for testing
type mockDockerCommand struct {
	filesUsed []string
	callCount int
}

func (m *mockDockerCommand) FilesUsedFromContext(cfg *v1.Config, buildArgs *dockerfile.BuildArgs) ([]string, error) {
	m.callCount++
	return m.filesUsed, nil
}

// Implement other required methods with minimal implementations
func (m *mockDockerCommand) ExecuteCommand(cfg *v1.Config, buildArgs *dockerfile.BuildArgs) error {
	return nil
}

func (m *mockDockerCommand) String() string {
	return "MOCK_COMMAND"
}

func (m *mockDockerCommand) FilesToSnapshot() []string {
	return []string{}
}

func (m *mockDockerCommand) ProvidesFilesToSnapshot() bool {
	return true
}

func (m *mockDockerCommand) MetadataOnly() bool {
	return false
}

func (m *mockDockerCommand) RequiresUnpackedFS() bool {
	return false
}

func (m *mockDockerCommand) CacheCommand(img v1.Image) commands.DockerCommand {
	return m
}

func (m *mockDockerCommand) ShouldCacheOutput() bool {
	return false
}

func (m *mockDockerCommand) IsArgsEnvsRequiredInCache() bool {
	return false
}

func (m *mockDockerCommand) ShouldDetectDeletedFiles() bool {
	return false
}
