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
	"testing"

	"github.com/Gosayram/kaniko/pkg/config"
)

func TestOptimizeForNoCache(t *testing.T) {
	// Test with cache disabled
	opts := &config.KanikoOptions{
		Cache: false,
	}

	optimizeForNoCache(opts)

	// Verify optimizations were applied
	if !opts.IncrementalSnapshots {
		t.Error("Expected IncrementalSnapshots to be enabled")
	}

	if opts.MaxParallelCommands == 0 {
		t.Error("Expected MaxParallelCommands to be set")
	}

	if !opts.EnableParallelExec {
		t.Error("Expected EnableParallelExec to be enabled")
	}

	if opts.SnapshotMode != "time" {
		t.Error("Expected SnapshotMode to be set to 'time'")
	}

	if opts.MaxMemoryUsageBytes == 0 {
		t.Error("Expected MaxMemoryUsageBytes to be set")
	}

	if !opts.MemoryMonitoring {
		t.Error("Expected MemoryMonitoring to be enabled")
	}

	if opts.GCThreshold == 0 {
		t.Error("Expected GCThreshold to be set")
	}

	if opts.CommandTimeout == 0 {
		t.Error("Expected CommandTimeout to be set")
	}

	if opts.ImageFSExtractRetry == 0 {
		t.Error("Expected ImageFSExtractRetry to be set")
	}

	if opts.MaxFileSizeBytes == 0 {
		t.Error("Expected MaxFileSizeBytes to be set")
	}

	if opts.MaxTotalFileSizeBytes == 0 {
		t.Error("Expected MaxTotalFileSizeBytes to be set")
	}
}

func TestOptimizeForNoCacheWithCacheEnabled(t *testing.T) {
	// Test with cache enabled - should not apply no-cache optimizations
	opts := &config.KanikoOptions{
		Cache: true,
	}

	originalIncrementalSnapshots := opts.IncrementalSnapshots
	originalMaxParallelCommands := opts.MaxParallelCommands

	// Use applyComprehensiveOptimizations which properly handles cache logic
	applyComprehensiveOptimizations(opts)

	// Verify no-cache optimizations were NOT applied when cache is enabled
	if opts.IncrementalSnapshots != originalIncrementalSnapshots {
		t.Error("Expected IncrementalSnapshots to remain unchanged when cache is enabled")
	}

	if opts.MaxParallelCommands != originalMaxParallelCommands {
		t.Error("Expected MaxParallelCommands to remain unchanged when cache is enabled")
	}

	// But other optimizations should still be applied
	if opts.Compression != "zstd" {
		t.Error("Expected Compression to be set to 'zstd' even with cache enabled")
	}

	if opts.CompressionLevel != 3 {
		t.Error("Expected CompressionLevel to be set to 3 even with cache enabled")
	}
}

func TestOptimizePerformance(t *testing.T) {
	opts := &config.KanikoOptions{}

	optimizePerformance(opts)

	// Verify performance optimizations were applied
	if opts.Compression != "zstd" {
		t.Error("Expected Compression to be set to 'zstd'")
	}

	if opts.CompressionLevel != 3 {
		t.Error("Expected CompressionLevel to be set to 3")
	}

	if !opts.CompressedCaching {
		t.Error("Expected CompressedCaching to be enabled")
	}

	if opts.MonitoringInterval != 5 {
		t.Error("Expected MonitoringInterval to be set to 5")
	}

	if !opts.IntegrityCheck {
		t.Error("Expected IntegrityCheck to be enabled")
	}

	if opts.MaxExpectedChanges != 1000 {
		t.Error("Expected MaxExpectedChanges to be set to 1000")
	}

	if !opts.FullScanBackup {
		t.Error("Expected FullScanBackup to be enabled")
	}
}

func TestOptimizeNetwork(t *testing.T) {
	opts := &config.KanikoOptions{}

	optimizeNetwork(opts)

	// Verify network optimizations were applied
	if opts.PushRetry != 3 {
		t.Error("Expected PushRetry to be set to 3")
	}

	if opts.PushRetryInitialDelay != 1000 {
		t.Error("Expected PushRetryInitialDelay to be set to 1000")
	}

	if opts.PushRetryMaxDelay != 30000 {
		t.Error("Expected PushRetryMaxDelay to be set to 30000")
	}

	if opts.PushRetryBackoffMultiplier != 2.0 {
		t.Error("Expected PushRetryBackoffMultiplier to be set to 2.0")
	}

	if opts.ImageDownloadRetry != 3 {
		t.Error("Expected ImageDownloadRetry to be set to 3")
	}

	if !opts.PushIgnoreImmutableTagErrors {
		t.Error("Expected PushIgnoreImmutableTagErrors to be enabled")
	}
}

func TestOptimizeForNoCacheWithExistingSettings(t *testing.T) {
	// Test that existing settings are not overridden
	opts := &config.KanikoOptions{
		Cache:                 false,
		IncrementalSnapshots:  true,                   // Already enabled
		MaxParallelCommands:   4,                      // Already set
		SnapshotMode:          "full",                 // Already set
		MaxMemoryUsageBytes:   1024 * 1024 * 1024,     // Already set (1GB)
		MemoryMonitoring:      true,                   // Already enabled
		GCThreshold:           70,                     // Already set
		CommandTimeout:        15 * 60,                // Already set (15 minutes)
		ImageFSExtractRetry:   5,                      // Already set
		MaxFileSizeBytes:      100 * 1024 * 1024,      // Already set (100MB)
		MaxTotalFileSizeBytes: 5 * 1024 * 1024 * 1024, // Already set (5GB)
	}

	optimizeForNoCache(opts)

	// Verify existing settings were preserved
	if !opts.IncrementalSnapshots {
		t.Error("Expected IncrementalSnapshots to remain enabled")
	}

	if opts.MaxParallelCommands != 4 {
		t.Error("Expected MaxParallelCommands to remain 4")
	}

	if opts.SnapshotMode != "full" {
		t.Error("Expected SnapshotMode to remain 'full'")
	}

	if opts.MaxMemoryUsageBytes != 1024*1024*1024 {
		t.Error("Expected MaxMemoryUsageBytes to remain 1GB")
	}

	if !opts.MemoryMonitoring {
		t.Error("Expected MemoryMonitoring to remain enabled")
	}

	if opts.GCThreshold != 70 {
		t.Error("Expected GCThreshold to remain 70")
	}

	if opts.CommandTimeout != 15*60 {
		t.Error("Expected CommandTimeout to remain 15 minutes")
	}

	if opts.ImageFSExtractRetry != 5 {
		t.Error("Expected ImageFSExtractRetry to remain 5")
	}

	if opts.MaxFileSizeBytes != 100*1024*1024 {
		t.Error("Expected MaxFileSizeBytes to remain 100MB")
	}

	if opts.MaxTotalFileSizeBytes != 5*1024*1024*1024 {
		t.Error("Expected MaxTotalFileSizeBytes to remain 5GB")
	}
}

func TestOptimizeFilesystem(t *testing.T) {
	opts := &config.KanikoOptions{}

	optimizeFilesystem(opts)

	// Verify filesystem optimizations were applied
	if opts.SnapshotMode != "time" {
		t.Error("Expected SnapshotMode to be set to 'time'")
	}

	if !opts.IncrementalSnapshots {
		t.Error("Expected IncrementalSnapshots to be enabled")
	}

	if opts.MaxExpectedChanges != 5000 {
		t.Error("Expected MaxExpectedChanges to be set to 5000")
	}

	if !opts.IntegrityCheck {
		t.Error("Expected IntegrityCheck to be enabled")
	}

	if !opts.FullScanBackup {
		t.Error("Expected FullScanBackup to be enabled")
	}

	if opts.MaxFileSizeBytes != 500*1024*1024 {
		t.Error("Expected MaxFileSizeBytes to be set to 500MB")
	}

	if opts.MaxTotalFileSizeBytes != 10*1024*1024*1024 {
		t.Error("Expected MaxTotalFileSizeBytes to be set to 10GB")
	}

	if !opts.CompressedCaching {
		t.Error("Expected CompressedCaching to be enabled")
	}

	if opts.Compression != "zstd" {
		t.Error("Expected Compression to be set to 'zstd'")
	}

	if opts.CompressionLevel != 3 {
		t.Error("Expected CompressionLevel to be set to 3")
	}
}

func TestOptimizeFilesystemWithExistingSettings(t *testing.T) {
	// Test that existing settings are not overridden
	opts := &config.KanikoOptions{
		SnapshotMode:          "full",                 // Already set
		IncrementalSnapshots:  true,                   // Already enabled
		MaxExpectedChanges:    1000,                   // Already set
		IntegrityCheck:        true,                   // Already enabled
		FullScanBackup:        true,                   // Already enabled
		MaxFileSizeBytes:      100 * 1024 * 1024,      // Already set (100MB)
		MaxTotalFileSizeBytes: 5 * 1024 * 1024 * 1024, // Already set (5GB)
		CompressedCaching:     true,                   // Already enabled
		Compression:           "gzip",                 // Already set
		CompressionLevel:      6,                      // Already set
	}

	optimizeFilesystem(opts)

	// Verify existing settings were preserved
	if opts.SnapshotMode != "full" {
		t.Error("Expected SnapshotMode to remain 'full'")
	}

	if !opts.IncrementalSnapshots {
		t.Error("Expected IncrementalSnapshots to remain enabled")
	}

	if opts.MaxExpectedChanges != 1000 {
		t.Error("Expected MaxExpectedChanges to remain 1000")
	}

	if !opts.IntegrityCheck {
		t.Error("Expected IntegrityCheck to remain enabled")
	}

	if !opts.FullScanBackup {
		t.Error("Expected FullScanBackup to remain enabled")
	}

	if opts.MaxFileSizeBytes != 100*1024*1024 {
		t.Error("Expected MaxFileSizeBytes to remain 100MB")
	}

	if opts.MaxTotalFileSizeBytes != 5*1024*1024*1024 {
		t.Error("Expected MaxTotalFileSizeBytes to remain 5GB")
	}

	if !opts.CompressedCaching {
		t.Error("Expected CompressedCaching to remain enabled")
	}

	if opts.Compression != "gzip" {
		t.Error("Expected Compression to remain 'gzip'")
	}

	if opts.CompressionLevel != 6 {
		t.Error("Expected CompressionLevel to remain 6")
	}
}

func TestApplyComprehensiveOptimizations(t *testing.T) {
	// Test with cache disabled
	opts := &config.KanikoOptions{
		Cache: false,
	}

	applyComprehensiveOptimizations(opts)

	// Verify all optimizations were applied
	if !opts.IncrementalSnapshots {
		t.Error("Expected IncrementalSnapshots to be enabled")
	}

	if opts.MaxParallelCommands == 0 {
		t.Error("Expected MaxParallelCommands to be set")
	}

	if opts.Compression != "zstd" {
		t.Error("Expected Compression to be set to 'zstd'")
	}

	if opts.CompressionLevel != 3 {
		t.Error("Expected CompressionLevel to be set to 3")
	}

	if opts.PushRetry == 0 {
		t.Error("Expected PushRetry to be set")
	}

	if opts.SnapshotMode != "time" {
		t.Error("Expected SnapshotMode to be set to 'time'")
	}

	if !opts.IntegrityCheck {
		t.Error("Expected IntegrityCheck to be enabled")
	}
}

func TestApplyComprehensiveOptimizationsWithCache(t *testing.T) {
	// Test with cache enabled
	opts := &config.KanikoOptions{
		Cache: true,
	}

	applyComprehensiveOptimizations(opts)

	// Verify optimizations were applied but no-cache specific ones were skipped
	if opts.Compression != "zstd" {
		t.Error("Expected Compression to be set to 'zstd'")
	}

	if opts.CompressionLevel != 3 {
		t.Error("Expected CompressionLevel to be set to 3")
	}

	if opts.PushRetry == 0 {
		t.Error("Expected PushRetry to be set")
	}

	if opts.SnapshotMode != "time" {
		t.Error("Expected SnapshotMode to be set to 'time'")
	}

	if !opts.IntegrityCheck {
		t.Error("Expected IntegrityCheck to be enabled")
	}
}

func TestValidateOptimizations(t *testing.T) {
	// Test with properly configured options
	opts := &config.KanikoOptions{
		Cache:                false,
		IncrementalSnapshots: true,
		MaxParallelCommands:  4,
		Compression:          "zstd",
		CompressionLevel:     3,
		SnapshotMode:         "time",
		IntegrityCheck:       true,
	}
	opts.PushRetry = 3
	opts.ImageDownloadRetry = 3

	// This should not produce any warnings
	validateOptimizations(opts)
}

func TestValidateOptimizationsWithWarnings(t *testing.T) {
	// Test with missing configurations
	opts := &config.KanikoOptions{
		Cache: false,
		// Missing IncrementalSnapshots
		// Missing MaxParallelCommands
		// Missing Compression
		// Missing CompressionLevel
		// Missing PushRetry
		// Missing ImageDownloadRetry
		// Missing SnapshotMode
		// Missing IntegrityCheck
	}

	// This should produce warnings
	validateOptimizations(opts)
}
