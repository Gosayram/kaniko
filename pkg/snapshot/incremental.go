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

package snapshot

import (
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Constants for incremental snapshotter
const (
	DefaultMaxExpectedChanges = 1000
	DefaultScanCountThreshold = 100
	DefaultFullScanInterval   = 24 * time.Hour
)

// FileInfo holds metadata about a file for caching
type FileInfo struct {
	Path     string
	Size     int64
	ModTime  time.Time
	Mode     os.FileMode
	Hash     string
	Checksum string
}

// IncrementalSnapshotter provides safe incremental snapshots with integrity checks
type IncrementalSnapshotter struct {
	// Core components
	baseSnapshotter *Snapshotter
	fileCache       map[string]FileInfo
	lastScanTime    time.Time

	// Integrity and safety
	integrityCheck     bool
	fullScanBackup     bool
	maxExpectedChanges int

	// Thread safety
	mutex sync.RWMutex

	// Performance tracking
	scanCount    int
	lastFullScan time.Time
}

// NewIncrementalSnapshotter creates a new incremental snapshotter
func NewIncrementalSnapshotter(baseSnapshotter *Snapshotter) *IncrementalSnapshotter {
	return &IncrementalSnapshotter{
		baseSnapshotter:    baseSnapshotter,
		fileCache:          make(map[string]FileInfo),
		integrityCheck:     true,
		fullScanBackup:     true,
		maxExpectedChanges: DefaultMaxExpectedChanges, // Configurable threshold
		lastFullScan:       time.Now(),
	}
}

// SafeDetectChanges safely detects file changes with integrity verification
func (s *IncrementalSnapshotter) SafeDetectChanges() ([]string, error) {
	logrus.Debugf("🔍 Starting safe incremental change detection")

	// 1. Incremental check (fast path)
	incrementalChanges, err := s.detectIncrementalChanges()
	if err != nil {
		logrus.Warnf("❌ Incremental detection failed: %v", err)
		return s.fallbackToFullScan()
	}

	// 2. Integrity verification (critical)
	if s.needsIntegrityCheck(incrementalChanges) {
		logrus.Warnf("⚠️ Integrity concerns detected, falling back to full scan")
		return s.fallbackToFullScan()
	}

	logrus.Debugf("✅ Incremental detection successful: %d changes", len(incrementalChanges))
	return incrementalChanges, nil
}

// detectIncrementalChanges performs fast incremental change detection
func (s *IncrementalSnapshotter) detectIncrementalChanges() ([]string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var changedFiles []string
	currentTime := time.Now()

	// Check cached files for changes
	for path, fileInfo := range s.fileCache {
		// Check if file still exists
		if _, err := os.Stat(path); os.IsNotExist(err) {
			// File was deleted
			changedFiles = append(changedFiles, path)
			logrus.Debugf("📄 File deleted: %s", path)
			continue
		}

		// Check modification time
		stat, err := os.Stat(path)
		if err != nil {
			logrus.Debugf("❌ Error checking file %s: %v", path, err)
			continue
		}

		// File was modified
		if stat.ModTime().After(fileInfo.ModTime) || stat.Size() != fileInfo.Size {
			changedFiles = append(changedFiles, path)
			logrus.Debugf("📄 File modified: %s (size: %d->%d, mtime: %v->%v)",
				path, fileInfo.Size, stat.Size(), fileInfo.ModTime, stat.ModTime())
		}
	}

	// Update cache with current file info
	s.updateFileCache(changedFiles)
	s.lastScanTime = currentTime
	s.scanCount++

	return changedFiles, nil
}

// needsIntegrityCheck determines if a full scan is needed for integrity
func (s *IncrementalSnapshotter) needsIntegrityCheck(changedFiles []string) bool {
	// Too many changes - might indicate a problem
	if len(changedFiles) > s.maxExpectedChanges {
		logrus.Warnf("⚠️ Too many changes detected: %d (max: %d)", len(changedFiles), s.maxExpectedChanges)
		return true
	}

	// Check for suspicious patterns
	for _, file := range changedFiles {
		if s.isCriticalSystemFile(file) {
			logrus.Warnf("⚠️ Critical system file changed: %s", file)
			return true
		}
	}

	// Force full scan periodically for safety
	timeSinceLastFullScan := time.Since(s.lastFullScan)
	if timeSinceLastFullScan > 24*time.Hour {
		logrus.Infof("🔄 Periodic full scan due to time elapsed: %v", timeSinceLastFullScan)
		return true
	}

	// Force full scan after many incremental scans
	if s.scanCount > DefaultScanCountThreshold {
		logrus.Infof("🔄 Periodic full scan due to scan count: %d", s.scanCount)
		return true
	}

	return false
}

// isCriticalSystemFile checks if a file is critical for system integrity
func (s *IncrementalSnapshotter) isCriticalSystemFile(file string) bool {
	criticalPaths := []string{
		"/etc/passwd",
		"/etc/group",
		"/etc/shadow",
		"/etc/hosts",
		"/etc/hostname",
		"/proc/",
		"/sys/",
		"/dev/",
	}

	for _, criticalPath := range criticalPaths {
		if strings.HasPrefix(file, criticalPath) {
			return true
		}
	}

	return false
}

// fallbackToFullScan performs a full filesystem scan as fallback
func (s *IncrementalSnapshotter) fallbackToFullScan() ([]string, error) {
	logrus.Infof("🔄 Performing full filesystem scan for integrity")

	// Use the base snapshotter's full scan
	filesToAdd, _, err := s.baseSnapshotter.scanFullFilesystem()
	if err != nil {
		return nil, err
	}

	// Update cache with all files
	s.mutex.Lock()
	s.fileCache = make(map[string]FileInfo)
	s.updateFileCache(filesToAdd)
	s.lastFullScan = time.Now()
	s.scanCount = 0
	s.mutex.Unlock()

	logrus.Infof("✅ Full scan completed: %d files", len(filesToAdd))
	return filesToAdd, nil
}

// updateFileCache updates the file cache with current file information
func (s *IncrementalSnapshotter) updateFileCache(files []string) {
	for _, file := range files {
		stat, err := os.Stat(file)
		if err != nil {
			logrus.Debugf("❌ Error updating cache for %s: %v", file, err)
			continue
		}

		s.fileCache[file] = FileInfo{
			Path:    file,
			Size:    stat.Size(),
			ModTime: stat.ModTime(),
			Mode:    stat.Mode(),
		}
	}
}

// TakeIncrementalSnapshot takes an incremental snapshot with safety checks
func (s *IncrementalSnapshotter) TakeIncrementalSnapshot() (string, error) {
	logrus.Debugf("📸 Taking incremental snapshot")

	// 1. Safe change detection
	changedFiles, err := s.SafeDetectChanges()
	if err != nil {
		return "", err
	}

	// 2. If no changes, return empty result
	if len(changedFiles) == 0 {
		logrus.Info("📸 No files changed, skipping incremental snapshot")
		return "", nil
	}

	// 3. Use base snapshotter to create tarball with only changed files
	return s.baseSnapshotter.TakeSnapshot(changedFiles, true, false)
}

// GetCacheStats returns statistics about the file cache
func (s *IncrementalSnapshotter) GetCacheStats() map[string]interface{} {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return map[string]interface{}{
		"cached_files":     len(s.fileCache),
		"scan_count":       s.scanCount,
		"last_scan_time":   s.lastScanTime,
		"last_full_scan":   s.lastFullScan,
		"integrity_check":  s.integrityCheck,
		"full_scan_backup": s.fullScanBackup,
	}
}

// ClearCache clears the file cache (useful for testing or memory management)
func (s *IncrementalSnapshotter) ClearCache() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.fileCache = make(map[string]FileInfo)
	s.scanCount = 0
	s.lastScanTime = time.Time{}

	logrus.Info("🧹 File cache cleared")
}
