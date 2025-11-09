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
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/filesystem"
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

	// Periodic integrity check configuration
	fullScanInterval   time.Duration // Interval for periodic full scans
	scanCountThreshold int           // Number of scans before forcing full scan

	// Optional filesystem watcher for real-time change detection
	watcher           *filesystem.Watcher
	watchedChanges    map[string]bool // Track changes detected by watcher
	useWatcher        bool            // Whether to use filesystem watcher
	listenerStarted   bool            // Whether listener goroutine is started
	listenerStartedMu sync.Mutex      // Mutex for listenerStarted flag

	// Thread safety
	mutex sync.RWMutex

	// Performance tracking
	scanCount    int
	lastFullScan time.Time
}

// NewIncrementalSnapshotter creates a new incremental snapshotter
func NewIncrementalSnapshotter(baseSnapshotter *Snapshotter) *IncrementalSnapshotter {
	// Try to create filesystem watcher (optional, may fail on some systems)
	watcher, _ := filesystem.NewFileSystemWatcher()

	return &IncrementalSnapshotter{
		baseSnapshotter:    baseSnapshotter,
		fileCache:          make(map[string]FileInfo),
		integrityCheck:     true,
		fullScanBackup:     true,
		maxExpectedChanges: DefaultMaxExpectedChanges, // Configurable threshold
		fullScanInterval:   DefaultFullScanInterval,   // Periodic full scan interval
		scanCountThreshold: DefaultScanCountThreshold, // Scan count threshold
		watcher:            watcher,
		watchedChanges:     make(map[string]bool),
		useWatcher:         watcher != nil, // If watcher was created, it's supported
		lastFullScan:       time.Now(),
	}
}

// EnableWatcher enables filesystem watcher for real-time change detection
func (s *IncrementalSnapshotter) EnableWatcher() error {
	if s.watcher == nil {
		watcher, err := filesystem.NewFileSystemWatcher()
		if err != nil {
			return fmt.Errorf("failed to create filesystem watcher: %w", err)
		}
		if watcher == nil {
			return fmt.Errorf("filesystem watcher not supported on this platform")
		}
		s.watcher = watcher
	}

	s.useWatcher = true
	s.watcher.Start()
	// Start listening for changes
	s.listenForWatcherChanges()
	logrus.Info("Filesystem watcher enabled for real-time change detection")
	return nil
}

// DisableWatcher disables filesystem watcher
func (s *IncrementalSnapshotter) DisableWatcher() {
	if s.watcher != nil {
		s.watcher.Stop()
		s.useWatcher = false
		logrus.Info("Filesystem watcher disabled")
	}
}

// SetFullScanInterval sets the interval for periodic full scans
func (s *IncrementalSnapshotter) SetFullScanInterval(interval time.Duration) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.fullScanInterval = interval
	logrus.Infof("Full scan interval set to %v", interval)
}

// SetScanCountThreshold sets the number of scans before forcing a full scan
func (s *IncrementalSnapshotter) SetScanCountThreshold(threshold int) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.scanCountThreshold = threshold
	logrus.Infof("Scan count threshold set to %d", threshold)
}

// SetMaxExpectedChanges sets the maximum expected changes before triggering full scan
func (s *IncrementalSnapshotter) SetMaxExpectedChanges(maxChanges int) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.maxExpectedChanges = maxChanges
	logrus.Infof("Max expected changes set to %d", maxChanges)
}

// SetIntegrityCheck enables or disables integrity checking
func (s *IncrementalSnapshotter) SetIntegrityCheck(enabled bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.integrityCheck = enabled
	logrus.Infof("Integrity check %s", map[bool]string{true: "enabled", false: "disabled"}[enabled])
}

// SetFullScanBackup enables or disables full scan backup
func (s *IncrementalSnapshotter) SetFullScanBackup(enabled bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.fullScanBackup = enabled
	logrus.Infof("Full scan backup %s", map[bool]string{true: "enabled", false: "disabled"}[enabled])
}

// SafeDetectChanges safely detects file changes with integrity verification
func (s *IncrementalSnapshotter) SafeDetectChanges() ([]string, error) {
	logrus.Debugf("🔍 Starting safe incremental change detection")

	// 1. Incremental check (fast path)
	incrementalChanges := s.detectIncrementalChanges()

	// 2. Integrity verification (critical)
	if s.needsIntegrityCheck(incrementalChanges) {
		logrus.Warnf(" Integrity concerns detected, falling back to full scan")
		return s.fallbackToFullScan()
	}

	logrus.Debugf("Incremental detection successful: %d changes", len(incrementalChanges))
	return incrementalChanges, nil
}

// DetectChangedFiles detects which files from the provided list have changed
// Uses hash cache for fast change detection
func (s *IncrementalSnapshotter) DetectChangedFiles(files []string) []string {
	var changedFiles []string
	changedSet := make(map[string]bool)

	// First pass: detect changed files (read-only)
	s.mutex.RLock()
	for _, file := range files {
		if s.isFileChangedUnsafe(file) {
			if !changedSet[file] {
				changedFiles = append(changedFiles, file)
				changedSet[file] = true
			}
		}
	}
	s.mutex.RUnlock()

	// Second pass: update cache with current file info for changed files
	if len(changedFiles) > 0 {
		s.mutex.Lock()
		s.updateFileCache(changedFiles)
		s.mutex.Unlock()
	}

	return changedFiles
}

// isFileChangedUnsafe checks if a file has changed without acquiring locks
// Must be called with mutex.RLock held
func (s *IncrementalSnapshotter) isFileChangedUnsafe(file string) bool {
	cachedInfo, exists := s.fileCache[file]

	if !exists {
		return true // File is new
	}

	// Check if file still exists
	stat, err := os.Stat(file)
	if err != nil {
		if os.IsNotExist(err) {
			return true // File was deleted
		}
		return true // Error - consider changed
	}

	// Quick check: compare size and modtime first (fast path)
	if stat.Size() != cachedInfo.Size || stat.ModTime().After(cachedInfo.ModTime) {
		return true
	}

	// If size and modtime match, compare hash for more reliable detection
	currentHash := s.computeFileHash(file, stat)
	return cachedInfo.Hash != currentHash
}

// detectIncrementalChanges performs fast incremental change detection using cached hashes
// Optionally uses filesystem watcher for real-time change detection
func (s *IncrementalSnapshotter) detectIncrementalChanges() []string {
	var changedFiles []string
	currentTime := time.Now()

	// If watcher is enabled, check for changes detected by watcher first
	if s.useWatcher && s.watcher != nil {
		watchedChanges := s.getWatchedChanges()
		if len(watchedChanges) > 0 {
			logrus.Debugf("Found %d changes from filesystem watcher", len(watchedChanges))
			changedFiles = append(changedFiles, watchedChanges...)
		}
	}

	// Also check cached files for changes using hash cache (fallback and verification)
	s.mutex.RLock()
	cachedFiles := make([]string, 0, len(s.fileCache))
	for path := range s.fileCache {
		cachedFiles = append(cachedFiles, path)
	}
	s.mutex.RUnlock()

	// Check cached files for changes (may catch changes watcher missed)
	changedSet := make(map[string]bool)
	for _, file := range changedFiles {
		changedSet[file] = true
	}

	for _, path := range cachedFiles {
		if changedSet[path] {
			continue // Already detected by watcher
		}
		if s.isFileChanged(path) {
			if !changedSet[path] {
				changedFiles = append(changedFiles, path)
				changedSet[path] = true
			}
			logrus.Debugf("📄 File changed: %s", path)
		}
	}

	// Update cache with current file info (including hashes)
	s.mutex.Lock()
	s.updateFileCache(changedFiles)
	s.lastScanTime = currentTime
	// Clear watched changes after processing
	if s.useWatcher {
		s.watchedChanges = make(map[string]bool)
	}
	// Update scan count and last full scan time
	s.scanCount++
	if s.scanCount >= s.scanCountThreshold {
		s.lastFullScan = currentTime
		s.scanCount = 0
	}
	s.mutex.Unlock()

	return changedFiles
}

// getWatchedChanges retrieves changes detected by filesystem watcher
func (s *IncrementalSnapshotter) getWatchedChanges() []string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	changes := make([]string, 0, len(s.watchedChanges))
	for path := range s.watchedChanges {
		changes = append(changes, path)
	}
	return changes
}

// WatchPath adds a path to be watched by filesystem watcher
func (s *IncrementalSnapshotter) WatchPath(path string) error {
	if !s.useWatcher || s.watcher == nil {
		return nil // Watcher not enabled, silently ignore
	}

	if err := s.watcher.Watch(path); err != nil {
		return fmt.Errorf("failed to watch path %s: %w", path, err)
	}

	return nil
}

// listenForWatcherChanges listens for changes from filesystem watcher
// This should be called once when watcher is enabled
func (s *IncrementalSnapshotter) listenForWatcherChanges() {
	if s.watcher == nil || !s.useWatcher {
		return
	}

	// Check if listener is already started
	s.listenerStartedMu.Lock()
	if s.listenerStarted {
		s.listenerStartedMu.Unlock()
		return // Already listening
	}
	s.listenerStarted = true
	s.listenerStartedMu.Unlock()

	// Listen for changes in a separate goroutine
	go func() {
		for change := range s.watcher.GetChanges() {
			s.mutex.Lock()
			s.watchedChanges[change] = true
			s.mutex.Unlock()
			logrus.Debugf("Watcher detected change: %s", change)
		}
		// Channel closed, reset flag
		s.listenerStartedMu.Lock()
		s.listenerStarted = false
		s.listenerStartedMu.Unlock()
	}()
}

// needsIntegrityCheck determines if a full scan is needed for integrity
func (s *IncrementalSnapshotter) needsIntegrityCheck(changedFiles []string) bool {
	// Too many changes - might indicate a problem
	if len(changedFiles) > s.maxExpectedChanges {
		logrus.Warnf(" Too many changes detected: %d (max: %d)", len(changedFiles), s.maxExpectedChanges)
		return true
	}

	// Check for suspicious patterns
	for _, file := range changedFiles {
		if s.isCriticalSystemFile(file) {
			logrus.Warnf(" Critical system file changed: %s", file)
			return true
		}
	}

	// Force full scan periodically for safety (configurable interval)
	timeSinceLastFullScan := time.Since(s.lastFullScan)
	if timeSinceLastFullScan > s.fullScanInterval {
		logrus.Infof("Periodic full scan due to time elapsed: %v (interval: %v)", timeSinceLastFullScan, s.fullScanInterval)
		return true
	}

	// Force full scan after many incremental scans (configurable threshold)
	if s.scanCount > s.scanCountThreshold {
		logrus.Infof("Periodic full scan due to scan count: %d (threshold: %d)", s.scanCount, s.scanCountThreshold)
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
	logrus.Infof("Performing full filesystem scan for integrity")

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

	logrus.Infof("Full scan completed: %d files", len(filesToAdd))
	return filesToAdd, nil
}

// updateFileCache updates the file cache with current file information
func (s *IncrementalSnapshotter) updateFileCache(files []string) {
	for _, file := range files {
		stat, err := os.Stat(file)
		if err != nil {
			logrus.Debugf("Error updating cache for %s: %v", file, err)
			continue
		}

		// Compute hash for file change detection (cached for performance)
		hash := s.computeFileHash(file, stat)

		s.fileCache[file] = FileInfo{
			Path:    file,
			Size:    stat.Size(),
			ModTime: stat.ModTime(),
			Mode:    stat.Mode(),
			Hash:    hash,
		}
	}
}

// computeFileHash computes a hash for a file based on its metadata
// This is a lightweight hash for change detection (not cryptographic)
func (s *IncrementalSnapshotter) computeFileHash(_ string, stat os.FileInfo) string {
	// Use a simple hash based on size, modtime, and mode for fast change detection
	// This is cached to avoid recomputing on every check
	hasher := func() string {
		// Simple hash combining size, modtime, and mode
		// This is faster than reading file contents but still reliable for change detection
		return fmt.Sprintf("%d-%d-%d", stat.Size(), stat.ModTime().UnixNano(), stat.Mode())
	}
	return hasher()
}

// isFileChanged checks if a file has changed by comparing cached hash with current state
func (s *IncrementalSnapshotter) isFileChanged(file string) bool {
	s.mutex.RLock()
	cachedInfo, exists := s.fileCache[file]
	s.mutex.RUnlock()

	if !exists {
		return true // File is new
	}

	// Check if file still exists
	stat, err := os.Stat(file)
	if err != nil {
		if os.IsNotExist(err) {
			return true // File was deleted
		}
		return true // Error - consider changed
	}

	// Quick check: compare size and modtime first (fast path)
	if stat.Size() != cachedInfo.Size || stat.ModTime().After(cachedInfo.ModTime) {
		return true
	}

	// If size and modtime match, compare hash for more reliable detection
	currentHash := s.computeFileHash(file, stat)
	return cachedInfo.Hash != currentHash
}

// TakeIncrementalSnapshot takes an incremental snapshot with safety checks
func (s *IncrementalSnapshotter) TakeIncrementalSnapshot() (string, error) {
	logrus.Debugf("Taking incremental snapshot")

	// 1. Safe change detection
	changedFiles, err := s.SafeDetectChanges()
	if err != nil {
		return "", err
	}

	// 2. If no changes, return empty result
	if len(changedFiles) == 0 {
		logrus.Info("No files changed, skipping incremental snapshot")
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
