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

package snapshot

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Constants for incremental snapshots
const (
	DefaultScanInterval = 5 * time.Second
	BufferSize64KB      = 64 * 1024
	FilePerm600         = 0o600
)

// IncrementalSnapshotter provides efficient incremental filesystem scanning
type IncrementalSnapshotter struct {
	directory    string
	lastSnapshot map[string]FileInfo
	ignoreList   []string
	mutex        sync.RWMutex
	cacheFile    string
	lastScanTime time.Time
	scanInterval time.Duration
}

// FileInfo represents cached file information
type FileInfo struct {
	Path     string      `json:"path"`
	Size     int64       `json:"size"`
	ModTime  time.Time   `json:"mod_time"`
	Mode     os.FileMode `json:"mode"`
	Checksum string      `json:"checksum"`
}

// NewIncrementalSnapshotter creates a new incremental snapshotter
func NewIncrementalSnapshotter(directory string, ignoreList []string) *IncrementalSnapshotter {
	return &IncrementalSnapshotter{
		directory:    directory,
		ignoreList:   ignoreList,
		lastSnapshot: make(map[string]FileInfo),
		cacheFile:    filepath.Join(directory, ".kaniko_snapshot_cache"),
		scanInterval: DefaultScanInterval, // Minimum interval between scans
	}
}

// TakeIncrementalSnapshot creates a snapshot of only changed files
func (s *IncrementalSnapshotter) TakeIncrementalSnapshot() (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check if enough time has passed since last scan
	if time.Since(s.lastScanTime) < s.scanInterval {
		logrus.Debugf("Skipping incremental scan - too soon (last scan: %v)", s.lastScanTime)
		return "", nil
	}

	// Load previous snapshot if available
	if err := s.loadLastSnapshot(); err != nil {
		logrus.Warnf("Failed to load last snapshot: %v", err)
		s.lastSnapshot = make(map[string]FileInfo)
	}

	// Detect changes
	changedFiles, deletedFiles, err := s.detectChanges()
	if err != nil {
		return "", fmt.Errorf("failed to detect changes: %w", err)
	}

	// If no changes, return empty result
	if len(changedFiles) == 0 && len(deletedFiles) == 0 {
		logrus.Debugf("No changes detected in incremental scan")
		s.lastScanTime = time.Now()
		return "", nil
	}

	logrus.Infof("Incremental scan found %d changed files, %d deleted files",
		len(changedFiles), len(deletedFiles))

	// Create snapshot of changes
	snapshotPath, err := s.createChangeSnapshot(changedFiles, deletedFiles)
	if err != nil {
		return "", fmt.Errorf("failed to create change snapshot: %w", err)
	}

	// Update cache
	s.updateSnapshotCache(changedFiles, deletedFiles)
	s.lastScanTime = time.Now()

	return snapshotPath, nil
}

// detectChanges finds files that have changed since last snapshot
func (s *IncrementalSnapshotter) detectChanges() (added, modified []string, err error) {
	var changedFiles []string
	var deletedFiles []string

	// Walk through directory
	walkErr := filepath.Walk(s.directory, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		// Skip if in ignore list
		if s.isIgnored(path) {
			return nil
		}

		// Get relative path
		relPath, err := filepath.Rel(s.directory, path)
		if err != nil {
			return err
		}

		// Skip root directory
		if relPath == "." {
			return nil
		}

		// Check if file was deleted
		if _, exists := s.lastSnapshot[relPath]; exists {
			// File was in last snapshot, check if it still exists
			if info == nil {
				deletedFiles = append(deletedFiles, relPath)
				return nil
			}
		}

		// Check if file is new or changed
		if s.isFileChanged(relPath, info) {
			changedFiles = append(changedFiles, relPath)
		}

		return nil
	})

	return changedFiles, deletedFiles, walkErr
}

// isFileChanged checks if a file has changed since last snapshot
func (s *IncrementalSnapshotter) isFileChanged(relPath string, info os.FileInfo) bool {
	lastInfo, exists := s.lastSnapshot[relPath]
	if !exists {
		// New file
		return true
	}

	// Check if size changed
	if info.Size() != lastInfo.Size {
		return true
	}

	// Check if modification time changed
	if !info.ModTime().Equal(lastInfo.ModTime) {
		return true
	}

	// Check if mode changed
	if info.Mode() != lastInfo.Mode {
		return true
	}

	// For small files, check content hash
	if info.Size() < 1024*1024 { // 1MB threshold
		checksum, err := s.calculateFileChecksum(filepath.Join(s.directory, relPath))
		if err != nil {
			logrus.Warnf("Failed to calculate checksum for %s: %v", relPath, err)
			return true // Assume changed if we can't verify
		}
		if checksum != lastInfo.Checksum {
			return true
		}
	}

	return false
}

// calculateFileChecksum calculates MD5 checksum of a file
func (s *IncrementalSnapshotter) calculateFileChecksum(filePath string) (string, error) {
	file, err := os.Open(filepath.Clean(filePath))
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := file.Seek(0, 0); err != nil {
		return "", err
	}

	// Read file in chunks to avoid memory issues
	buffer := make([]byte, BufferSize64KB) // 64KB buffer
	for {
		n, err := file.Read(buffer)
		if n > 0 {
			hash.Write(buffer[:n])
		}
		if err != nil {
			break
		}
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// isIgnored checks if a path should be ignored
func (s *IncrementalSnapshotter) isIgnored(path string) bool {
	for _, pattern := range s.ignoreList {
		matched, err := filepath.Match(pattern, filepath.Base(path))
		if err != nil {
			logrus.Warnf("Invalid ignore pattern %s: %v", pattern, err)
			continue
		}
		if matched {
			return true
		}
	}
	return false
}

// createChangeSnapshot creates a tarball of only the changed files
func (s *IncrementalSnapshotter) createChangeSnapshot(changedFiles, deletedFiles []string) (string, error) {
	// Create temporary file for snapshot
	tmpFile, err := os.CreateTemp("", "kaniko_incremental_*.tar")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	// TODO: Implement tarball creation
	// This would use the existing tar utilities from Kaniko
	// For now, just return the temp file path
	logrus.Debugf("Created incremental snapshot with %d changed files, %d deleted files",
		len(changedFiles), len(deletedFiles))

	return tmpFile.Name(), nil
}

// updateSnapshotCache updates the internal cache with current file states
func (s *IncrementalSnapshotter) updateSnapshotCache(changedFiles, deletedFiles []string) {
	// Remove deleted files from cache
	for _, deletedFile := range deletedFiles {
		delete(s.lastSnapshot, deletedFile)
	}

	// Update changed files in cache
	for _, changedFile := range changedFiles {
		fullPath := filepath.Join(s.directory, changedFile)
		info, err := os.Stat(fullPath)
		if err != nil {
			logrus.Warnf("Failed to stat changed file %s: %v", changedFile, err)
			continue
		}

		checksum := ""
		if info.Size() < 1024*1024 { // Only calculate checksum for small files
			if cs, err := s.calculateFileChecksum(fullPath); err == nil {
				checksum = cs
			}
		}

		s.lastSnapshot[changedFile] = FileInfo{
			Path:     changedFile,
			Size:     info.Size(),
			ModTime:  info.ModTime(),
			Mode:     info.Mode(),
			Checksum: checksum,
		}
	}

	// Save cache to disk
	if err := s.saveSnapshotCache(); err != nil {
		logrus.Warnf("Failed to save snapshot cache: %v", err)
	}
}

// loadLastSnapshot loads the previous snapshot from disk
func (s *IncrementalSnapshotter) loadLastSnapshot() error {
	data, err := os.ReadFile(s.cacheFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No previous snapshot
		}
		return err
	}

	return json.Unmarshal(data, &s.lastSnapshot)
}

// saveSnapshotCache saves the current snapshot to disk
func (s *IncrementalSnapshotter) saveSnapshotCache() error {
	data, err := json.Marshal(s.lastSnapshot)
	if err != nil {
		return err
	}

	return os.WriteFile(s.cacheFile, data, FilePerm600)
}

// GetCacheStats returns statistics about the snapshot cache
func (s *IncrementalSnapshotter) GetCacheStats() map[string]interface{} {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return map[string]interface{}{
		"cached_files":    len(s.lastSnapshot),
		"cache_file":      s.cacheFile,
		"last_scan_time":  s.lastScanTime,
		"scan_interval":   s.scanInterval,
		"directory":       s.directory,
		"ignore_patterns": len(s.ignoreList),
	}
}

// ClearCache clears the snapshot cache
func (s *IncrementalSnapshotter) ClearCache() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.lastSnapshot = make(map[string]FileInfo)
	s.lastScanTime = time.Time{}

	if err := os.Remove(s.cacheFile); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}
