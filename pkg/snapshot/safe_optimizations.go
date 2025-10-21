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
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/filesystem"
	"github.com/Gosayram/kaniko/pkg/util"
)

// Constants for optimization
const (
	defaultMetadataCacheSize = 2000
	minFileSizeBytes         = 2048
	percentageMultiplier     = 100
	averageDivisor           = 2
)

// SafeSnapshotOptimizer provides safe optimizations for snapshot operations
type SafeSnapshotOptimizer struct {
	// Core components
	snapshotter      *Snapshotter
	parallelHasher   *ParallelHasher
	integrityChecker *IntegrityChecker
	symlinkResolver  *SafeSymlinkResolver
	metadataCache    *MetadataCache

	// Configuration
	opts            *config.KanikoOptions
	maxWorkers      int
	enableParallel  bool
	enableIntegrity bool

	// Statistics
	stats      *OptimizationStats
	statsMutex sync.RWMutex
}

// ParallelHasher provides parallel file hashing with integrity verification
type ParallelHasher struct {
	maxWorkers     int
	hasher         func(string) (string, error)
	integrityCheck bool
	stats          *HashingStats
	statsMutex     sync.RWMutex
}

// IntegrityChecker verifies the integrity of snapshot operations
type IntegrityChecker struct {
	maxExpectedChanges int
	criticalFiles      map[string]bool
	suspiciousPatterns []string
	stats              *IntegrityStats
	statsMutex         sync.RWMutex
}

// SafeSymlinkResolver safely resolves symbolic links
type SafeSymlinkResolver struct {
	resolvedCache map[string]string
	cacheMutex    sync.RWMutex
	stats         *SymlinkStats
	statsMutex    sync.RWMutex
}

// MetadataCache caches file metadata for faster comparison
type MetadataCache struct {
	cache      map[string]*FileMetadata
	cacheMutex sync.RWMutex
	maxSize    int
	stats      *CacheStats
	statsMutex sync.RWMutex
}

// FileMetadata represents cached file metadata
type FileMetadata struct {
	Path      string      `json:"path"`
	Size      int64       `json:"size"`
	ModTime   time.Time   `json:"mod_time"`
	Mode      os.FileMode `json:"mode"`
	Hash      string      `json:"hash"`
	IsDir     bool        `json:"is_dir"`
	IsSymlink bool        `json:"is_symlink"`
	Target    string      `json:"target,omitempty"`
}

// OptimizationStats tracks optimization performance
type OptimizationStats struct {
	TotalSnapshots       int64         `json:"total_snapshots"`
	IncrementalSnapshots int64         `json:"incremental_snapshots"`
	FullSnapshots        int64         `json:"full_snapshots"`
	IntegrityChecks      int64         `json:"integrity_checks"`
	IntegrityFailures    int64         `json:"integrity_failures"`
	AverageTime          time.Duration `json:"average_time"`
	FilesProcessed       int64         `json:"files_processed"`
	HashesComputed       int64         `json:"hashes_computed"`
	CacheHits            int64         `json:"cache_hits"`
	CacheMisses          int64         `json:"cache_misses"`
	StartTime            time.Time     `json:"start_time"`
	LastReset            time.Time     `json:"last_reset"`
}

// HashingStats tracks hashing performance
type HashingStats struct {
	TotalHashes      int64         `json:"total_hashes"`
	ParallelHashes   int64         `json:"parallel_hashes"`
	SequentialHashes int64         `json:"sequential_hashes"`
	AverageTime      time.Duration `json:"average_time"`
	Errors           int64         `json:"errors"`
	StartTime        time.Time     `json:"start_time"`
}

// IntegrityStats tracks integrity checking performance
type IntegrityStats struct {
	TotalChecks  int64         `json:"total_checks"`
	PassedChecks int64         `json:"passed_checks"`
	FailedChecks int64         `json:"failed_checks"`
	AverageTime  time.Duration `json:"average_time"`
	StartTime    time.Time     `json:"start_time"`
}

// SymlinkStats tracks symlink resolution performance
type SymlinkStats struct {
	TotalResolutions int64         `json:"total_resolutions"`
	CacheHits        int64         `json:"cache_hits"`
	CacheMisses      int64         `json:"cache_misses"`
	Errors           int64         `json:"errors"`
	AverageTime      time.Duration `json:"average_time"`
	StartTime        time.Time     `json:"start_time"`
}

// CacheStats tracks metadata cache performance
type CacheStats struct {
	TotalRequests int64     `json:"total_requests"`
	CacheHits     int64     `json:"cache_hits"`
	CacheMisses   int64     `json:"cache_misses"`
	Evictions     int64     `json:"evictions"`
	HitRate       float64   `json:"hit_rate"`
	StartTime     time.Time `json:"start_time"`
}

// NewSafeSnapshotOptimizer creates a new safe snapshot optimizer
func NewSafeSnapshotOptimizer(snapshotter *Snapshotter, opts *config.KanikoOptions) *SafeSnapshotOptimizer {
	maxWorkers := opts.MaxParallelCommands
	if maxWorkers <= 0 {
		maxWorkers = runtime.NumCPU()
	}

	optimizer := &SafeSnapshotOptimizer{
		snapshotter:     snapshotter,
		opts:            opts,
		maxWorkers:      maxWorkers,
		enableParallel:  opts.EnableParallelExec,
		enableIntegrity: opts.IntegrityCheck,
		stats: &OptimizationStats{
			StartTime: time.Now(),
			LastReset: time.Now(),
		},
	}

	// Initialize components
	optimizer.parallelHasher = NewParallelHasher(maxWorkers, snapshotter.l.hasher, opts.IntegrityCheck)
	optimizer.integrityChecker = NewIntegrityChecker(opts.MaxExpectedChanges)
	optimizer.symlinkResolver = NewSafeSymlinkResolver()
	optimizer.metadataCache = NewMetadataCache(defaultMetadataCacheSize) // Optimized for large projects

	logrus.Info("🛡️ Safe snapshot optimizer initialized with integrity checking")
	return optimizer
}

// NewParallelHasher creates a new parallel hasher
func NewParallelHasher(maxWorkers int, hasher func(string) (string, error), integrityCheck bool) *ParallelHasher {
	return &ParallelHasher{
		maxWorkers:     maxWorkers,
		hasher:         hasher,
		integrityCheck: integrityCheck,
		stats: &HashingStats{
			StartTime: time.Now(),
		},
	}
}

// NewIntegrityChecker creates a new integrity checker
func NewIntegrityChecker(maxExpectedChanges int) *IntegrityChecker {
	return &IntegrityChecker{
		maxExpectedChanges: maxExpectedChanges,
		criticalFiles: map[string]bool{
			"/etc/passwd":      true,
			"/etc/group":       true,
			"/etc/shadow":      true,
			"/etc/hosts":       true,
			"/etc/resolv.conf": true,
		},
		suspiciousPatterns: []string{
			"..", "~", "tmp", "temp",
		},
		stats: &IntegrityStats{
			StartTime: time.Now(),
		},
	}
}

// NewSafeSymlinkResolver creates a new safe symlink resolver
func NewSafeSymlinkResolver() *SafeSymlinkResolver {
	return &SafeSymlinkResolver{
		resolvedCache: make(map[string]string),
		stats: &SymlinkStats{
			StartTime: time.Now(),
		},
	}
}

// NewMetadataCache creates a new metadata cache
func NewMetadataCache(maxSize int) *MetadataCache {
	return &MetadataCache{
		cache:   make(map[string]*FileMetadata),
		maxSize: maxSize,
		stats: &CacheStats{
			StartTime: time.Now(),
		},
	}
}

// OptimizedWalkFS performs optimized filesystem walk with parallel hashing
func (sso *SafeSnapshotOptimizer) OptimizedWalkFS(
	dir string, existingPaths map[string]struct{}) (changedFiles []string, deletedFiles map[string]struct{}, err error) {
	start := time.Now()
	defer func() {
		sso.updateStats(time.Since(start))
	}()

	logrus.Debugf("🔍 Starting optimized filesystem walk for %s", dir)

	// 1. Parallel directory scanning
	logrus.Debugf("🔍 Starting parallel directory scan for %s", dir)
	scanResults, err := sso.parallelDirectoryScan(dir)
	if err != nil {
		logrus.Warnf("⚠️ Parallel directory scan failed: %v, falling back to standard WalkFS", err)
		return nil, nil, fmt.Errorf("parallel directory scan failed: %w", err)
	}
	logrus.Debugf("🔍 Parallel directory scan completed: found %d files", len(scanResults.files))

	// 2. Parallel file hashing with integrity verification
	changedFiles, err = sso.parallelFileHashing(scanResults.files)
	if err != nil {
		return nil, nil, fmt.Errorf("parallel file hashing failed: %w", err)
	}

	// 3. Critical integrity check
	if sso.enableIntegrity && sso.integrityChecker.NeedsFullScan(changedFiles) {
		logrus.Warn("⚠️ Integrity concerns detected, falling back to full scan")
		sso.recordIntegrityFailure()
		return sso.fullWalkFS(dir, existingPaths)
	}

	// 4. Safe symlink resolution
	resolvedFiles, err := sso.symlinkResolver.SafeResolveSymlinks(changedFiles)
	if err != nil {
		logrus.Warnf("⚠️ Symlink resolution failed: %v, continuing with original paths", err)
		resolvedFiles = changedFiles
	}

	logrus.Debugf("✅ Optimized walk completed: %d files changed", len(resolvedFiles))
	return resolvedFiles, scanResults.deletedFiles, nil
}

// parallelDirectoryScan performs parallel directory scanning
func (sso *SafeSnapshotOptimizer) parallelDirectoryScan(dir string) (*ScanResults, error) {
	results := &ScanResults{
		files:        make([]string, 0),
		deletedFiles: make(map[string]struct{}),
	}

	// Use worker pool for parallel scanning
	workers := make(chan struct{}, sso.maxWorkers)
	var wg sync.WaitGroup
	var mutex sync.Mutex

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Skip problematic paths like /proc/*/fd/* that may not be accessible in containers
			if strings.Contains(path, "/proc/") && strings.Contains(path, "/fd/") {
				return filepath.SkipDir
			}
			// For other errors, log and continue
			logrus.Debugf("Skipping problematic path %s: %v", path, err)
			return nil
		}

		// Skip if not a regular file
		if !info.Mode().IsRegular() {
			return nil
		}

		wg.Add(1)
		go func(p string, i os.FileInfo) {
			defer wg.Done()

			// Acquire worker
			workers <- struct{}{}
			defer func() { <-workers }()

			// Process file
			if sso.shouldProcessFile(p, i) {
				mutex.Lock()
				results.files = append(results.files, p)
				mutex.Unlock()
			}
		}(path, info)

		return nil
	})

	wg.Wait()
	close(workers)

	return results, err
}

// ScanResults holds the results of a directory scan
type ScanResults struct {
	files        []string
	deletedFiles map[string]struct{}
}

// shouldProcessFile determines if a file should be processed
func (sso *SafeSnapshotOptimizer) shouldProcessFile(path string, info os.FileInfo) bool {
	// Skip only system hidden files, but allow all user-created hidden files
	baseName := filepath.Base(path)
	if baseName[0] == '.' {
		// Skip only system/temporary hidden files
		systemHiddenFiles := []string{
			".DS_Store", ".Thumbs.db", ".Spotlight-V100",
			".Trashes", ".fseventsd", ".TemporaryItems",
		}
		for _, system := range systemHiddenFiles {
			if baseName == system {
				logrus.Debugf("🚫 Skipping system hidden file: %s", path)
				return false
			}
		}
		// Allow all other hidden files (including .output, .next, etc.)
		logrus.Debugf("✅ Processing hidden file: %s", path)
	}

	// Skip if in ignore list
	if util.CheckIgnoreList(path) {
		logrus.Debugf("🚫 Skipping ignored file: %s", path)
		return false
	}

	// Skip if too small (likely not important)
	if info.Size() < minFileSizeBytes { // Optimized for better performance
		logrus.Debugf("🚫 Skipping small file: %s (size: %d)", path, info.Size())
		return false
	}

	logrus.Debugf("✅ Processing file: %s", path)
	return true
}

// parallelFileHashing performs parallel file hashing
func (sso *SafeSnapshotOptimizer) parallelFileHashing(files []string) ([]string, error) {
	if !sso.enableParallel || len(files) < 2 {
		return sso.sequentialFileHashing(files)
	}

	return sso.parallelHasher.HashFiles(files)
}

// sequentialFileHashing performs sequential file hashing
func (sso *SafeSnapshotOptimizer) sequentialFileHashing(files []string) ([]string, error) {
	changedFiles := make([]string, 0)

	for _, file := range files {
		// Check cache first
		if sso.metadataCache.HasFile(file) {
			sso.recordCacheHit()
			continue
		}

		// Compute hash
		hash, err := sso.parallelHasher.hasher(file)
		if err != nil {
			logrus.Debugf("Failed to hash file %s: %v", file, err)
			continue
		}

		// Check if file changed
		changed, err := sso.snapshotter.l.CheckFileChange(file)
		if err != nil {
			logrus.Debugf("Failed to check file change for %s: %v", file, err)
			continue
		}
		if changed {
			changedFiles = append(changedFiles, file)
		}

		// Update cache
		sso.metadataCache.UpdateFile(file, hash)
		sso.recordCacheMiss()
	}

	return changedFiles, nil
}

// fullWalkFS performs a full filesystem walk (fallback)
func (sso *SafeSnapshotOptimizer) fullWalkFS(
	dir string, existingPaths map[string]struct{}) (changedFiles []string, deletedFiles map[string]struct{}, err error) {
	logrus.Info("🔄 Performing full filesystem walk")

	// Use original WalkFS implementation
	changedPaths, deletedPaths := util.WalkFS(dir, existingPaths, sso.snapshotter.l.CheckFileChange)

	// Resolve paths safely
	resolvedFiles, err := filesystem.ResolvePaths(changedPaths, sso.snapshotter.ignorelist)
	if err != nil {
		return nil, nil, err
	}

	return resolvedFiles, deletedPaths, nil
}

// HashFiles performs parallel file hashing
func (ph *ParallelHasher) HashFiles(files []string) ([]string, error) {
	start := time.Now()
	defer func() {
		ph.updateStats(time.Since(start))
	}()

	changedFiles := make([]string, 0)
	workers := make(chan struct{}, ph.maxWorkers)
	var wg sync.WaitGroup
	var mutex sync.Mutex

	for _, file := range files {
		wg.Add(1)
		go func(f string) {
			defer wg.Done()

			// Acquire worker
			workers <- struct{}{}
			defer func() { <-workers }()

			// Hash file
			hash, err := ph.hasher(f)
			if err != nil {
				ph.recordError()
				return
			}

			// Check if file changed (simplified)
			if hash != "" {
				mutex.Lock()
				changedFiles = append(changedFiles, f)
				mutex.Unlock()
			}

			ph.recordHash()
		}(file)
	}

	wg.Wait()
	close(workers)

	return changedFiles, nil
}

// NeedsFullScan checks if a full scan is needed based on integrity concerns
func (ic *IntegrityChecker) NeedsFullScan(files []string) bool {
	ic.statsMutex.Lock()
	defer ic.statsMutex.Unlock()

	ic.stats.TotalChecks++

	// Check for too many changes
	if len(files) > ic.maxExpectedChanges {
		ic.stats.FailedChecks++
		return true
	}

	// Check for critical file changes
	for _, file := range files {
		if ic.criticalFiles[file] {
			ic.stats.FailedChecks++
			return true
		}

		// Check for suspicious patterns
		for _, pattern := range ic.suspiciousPatterns {
			if filepath.Base(file) == pattern {
				ic.stats.FailedChecks++
				return true
			}
		}
	}

	ic.stats.PassedChecks++
	return false
}

// SafeResolveSymlinks safely resolves symbolic links
func (ssr *SafeSymlinkResolver) SafeResolveSymlinks(paths []string) ([]string, error) {
	start := time.Now()
	defer func() {
		ssr.updateStats(time.Since(start))
	}()

	resolved := make([]string, 0, len(paths))

	for _, path := range paths {
		// Check cache first
		if cached, found := ssr.getCached(path); found {
			resolved = append(resolved, cached)
			ssr.recordCacheHit()
			continue
		}

		// Resolve symlink
		resolvedPath, err := ssr.resolveSymlink(path)
		if err != nil {
			logrus.Debugf("Failed to resolve symlink %s: %v", path, err)
			resolved = append(resolved, path) // Use original path
			ssr.recordError()
			continue
		}

		// Cache result
		ssr.setCached(path, resolvedPath)
		resolved = append(resolved, resolvedPath)
		ssr.recordCacheMiss()
	}

	return resolved, nil
}

// resolveSymlink resolves a single symlink
func (ssr *SafeSymlinkResolver) resolveSymlink(path string) (string, error) {
	// Check if file exists
	if _, err := os.Lstat(path); err != nil {
		return "", err
	}

	// Resolve symlink
	return filepath.EvalSymlinks(path)
}

// getCached retrieves a cached resolution
func (ssr *SafeSymlinkResolver) getCached(path string) (string, bool) {
	ssr.cacheMutex.RLock()
	defer ssr.cacheMutex.RUnlock()

	resolved, found := ssr.resolvedCache[path]
	return resolved, found
}

// setCached caches a resolution
func (ssr *SafeSymlinkResolver) setCached(path, resolved string) {
	ssr.cacheMutex.Lock()
	defer ssr.cacheMutex.Unlock()

	ssr.resolvedCache[path] = resolved
}

// HasFile checks if file metadata is cached
func (mc *MetadataCache) HasFile(path string) bool {
	mc.cacheMutex.RLock()
	defer mc.cacheMutex.RUnlock()

	_, found := mc.cache[path]
	return found
}

// UpdateFile updates file metadata in cache
func (mc *MetadataCache) UpdateFile(path, hash string) {
	mc.cacheMutex.Lock()
	defer mc.cacheMutex.Unlock()

	// Check cache size
	if len(mc.cache) >= mc.maxSize {
		mc.evictOldest()
	}

	// Update cache
	mc.cache[path] = &FileMetadata{
		Path: path,
		Hash: hash,
	}
}

// evictOldest evicts the oldest cache entry
func (mc *MetadataCache) evictOldest() {
	// Simple eviction: remove first entry
	for key := range mc.cache {
		delete(mc.cache, key)
		mc.recordEviction()
		break
	}
}

// Statistics methods
func (sso *SafeSnapshotOptimizer) updateStats(duration time.Duration) {
	sso.statsMutex.Lock()
	defer sso.statsMutex.Unlock()

	sso.stats.TotalSnapshots++
	sso.stats.AverageTime = (sso.stats.AverageTime + duration) / averageDivisor
}

func (sso *SafeSnapshotOptimizer) recordIntegrityFailure() {
	sso.statsMutex.Lock()
	defer sso.statsMutex.Unlock()

	sso.stats.IntegrityFailures++
}

func (sso *SafeSnapshotOptimizer) recordCacheHit() {
	sso.statsMutex.Lock()
	defer sso.statsMutex.Unlock()

	sso.stats.CacheHits++
}

func (sso *SafeSnapshotOptimizer) recordCacheMiss() {
	sso.statsMutex.Lock()
	defer sso.statsMutex.Unlock()

	sso.stats.CacheMisses++
}

func (ph *ParallelHasher) updateStats(duration time.Duration) {
	ph.statsMutex.Lock()
	defer ph.statsMutex.Unlock()

	ph.stats.AverageTime = (ph.stats.AverageTime + duration) / averageDivisor
}

func (ph *ParallelHasher) recordHash() {
	ph.statsMutex.Lock()
	defer ph.statsMutex.Unlock()

	ph.stats.TotalHashes++
	ph.stats.ParallelHashes++
}

func (ph *ParallelHasher) recordError() {
	ph.statsMutex.Lock()
	defer ph.statsMutex.Unlock()

	ph.stats.Errors++
}

func (ssr *SafeSymlinkResolver) updateStats(duration time.Duration) {
	ssr.statsMutex.Lock()
	defer ssr.statsMutex.Unlock()

	ssr.stats.TotalResolutions++
	ssr.stats.AverageTime = (ssr.stats.AverageTime + duration) / averageDivisor
}

func (ssr *SafeSymlinkResolver) recordCacheHit() {
	ssr.statsMutex.Lock()
	defer ssr.statsMutex.Unlock()

	ssr.stats.CacheHits++
}

func (ssr *SafeSymlinkResolver) recordCacheMiss() {
	ssr.statsMutex.Lock()
	defer ssr.statsMutex.Unlock()

	ssr.stats.CacheMisses++
}

func (ssr *SafeSymlinkResolver) recordError() {
	ssr.statsMutex.Lock()
	defer ssr.statsMutex.Unlock()

	ssr.stats.Errors++
}

func (mc *MetadataCache) recordEviction() {
	mc.statsMutex.Lock()
	defer mc.statsMutex.Unlock()

	mc.stats.Evictions++
}

// GetStatistics returns optimization statistics
func (sso *SafeSnapshotOptimizer) GetStatistics() *OptimizationStats {
	sso.statsMutex.RLock()
	defer sso.statsMutex.RUnlock()

	// Return a copy to avoid race conditions
	stats := *sso.stats
	return &stats
}

// LogStatistics logs optimization statistics
func (sso *SafeSnapshotOptimizer) LogStatistics() {
	stats := sso.GetStatistics()

	logrus.Infof("📊 Safe Snapshot Optimization Statistics:")
	logrus.Infof("   Total Snapshots: %d", stats.TotalSnapshots)
	logrus.Infof("   Incremental: %d, Full: %d", stats.IncrementalSnapshots, stats.FullSnapshots)
	logrus.Infof("   Integrity Checks: %d, Failures: %d", stats.IntegrityChecks, stats.IntegrityFailures)
	logrus.Infof("   Average Time: %v", stats.AverageTime)
	logrus.Infof("   Files Processed: %d", stats.FilesProcessed)
	hitRate := float64(stats.CacheHits) / float64(stats.CacheHits+stats.CacheMisses) * percentageMultiplier
	logrus.Infof("   Cache Hit Rate: %.2f%%", hitRate)
}
