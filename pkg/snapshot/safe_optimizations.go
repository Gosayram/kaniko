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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/filesystem"
	"github.com/Gosayram/kaniko/pkg/logging"
	"github.com/Gosayram/kaniko/pkg/util"
)

// Constants for optimization
const (
	defaultMetadataCacheSize = 2000
	minFileSizeBytes         = 2048
	percentageMultiplier     = 100
	averageDivisor           = 2
	// Conservative max workers limit for I/O-bound operations
	maxWorkersLimit = 4
	// DefaultDirectoryScanTimeout is the default timeout for directory scanning
	DefaultDirectoryScanTimeout = 10 * time.Minute
	// DefaultMaxFilesProcessed is the default maximum number of files to process
	DefaultMaxFilesProcessed = 100000
	// MemoryCheckInterval is the interval for checking memory usage during directory scan
	MemoryCheckInterval = 10 * time.Second
	// MemoryBaselineBytes is the baseline memory for percentage calculation (2GB)
	MemoryBaselineBytes = 2 * 1024 * 1024 * 1024
	// MemoryWarningThresholdPercent is the percentage of memory usage to trigger warning
	MemoryWarningThresholdPercent = 80
	// BytesPerKB is the number of bytes in a kilobyte
	BytesPerKB = 1024
	// BytesPerMB is the number of bytes in a megabyte
	BytesPerMB = BytesPerKB * BytesPerKB
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
	// Use MaxWorkers from options if set, otherwise use conservative default
	maxWorkers := opts.MaxWorkers
	if maxWorkers <= 0 {
		maxWorkers = opts.MaxParallelCommands
	}
	if maxWorkers <= 0 {
		// Conservative default: min(4, NumCPU) instead of NumCPU
		numCPU := runtime.NumCPU()
		maxWorkers = numCPU
		if maxWorkers > maxWorkersLimit {
			maxWorkers = maxWorkersLimit
		}
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
	// Use MaxParallelHashing from options if set, otherwise use maxWorkers
	hashWorkers := maxWorkers
	if opts.MaxParallelHashing > 0 {
		hashWorkers = opts.MaxParallelHashing
	}
	optimizer.parallelHasher = NewParallelHasher(hashWorkers, snapshotter.l.hasher, opts.IntegrityCheck)
	optimizer.integrityChecker = NewIntegrityChecker(opts.MaxExpectedChanges)
	optimizer.symlinkResolver = NewSafeSymlinkResolver()
	optimizer.metadataCache = NewMetadataCache(defaultMetadataCacheSize) // Optimized for large projects

	logrus.Info("Safe snapshot optimizer initialized with integrity checking")
	return optimizer
}

// NewParallelHasher creates a new parallel hasher
// Uses conservative defaults to avoid excessive CPU usage
func NewParallelHasher(maxWorkers int, hasher func(string) (string, error), integrityCheck bool) *ParallelHasher {
	// Apply conservative limit if not set
	if maxWorkers <= 0 {
		numCPU := runtime.NumCPU()
		maxWorkers = numCPU
		if maxWorkers > maxWorkersLimit {
			maxWorkers = maxWorkersLimit
		}
	}
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

	// Optimized logging: use async logging for hot paths (reduces CPU usage)
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logging.AsyncDebugf("Starting optimized filesystem walk for %s", dir)
	}

	// 1. Parallel directory scanning
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logging.AsyncDebugf("Starting parallel directory scan for %s", dir)
	}
	scanResults, err := sso.parallelDirectoryScan(dir)
	if err != nil {
		logrus.Warnf("Parallel directory scan failed: %v, falling back to standard WalkFS", err)
		return nil, nil, fmt.Errorf("parallel directory scan failed: %w", err)
	}
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logging.AsyncDebugf("Parallel directory scan completed: found %d files", len(scanResults.files))
	}

	// 2. Parallel file hashing with integrity verification
	changedFiles, err = sso.parallelFileHashing(scanResults.files)
	if err != nil {
		return nil, nil, fmt.Errorf("parallel file hashing failed: %w", err)
	}

	// 3. Critical integrity check
	if sso.enableIntegrity && sso.integrityChecker.NeedsFullScan(changedFiles) {
		logrus.Warn("Integrity concerns detected, falling back to full scan")
		sso.recordIntegrityFailure()
		return sso.fullWalkFS(dir, existingPaths)
	}

	// 4. Safe symlink resolution
	resolvedFiles, err := sso.symlinkResolver.SafeResolveSymlinks(changedFiles)
	if err != nil {
		logrus.Warnf("Symlink resolution failed: %v, continuing with original paths", err)
		resolvedFiles = changedFiles
	}

	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logging.AsyncDebugf("Optimized walk completed: %d files changed", len(resolvedFiles))
	}
	return resolvedFiles, scanResults.deletedFiles, nil
}

// createDirectoryScanContext creates a context with timeout for directory scanning
func createDirectoryScanContext() (context.Context, context.CancelFunc, time.Duration) {
	timeoutStr := os.Getenv("DIRECTORY_SCAN_TIMEOUT")
	if timeoutStr == "" {
		timeoutStr = "10m"
	}
	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		logrus.Warnf("Invalid DIRECTORY_SCAN_TIMEOUT value '%s', using default 10m", timeoutStr)
		timeout = DefaultDirectoryScanTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	return ctx, cancel, timeout
}

// getMaxFilesLimit gets the maximum number of files to process from environment
func getMaxFilesLimit() int64 {
	maxFilesStr := os.Getenv("MAX_FILES_PROCESSED")
	maxFiles := int64(DefaultMaxFilesProcessed) // Default: 100k files
	if maxFilesStr != "" {
		if parsed, err := strconv.ParseInt(maxFilesStr, 10, 64); err == nil && parsed > 0 {
			maxFiles = parsed
		}
	}
	return maxFiles
}

// checkFileCountLimit checks if file count exceeds the limit
func checkFileCountLimit(fileCount, maxFiles int64) error {
	if fileCount > 0 && fileCount%1000 == 0 {
		if fileCount > maxFiles {
			logrus.Warnf("File count %d exceeds limit %d, stopping directory scan", fileCount, maxFiles)
			return fmt.Errorf("file count limit exceeded: %d > %d", fileCount, maxFiles)
		}
	}
	return nil
}

// checkMemoryUsage checks memory usage and logs warning if high
func checkMemoryUsage(lastMemoryCheck time.Time, memoryCheckInterval time.Duration) time.Time {
	now := time.Now()
	if now.Sub(lastMemoryCheck) <= memoryCheckInterval {
		return lastMemoryCheck
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	memoryPercent := float64(m.Alloc) / float64(MemoryBaselineBytes) * float64(percentageMultiplier)
	if memoryPercent > MemoryWarningThresholdPercent {
		logrus.Warnf("High memory usage detected: %.1f%% (%dMB) during directory scan",
			memoryPercent, m.Alloc/BytesPerMB)
	}
	return now
}

// handleWalkError handles errors during file walking
func handleWalkError(path string, err error) error {
	if strings.Contains(path, "/proc/") && strings.Contains(path, "/fd/") {
		return filepath.SkipDir
	}
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logging.AsyncDebugf("Skipping problematic path %s: %v", path, err)
	}
	return nil
}

// processFileInWorker processes a file using a worker from the pool
func (sso *SafeSnapshotOptimizer) processFileInWorker(
	ctx context.Context,
	path string,
	info os.FileInfo,
	workers chan struct{},
	wg *sync.WaitGroup,
	walkFiles *[]string,
	mutex *sync.Mutex,
) {
	select {
	case workers <- struct{}{}:
		wg.Add(1)
		go func(p string, i os.FileInfo) {
			defer wg.Done()
			defer func() { <-workers }()

			select {
			case <-ctx.Done():
				return
			default:
			}

			if sso.shouldProcessFile(p, i) {
				mutex.Lock()
				*walkFiles = append(*walkFiles, p)
				mutex.Unlock()
			}
		}(path, info)
	case <-ctx.Done():
	default:
		// Worker pool is full, process synchronously
		if sso.shouldProcessFile(path, info) {
			mutex.Lock()
			*walkFiles = append(*walkFiles, path)
			mutex.Unlock()
		}
	}
}

// handleScanResult processes the result of directory scanning
func handleScanResult(res walkResult, timeout time.Duration, start time.Time) (*ScanResults, error) {
	const initialCapacity = 100
	results := &ScanResults{
		files:        make([]string, 0, initialCapacity),
		deletedFiles: make(map[string]struct{}),
	}

	if res.err != nil && res.err != context.DeadlineExceeded {
		return nil, res.err
	}
	if res.err == context.DeadlineExceeded {
		logrus.Warnf("Directory scan timed out after %v, returning partial results (%d files)", timeout, len(res.files))
		results.files = res.files
		return results, nil
	}

	results.files = res.files
	logrus.Infof("Directory scan completed: found %d files in %v", len(res.files), time.Since(start))

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	logrus.Debugf("Memory usage after scan: %dMB", m.Alloc/BytesPerMB)

	return results, nil
}

// walkResult represents the result of directory walking
type walkResult struct {
	files []string
	err   error
}

// parallelDirectoryScan performs parallel directory scanning with timeout and goroutine limits
func (sso *SafeSnapshotOptimizer) parallelDirectoryScan(dir string) (*ScanResults, error) {
	start := time.Now()

	const initialCapacity = 100
	results := &ScanResults{
		files:        make([]string, 0, initialCapacity),
		deletedFiles: make(map[string]struct{}),
	}

	ctx, cancel, timeout := createDirectoryScanContext()
	defer cancel()

	workers := make(chan struct{}, sso.maxWorkers)
	var wg sync.WaitGroup
	var mutex sync.Mutex
	resultCh := make(chan walkResult, 1)
	maxFiles := getMaxFilesLimit()

	go func() {
		var walkFiles []string
		var fileCount int64
		var lastMemoryCheck time.Time
		memoryCheckInterval := MemoryCheckInterval

		walkErr := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			if checkErr := checkFileCountLimit(fileCount, maxFiles); checkErr != nil {
				return checkErr
			}

			lastMemoryCheck = checkMemoryUsage(lastMemoryCheck, memoryCheckInterval)

			if err != nil {
				return handleWalkError(path, err)
			}

			if !info.Mode().IsRegular() {
				return nil
			}

			fileCount++
			sso.processFileInWorker(ctx, path, info, workers, &wg, &walkFiles, &mutex)

			return nil
		})

		wg.Wait()
		close(workers)
		resultCh <- walkResult{files: walkFiles, err: walkErr}
	}()

	select {
	case res := <-resultCh:
		return handleScanResult(res, timeout, start)
	case <-ctx.Done():
		logrus.Warnf("Directory scan timed out after %v, returning partial results", timeout)
		return results, nil
	}
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
				if logrus.IsLevelEnabled(logrus.DebugLevel) {
					logging.AsyncDebugf("🚫 Skipping system hidden file: %s", path)
				}
				return false
			}
		}
		// Allow all other hidden files (including .output, .next, etc.)
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			logging.AsyncDebugf("Processing hidden file: %s", path)
		}
	}

	// Skip if in ignore list
	if util.CheckIgnoreList(path) {
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			logging.AsyncDebugf("🚫 Skipping ignored file: %s", path)
		}
		return false
	}

	// Skip if too small (likely not important)
	if info.Size() < minFileSizeBytes { // Optimized for better performance
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			logging.AsyncDebugf("🚫 Skipping small file: %s (size: %d)", path, info.Size())
		}
		return false
	}

	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logging.AsyncDebugf("Processing file: %s", path)
	}
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
	// Optimized: pre-allocate with capacity to reduce reallocations
	changedFiles := make([]string, 0, len(files))

	for _, file := range files {
		// Check cache first
		if sso.metadataCache.HasFile(file) {
			sso.recordCacheHit()
			continue
		}

		// Compute hash
		hash, err := sso.parallelHasher.hasher(file)
		if err != nil {
			if logrus.IsLevelEnabled(logrus.DebugLevel) {
				logging.AsyncDebugf("Failed to hash file %s: %v", file, err)
			}
			continue
		}

		// Check if file changed
		changed, err := sso.snapshotter.l.CheckFileChange(file)
		if err != nil {
			if logrus.IsLevelEnabled(logrus.DebugLevel) {
				logging.AsyncDebugf("Failed to check file change for %s: %v", file, err)
			}
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
	logrus.Info("Performing full filesystem walk")

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
			if logrus.IsLevelEnabled(logrus.DebugLevel) {
				logging.AsyncDebugf("Failed to resolve symlink %s: %v", path, err)
			}
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

	logrus.Infof("Safe Snapshot Optimization Statistics:")
	logrus.Infof("   Total Snapshots: %d", stats.TotalSnapshots)
	logrus.Infof("   Incremental: %d, Full: %d", stats.IncrementalSnapshots, stats.FullSnapshots)
	logrus.Infof("   Integrity Checks: %d, Failures: %d", stats.IntegrityChecks, stats.IntegrityFailures)
	logrus.Infof("   Average Time: %v", stats.AverageTime)
	logrus.Infof("   Files Processed: %d", stats.FilesProcessed)
	hitRate := float64(stats.CacheHits) / float64(stats.CacheHits+stats.CacheMisses) * percentageMultiplier
	logrus.Infof("   Cache Hit Rate: %.2f%%", hitRate)
}
