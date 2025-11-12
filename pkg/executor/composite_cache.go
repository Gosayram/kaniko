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

package executor

import (
	"context"
	"crypto/sha256"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/util"
)

const (
	// DefaultHashDirTimeout is the default timeout for directory hashing
	DefaultHashDirTimeout = 10 * time.Minute
	// DefaultFileHashTimeout is the default timeout for file hashing
	DefaultFileHashTimeout = 30 * time.Second
	// AdaptiveHashLargeFileThreshold is the file size threshold (10MB) for adaptive hashing
	// Files >= this size will use metadata-only hashing for performance
	AdaptiveHashLargeFileThreshold = 10 * 1024 * 1024 // 10MB
	// AdaptiveHashManyFilesThreshold is the file count threshold (1000) for adaptive hashing
	// Directories with > this many files will use metadata-only hashing for all files
	AdaptiveHashManyFilesThreshold = 1000
)

// Global file hash cache to avoid recomputing hashes for the same files
// (per performance plan: cache file hashes to avoid repeated calculations)
//
// Deprecated: Use FileHashCache with invalidation instead.
// Kept for backward compatibility during migration.
var (
	fileHashCache   = make(map[string]string)
	fileHashCacheMu sync.RWMutex
)

// NewCompositeCache returns an initialized composite cache object.
func NewCompositeCache(initial ...string) *CompositeCache {
	c := CompositeCache{
		keys: initial,
	}
	return &c
}

// CompositeCache is a type that generates a cache key from a series of keys.
type CompositeCache struct {
	keys         []string
	cachedHash   string // Cached hash result to avoid recomputation
	hashComputed bool   // Whether hash has been computed
}

// AddKey adds the specified key to the sequence.
func (s *CompositeCache) AddKey(k ...string) {
	s.keys = append(s.keys, k...)
	// Invalidate cached hash when keys are added
	s.hashComputed = false
	s.cachedHash = ""
}

// Key returns the human readable composite key as a string.
func (s *CompositeCache) Key() string {
	return strings.Join(s.keys, "-")
}

// Hash returns the composite key in a string SHA256 format.
// Results are cached to avoid recomputation for the same key set.
func (s *CompositeCache) Hash() (string, error) {
	// Return cached hash if available
	if s.hashComputed {
		return s.cachedHash, nil
	}

	// Compute hash
	hashValue, err := util.SHA256(strings.NewReader(s.Key()))
	if err != nil {
		return "", err
	}

	// Cache the result
	s.cachedHash = hashValue
	s.hashComputed = true

	return hashValue, nil
}

// AddPath adds a file or directory path to the composite cache key
func (s *CompositeCache) AddPath(p string, fileContext util.FileContext) error {
	startTime := time.Now()
	logrus.Debugf("Adding path to cache key: %s", p)

	sha := sha256.New()
	fi, err := os.Lstat(p)
	if err != nil {
		// If path doesn't exist, log warning and continue without adding to cache
		// This prevents build failures when expected build artifacts are missing
		if os.IsNotExist(err) {
			logrus.Warnf("Path %s does not exist, skipping from cache key", p)
			return nil
		}
		return errors.Wrap(err, "could not add path")
	}

	if fi.Mode().IsDir() {
		logrus.Debugf("Hashing directory for cache key: %s", p)
		isEmptyDir, k, hashErr := hashDir(p, fileContext)
		if hashErr != nil {
			logrus.Errorf("Failed to hash directory %s after %v: %v", p, time.Since(startTime), hashErr)
			return hashErr
		}
		duration := time.Since(startTime)
		if duration > 5*time.Second {
			logrus.Infof("Directory hash for cache key completed in %v: %s", duration, p)
		}

		// Only add the hash of this directory to the key
		// if there is any ignored content.
		if !isEmptyDir || !fileContext.ExcludesFile(p) {
			s.keys = append(s.keys, k)
		}
		// Invalidate hash cache when directory hash is added
		s.hashComputed = false
		s.cachedHash = ""
		return nil
	}

	if fileContext.ExcludesFile(p) {
		return nil
	}

	// Use new FileHashCache with invalidation if opts are available
	// Otherwise fall back to old cache for backward compatibility
	var fh string
	if opts := getOptsForHashCache(); opts != nil {
		// Use new cache with invalidation
		var hashErr error
		fh, hashErr = getFileHashWithCache(p, fileContext, opts)
		if hashErr != nil {
			return hashErr
		}
	} else {
		// Fall back to old cache (backward compatibility)
		fileHashCacheMu.RLock()
		cachedHash, exists := fileHashCache[p]
		fileHashCacheMu.RUnlock()

		if exists {
			fh = cachedHash
		} else {
			// Compute hash if not cached
			// Use partial hashing for large files (default: 10MB limit)
			// This reduces CPU usage while maintaining good change detection
			var hashErr error
			maxFileHashSize := int64(defaultMaxFileHashSizeMB * fileHashBytesPerMegabyte) // Default: 10MB
			hasher := util.CacheHasherWithLimit(maxFileHashSize)
			fh, hashErr = hasher(p)
			if hashErr != nil {
				return hashErr
			}
			// Cache the result (per performance plan: cache file hashes)
			fileHashCacheMu.Lock()
			fileHashCache[p] = fh
			fileHashCacheMu.Unlock()
		}
	}

	if _, err := sha.Write([]byte(fh)); err != nil {
		return err
	}

	s.keys = append(s.keys, fmt.Sprintf("%x", sha.Sum(nil)))
	// Invalidate hash cache when file hash is added
	s.hashComputed = false
	s.cachedHash = ""

	duration := time.Since(startTime)
	if duration > 1*time.Second {
		logrus.Debugf("File hash for cache key completed in %v: %s", duration, p)
	}
	return nil
}

// parseHashDirTimeout parses the timeout from environment variable
func parseHashDirTimeout() time.Duration {
	timeoutStr := os.Getenv("HASH_DIR_TIMEOUT")
	if timeoutStr == "" {
		return DefaultHashDirTimeout
	}
	timeout, parseErr := time.ParseDuration(timeoutStr)
	if parseErr != nil {
		logrus.Warnf("Invalid HASH_DIR_TIMEOUT value '%s', using default 10m", timeoutStr)
		return DefaultHashDirTimeout
	}
	return timeout
}

// shouldUseAdaptiveHash checks if adaptive hashing should be used
func shouldUseAdaptiveHash() bool {
	useAdaptive := os.Getenv("USE_ADAPTIVE_DIR_HASH")
	if useAdaptive == "" {
		return true // Default: use adaptive hashing
	}
	return useAdaptive == "true" || useAdaptive == "1"
}

// hashFileInDirAdaptive hashes a single file using adaptive strategy based on file size
// For small files (<10MB): uses full content hashing
// For large files (>=10MB): uses metadata-only hashing
func hashFileInDirAdaptive(path string, fileContext util.FileContext, useMetadataOnly bool) (string, error) {
	var fileHash string
	var hashErr error

	// Check cache first
	if opts := getOptsForHashCache(); opts != nil {
		fileHash, hashErr = getFileHashWithCache(path, fileContext, opts)
		if hashErr == nil {
			return fileHash, nil
		}
	} else {
		fileHashCacheMu.RLock()
		cachedHash, exists := fileHashCache[path]
		fileHashCacheMu.RUnlock()

		if exists {
			return cachedHash, nil
		}
	}

	// Determine hashing strategy
	if useMetadataOnly {
		// Use metadata-only hashing (fast)
		hasher := util.RedoHasher()
		fileHash, hashErr = hasher(path)
	} else {
		// Check file size to decide strategy
		fi, err := os.Lstat(path)
		if err != nil {
			return "", err
		}

		if fi.Size() >= AdaptiveHashLargeFileThreshold {
			// Large file: use metadata-only hashing
			hasher := util.RedoHasher()
			fileHash, hashErr = hasher(path)
		} else {
			// Small file: use full content hashing
			maxFileHashSize := int64(defaultMaxFileHashSizeMB * fileHashBytesPerMegabyte)
			hasher := util.CacheHasherWithLimit(maxFileHashSize)
			fileHash, hashErr = hasher(path)
		}
	}

	if hashErr != nil {
		return "", hashErr
	}

	// Cache the result
	if opts := getOptsForHashCache(); opts != nil {
		_ = GetGlobalFileHashCache(opts).Set(path, fileHash)
	} else {
		fileHashCacheMu.Lock()
		fileHashCache[path] = fileHash
		fileHashCacheMu.Unlock()
	}

	return fileHash, nil
}

// hashFileInDirLegacy performs the actual hashing work for legacy implementation
func hashFileInDirLegacy(ctx context.Context, path string, fileContext util.FileContext) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	var fileHash string
	var hashErr error

	if opts := getOptsForHashCache(); opts != nil {
		fileHash, hashErr = getFileHashWithCache(path, fileContext, opts)
	} else {
		fileHashCacheMu.RLock()
		cachedHash, exists := fileHashCache[path]
		fileHashCacheMu.RUnlock()

		if exists {
			fileHash = cachedHash
		} else {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			default:
			}

			maxFileHashSize := int64(defaultMaxFileHashSizeMB * fileHashBytesPerMegabyte)
			hasher := util.CacheHasherWithLimit(maxFileHashSize)
			fileHash, hashErr = hasher(path)
			if hashErr == nil {
				fileHashCacheMu.Lock()
				fileHashCache[path] = fileHash
				fileHashCacheMu.Unlock()
			}
		}
	}

	return fileHash, hashErr
}

// hashFileInDir hashes a single file with timeout and caching (legacy implementation)
//
// Deprecated: Use hashFileInDirAdaptive for better performance
func hashFileInDir(path string, fileContext util.FileContext) (string, error) {
	// Use adaptive hashing if enabled
	if shouldUseAdaptiveHash() {
		return hashFileInDirAdaptive(path, fileContext, false)
	}

	// Legacy implementation with timeout (kept for backward compatibility)
	type hashResult struct {
		hash string
		err  error
	}
	hashResultCh := make(chan hashResult, 1)

	fileHashCtx, hashCancel := context.WithTimeout(context.Background(), DefaultFileHashTimeout)
	defer hashCancel()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logrus.Debugf("Panic while hashing file %s: %v, skipping", path, r)
				select {
				case hashResultCh <- hashResult{err: fmt.Errorf("panic: %v", r)}:
				case <-fileHashCtx.Done():
				}
			}
		}()

		fileHash, hashErr := hashFileInDirLegacy(fileHashCtx, path, fileContext)
		select {
		case hashResultCh <- hashResult{hash: fileHash, err: hashErr}:
		case <-fileHashCtx.Done():
		}
	}()

	select {
	case result := <-hashResultCh:
		return result.hash, result.err
	case <-fileHashCtx.Done():
		return "", fileHashCtx.Err()
	case <-time.After(DefaultFileHashTimeout):
		return "", fmt.Errorf("file hash timed out after %v", DefaultFileHashTimeout)
	}
}

// countFilesInDir counts files in directory (excluding ignored files)
func countFilesInDir(p string, fileContext util.FileContext) (int, error) {
	count := 0
	err := filepath.Walk(p, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) || os.IsPermission(err) {
				return nil
			}
			return nil
		}

		if info != nil && info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		if fileContext.ExcludesFile(path) {
			return nil
		}

		count++
		return nil
	})
	return count, err
}

// walkDirectoryForHashAdaptive walks directory and hashes files using adaptive strategy
// Simplified version without timeouts for better performance
func walkDirectoryForHashAdaptive(
	p string,
	fileContext util.FileContext,
	sha hash.Hash,
	useMetadataOnly bool,
) (isEmpty bool, fileCount int, err error) {
	err = filepath.Walk(p, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) || os.IsPermission(err) {
				if logrus.IsLevelEnabled(logrus.DebugLevel) {
					logrus.Debugf("File %s is not accessible during directory walk, skipping: %v", path, err)
				}
				return nil
			}
			if logrus.IsLevelEnabled(logrus.DebugLevel) {
				logrus.Debugf("Error accessing file %s during directory walk, skipping: %v", path, err)
			}
			return nil
		}

		if info != nil && info.Mode()&os.ModeSymlink != 0 {
			if logrus.IsLevelEnabled(logrus.DebugLevel) {
				logrus.Debugf("Skipping symlink %s during directory hash", path)
			}
			return nil
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		fileCount++

		if fileContext.ExcludesFile(path) {
			return nil
		}

		fileHash, hashErr := hashFileInDirAdaptive(path, fileContext, useMetadataOnly)
		if hashErr != nil {
			if logrus.IsLevelEnabled(logrus.DebugLevel) {
				logrus.Debugf("Failed to hash file %s: %v, skipping", path, hashErr)
			}
			return nil
		}

		if _, err := sha.Write([]byte(fileHash)); err != nil {
			return err
		}
		isEmpty = false
		return nil
	})

	return isEmpty, fileCount, err
}

// walkDirectoryForHash walks directory and hashes files (legacy implementation with timeouts)
func walkDirectoryForHash(
	hashCtx context.Context,
	p string,
	fileContext util.FileContext,
	sha hash.Hash,
	startTime time.Time,
) (isEmpty bool, fileCount int, err error) {
	// Use adaptive hashing if enabled
	if shouldUseAdaptiveHash() {
		// Count files first to determine strategy
		fileCountForStrategy, countErr := countFilesInDir(p, fileContext)
		if countErr != nil {
			logrus.Debugf("Failed to count files in directory %s: %v, using adaptive hashing", p, countErr)
		}

		useMetadataOnly := fileCountForStrategy > AdaptiveHashManyFilesThreshold
		return walkDirectoryForHashAdaptive(p, fileContext, sha, useMetadataOnly)
	}

	// Legacy implementation with timeouts (kept for backward compatibility)
	lastLogTime := startTime

	err = filepath.Walk(p, func(path string, info os.FileInfo, err error) error {
		select {
		case <-hashCtx.Done():
			logrus.Warnf("Directory hash canceled after processing %d files in %v (dir: %s)",
				fileCount, time.Since(startTime), p)
			return hashCtx.Err()
		default:
		}

		if err != nil {
			if os.IsNotExist(err) || os.IsPermission(err) {
				logrus.Debugf("File %s is not accessible during directory walk, skipping: %v", path, err)
				return nil
			}
			logrus.Debugf("Error accessing file %s during directory walk, skipping: %v", path, err)
			return nil
		}

		if info != nil && info.Mode()&os.ModeSymlink != 0 {
			logrus.Debugf("Skipping symlink %s during directory hash", path)
			return nil
		}

		fileCount++

		if time.Since(lastLogTime) > 10*time.Second {
			if logrus.IsLevelEnabled(logrus.DebugLevel) {
				logrus.Debugf("Still hashing directory %s: processed %d files in %v (current: %s)",
					p, fileCount, time.Since(startTime), path)
			}
			lastLogTime = time.Now()
		}

		if fileContext.ExcludesFile(path) {
			return nil
		}

		fileHash, hashErr := hashFileInDir(path, fileContext)
		if hashErr != nil {
			logrus.Debugf("Failed to hash file %s: %v, skipping", path, hashErr)
			return nil
		}

		if _, err := sha.Write([]byte(fileHash)); err != nil {
			return err
		}
		isEmpty = false
		return nil
	})

	return isEmpty, fileCount, err
}

// HashDir returns a hash of the directory.
// hashDir hashes a directory and all its files using adaptive strategy
func hashDir(p string, fileContext util.FileContext) (isEmpty bool, hashValue string, err error) {
	startTime := time.Now()
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logrus.Debugf("Starting directory hash for %s", p)
	}

	sha := sha256.New()

	// Use adaptive hashing if enabled
	if shouldUseAdaptiveHash() {
		// Count files first to determine strategy
		fileCount, countErr := countFilesInDir(p, fileContext)
		if countErr != nil {
			logrus.Debugf("Failed to count files in directory %s: %v, using adaptive hashing", p, countErr)
		}

		useMetadataOnly := fileCount > AdaptiveHashManyFilesThreshold
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			if useMetadataOnly {
				logrus.Debugf("Directory %s has %d files, using metadata-only hashing", p, fileCount)
			} else {
				logrus.Debugf("Directory %s has %d files, using adaptive hashing", p, fileCount)
			}
		}

		empty, actualFileCount, walkErr := walkDirectoryForHashAdaptive(p, fileContext, sha, useMetadataOnly)
		if walkErr != nil {
			return false, "", walkErr
		}

		duration := time.Since(startTime)
		if duration > 10*time.Second {
			logrus.Infof("Directory hash completed: %d files in %v (dir: %s)", actualFileCount, duration, p)
		} else if logrus.IsLevelEnabled(logrus.DebugLevel) {
			logrus.Debugf("Directory hash completed: %d files in %v (dir: %s)", actualFileCount, duration, p)
		}

		return empty, fmt.Sprintf("%x", sha.Sum(nil)), nil
	}

	// Legacy implementation with timeouts (kept for backward compatibility)
	timeout := parseHashDirTimeout()
	hashCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	logrus.Debugf("Starting directory hash for %s (timeout: %v)", p, timeout)

	legacySha := sha256.New()
	empty, fileCount, err := walkDirectoryForHash(hashCtx, p, fileContext, legacySha, startTime)

	if err != nil {
		if err == context.DeadlineExceeded || err == context.Canceled {
			logrus.Warnf("Directory hash timed out after processing %d files in %v (dir: %s)",
				fileCount, time.Since(startTime), p)
			return false, fmt.Sprintf("%x", legacySha.Sum(nil)), nil
		}
		return false, "", err
	}

	duration := time.Since(startTime)
	if duration > 10*time.Second {
		logrus.Infof("Directory hash completed: %d files in %v (dir: %s)", fileCount, duration, p)
	} else {
		logrus.Debugf("Directory hash completed: %d files in %v (dir: %s)", fileCount, duration, p)
	}

	return empty, fmt.Sprintf("%x", legacySha.Sum(nil)), nil
}
