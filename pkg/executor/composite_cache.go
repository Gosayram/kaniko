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
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/util"
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
	hash, err := util.SHA256(strings.NewReader(s.Key()))
	if err != nil {
		return "", err
	}

	// Cache the result
	s.cachedHash = hash
	s.hashComputed = true

	return hash, nil
}

// AddPath adds a file or directory path to the composite cache key
func (s *CompositeCache) AddPath(p string, context util.FileContext) error {
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
		isEmptyDir, k, hashErr := hashDir(p, context)
		if hashErr != nil {
			return hashErr
		}

		// Only add the hash of this directory to the key
		// if there is any ignored content.
		if !isEmptyDir || !context.ExcludesFile(p) {
			s.keys = append(s.keys, k)
		}
		// Invalidate hash cache when directory hash is added
		s.hashComputed = false
		s.cachedHash = ""
		return nil
	}

	if context.ExcludesFile(p) {
		return nil
	}

	// Use new FileHashCache with invalidation if opts are available
	// Otherwise fall back to old cache for backward compatibility
	var fh string
	if opts := getOptsForHashCache(); opts != nil {
		// Use new cache with invalidation
		var hashErr error
		fh, hashErr = getFileHashWithCache(p, context, opts)
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
	return nil
}

// HashDir returns a hash of the directory.
func hashDir(p string, context util.FileContext) (isEmpty bool, hash string, err error) {
	sha := sha256.New()
	empty := true
	if err := filepath.Walk(p, func(path string, _ os.FileInfo, err error) error {
		if err != nil {
			// If individual file access fails, log warning and continue
			// This prevents build failures when some files are inaccessible
			if os.IsNotExist(err) {
				logrus.Debugf("File %s does not exist during directory walk, skipping", path)
				return nil
			}
			return err
		}
		exclude := context.ExcludesFile(path)
		if exclude {
			return nil
		}

		// Use new FileHashCache with invalidation if opts are available
		// Otherwise fall back to old cache for backward compatibility
		var fileHash string
		if opts := getOptsForHashCache(); opts != nil {
			// Use new cache with invalidation
			var hashErr error
			fileHash, hashErr = getFileHashWithCache(path, context, opts)
			if hashErr != nil {
				// If file hashing fails, log warning and continue
				// This prevents build failures when some files can't be hashed
				logrus.Debugf("Failed to hash file %s: %v, skipping", path, hashErr)
				return nil
			}
		} else {
			// Fall back to old cache (backward compatibility)
			fileHashCacheMu.RLock()
			cachedHash, exists := fileHashCache[path]
			fileHashCacheMu.RUnlock()

			if exists {
				fileHash = cachedHash
			} else {
				// Compute hash if not cached
				// Use partial hashing for large files (default: 10MB limit)
				// This reduces CPU usage while maintaining good change detection
				var hashErr error
				maxFileHashSize := int64(defaultMaxFileHashSizeMB * fileHashBytesPerMegabyte) // Default: 10MB
				hasher := util.CacheHasherWithLimit(maxFileHashSize)
				fileHash, hashErr = hasher(path)
				if hashErr != nil {
					// If file hashing fails, log warning and continue
					// This prevents build failures when some files can't be hashed
					logrus.Debugf("Failed to hash file %s: %v, skipping", path, hashErr)
					return nil
				}
				// Cache the result (per performance plan: cache file hashes)
				fileHashCacheMu.Lock()
				fileHashCache[path] = fileHash
				fileHashCacheMu.Unlock()
			}
		}

		if _, err := sha.Write([]byte(fileHash)); err != nil {
			return err
		}
		empty = false
		return nil
	}); err != nil {
		return false, "", err
	}

	return empty, fmt.Sprintf("%x", sha.Sum(nil)), nil
}
