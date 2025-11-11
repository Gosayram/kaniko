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

package util //nolint:revive // package name 'util' is intentionally generic

import (
	"crypto/md5" //nolint:gosec // MD5 used for non-cryptographic purposes (file change detection)
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/minio/highwayhash"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	// highwayhashBlockSize is the size of blocks used for highwayhash computation
	highwayhashBlockSize = highwayhash.Size * 10 * 1024
	// initialXattrBufferSize is the initial buffer size for xattr operations
	initialXattrBufferSize = 128
	// exponentialBackoffBase is the base multiplier for exponential backoff
	exponentialBackoffBase = 2
)

// Hasher returns a hash function, used in snapshotting to determine if a file has changed
func Hasher() func(string) (string, error) {
	pool := sync.Pool{
		New: func() interface{} {
			b := make([]byte, highwayhashBlockSize)
			return &b
		},
	}
	key := make([]byte, highwayhash.Size)
	hasher := func(p string) (string, error) {
		h, _ := highwayhash.New(key)
		fi, err := os.Lstat(p)
		if err != nil {
			return "", err
		}
		h.Write([]byte(fi.Mode().String()))
		h.Write([]byte(fi.ModTime().String()))

		h.Write([]byte(strconv.FormatUint(uint64(fi.Sys().(*syscall.Stat_t).Uid), 36)))
		h.Write([]byte(","))
		h.Write([]byte(strconv.FormatUint(uint64(fi.Sys().(*syscall.Stat_t).Gid), 36)))

		if fi.Mode().IsRegular() {
			capability, _ := Lgetxattr(p, "security.capability")
			if capability != nil {
				h.Write(capability)
			}
			// Validate the file path to prevent directory traversal
			if err := ValidateFilePath(p); err != nil {
				return "", err
			}
			// #nosec G304 - path is validated before use
			f, err := os.Open(p)
			if err != nil {
				return "", err
			}
			defer f.Close()
			buf := pool.Get().(*[]byte)
			defer pool.Put(buf)
			if _, err := io.CopyBuffer(h, f, *buf); err != nil {
				return "", err
			}
		} else if fi.Mode()&os.ModeSymlink == os.ModeSymlink {
			linkPath, err := os.Readlink(p)
			if err != nil {
				return "", err
			}
			h.Write([]byte(linkPath))
		}

		return hex.EncodeToString(h.Sum(nil)), nil
	}
	return hasher
}

// CacheHasher takes into account everything the regular hasher does except for mtime
func CacheHasher() func(string) (string, error) {
	return CacheHasherWithLimit(0) // 0 = no limit, full hashing
}

// CacheHasherWithLimit creates a hasher with a size limit for partial hashing of large files
// For files larger than maxFileHashSize, uses partial hashing (first 64KB + last 64KB + size)
// For files <= maxFileHashSize, uses full hashing
// maxFileHashSize: 0 = no limit (full hashing), >0 = use partial hashing for larger files
func CacheHasherWithLimit(maxFileHashSize int64) func(string) (string, error) {
	const partialHashChunkSize = 64 * 1024 // 64KB chunks for partial hashing

	hasher := func(p string) (string, error) {
		// MD5 is used here for non-cryptographic purposes (file change detection)
		// The hash is only used internally for caching, not for security-sensitive operations
		h := md5.New() //nolint:gosec // MD5 acceptable for internal non-crypto use
		fi, err := os.Lstat(p)
		if err != nil {
			return "", err
		}

		// Hash file metadata (mode, uid, gid)
		hashFileMetadata(h, fi)

		// Hash file content based on file type
		if fi.Mode().IsRegular() {
			if err := hashRegularFile(h, p, fi.Size(), maxFileHashSize, partialHashChunkSize); err != nil {
				return "", err
			}
		} else if fi.Mode()&os.ModeSymlink == os.ModeSymlink {
			if err := hashSymlink(h, p); err != nil {
				return "", err
			}
		}

		return hex.EncodeToString(h.Sum(nil)), nil
	}
	return hasher
}

// hashFileMetadata hashes file metadata (mode, uid, gid)
func hashFileMetadata(h hash.Hash, fi os.FileInfo) {
	h.Write([]byte(fi.Mode().String()))
	h.Write([]byte(strconv.FormatUint(uint64(fi.Sys().(*syscall.Stat_t).Uid), 36)))
	h.Write([]byte(","))
	h.Write([]byte(strconv.FormatUint(uint64(fi.Sys().(*syscall.Stat_t).Gid), 36)))
}

// hashRegularFile hashes a regular file (partial or full based on size)
func hashRegularFile(h hash.Hash, path string, fileSize, maxFileHashSize, partialHashChunkSize int64) error {
	// Validate the file path to prevent directory traversal
	if err := ValidateFilePath(path); err != nil {
		return err
	}

	usePartialHashing := maxFileHashSize > 0 && fileSize > maxFileHashSize

	if usePartialHashing {
		return hashFilePartial(h, path, fileSize, partialHashChunkSize)
	}
	return hashFileFull(h, path)
}

// hashFilePartial performs partial hashing for large files: first 64KB + last 64KB + size
func hashFilePartial(h hash.Hash, path string, fileSize, partialHashChunkSize int64) error {
	// #nosec G304 - path is validated before use
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Hash file size first
	h.Write([]byte(strconv.FormatInt(fileSize, 10)))

	// Optimized: use buffer pool instead of make() to reduce allocations
	bufferPool := GetGlobalBufferPool()
	chunk := bufferPool.GetMediumBuffer() // 64KB = medium buffer
	defer bufferPool.PutMediumBuffer(chunk)

	// Read and hash first chunk
	n, err := f.ReadAt(chunk, 0)
	if err != nil && err != io.EOF {
		return err
	}
	if n > 0 {
		h.Write(chunk[:n])
	}

	// Read and hash last chunk (if file is large enough)
	if fileSize > partialHashChunkSize {
		startPos := fileSize - partialHashChunkSize
		if startPos < 0 {
			startPos = 0
		}
		n, err := f.ReadAt(chunk, startPos)
		if err != nil && err != io.EOF {
			return err
		}
		if n > 0 {
			h.Write(chunk[:n])
		}
	}

	return nil
}

// hashFileFull performs full hashing for small files
func hashFileFull(h hash.Hash, path string) error {
	// #nosec G304 - path is validated before use
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Use buffer pool for io.Copy to reduce allocations
	bufferPool := GetGlobalBufferPool()
	buf := bufferPool.GetMediumBuffer() // 64KB buffer for file reading
	defer bufferPool.PutMediumBuffer(buf)

	if _, err := io.CopyBuffer(h, f, buf); err != nil {
		return err
	}
	return nil
}

// hashSymlink hashes a symlink by reading its target path
func hashSymlink(h hash.Hash, path string) error {
	linkPath, err := os.Readlink(path)
	if err != nil {
		return err
	}
	h.Write([]byte(linkPath))
	return nil
}

// MtimeHasher returns a hash function, which only looks at mtime to determine if a file has changed.
// Note that the mtime can lag, so it's possible that a file will have changed but the mtime may look the same.
func MtimeHasher() func(string) (string, error) {
	hasher := func(p string) (string, error) {
		// MD5 is used here for non-cryptographic purposes (mtime-based change detection)
		// The hash is only used internally for performance optimization, not security
		h := md5.New() //nolint:gosec // MD5 acceptable for internal non-crypto use
		fi, err := os.Lstat(p)
		if err != nil {
			return "", err
		}
		h.Write([]byte(fi.ModTime().String()))
		return hex.EncodeToString(h.Sum(nil)), nil
	}
	return hasher
}

// RedoHasher returns a hash function, which looks at mtime, size, filemode, owner uid and gid
// Note that the mtime can lag, so it's possible that a file will have changed but the mtime may look the same.
func RedoHasher() func(string) (string, error) {
	hasher := func(p string) (string, error) {
		// MD5 is used here for non-cryptographic purposes (file metadata hashing)
		// The hash is only used internally for redo logging, not for security purposes
		h := md5.New() //nolint:gosec // MD5 acceptable for internal non-crypto use
		fi, err := os.Lstat(p)
		if err != nil {
			return "", err
		}

		// Optimized: conditional logging to reduce CPU usage in hot path
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			logrus.Debugf("Hash components for file: %s, mode: %s, mtime: %s, size: %s, user-id: %s, group-id: %s",
				p, fi.Mode().String(), fi.ModTime().String(),
				strconv.FormatInt(fi.Size(), 16), strconv.FormatUint(uint64(fi.Sys().(*syscall.Stat_t).Uid), 36),
				strconv.FormatUint(uint64(fi.Sys().(*syscall.Stat_t).Gid), 36))
		}

		h.Write([]byte(fi.Mode().String()))
		h.Write([]byte(fi.ModTime().String()))
		h.Write([]byte(strconv.FormatInt(fi.Size(), 16)))
		h.Write([]byte(strconv.FormatUint(uint64(fi.Sys().(*syscall.Stat_t).Uid), 36)))
		h.Write([]byte(","))
		h.Write([]byte(strconv.FormatUint(uint64(fi.Sys().(*syscall.Stat_t).Gid), 36)))

		return hex.EncodeToString(h.Sum(nil)), nil
	}
	return hasher
}

// SHA256 returns the shasum of the contents of r
func SHA256(r io.Reader) (string, error) {
	hasher := sha256.New()
	// Optimized: use buffer pool for io.Copy to reduce allocations
	bufferPool := GetGlobalBufferPool()
	buf := bufferPool.GetMediumBuffer() // 64KB buffer
	defer bufferPool.PutMediumBuffer(buf)
	_, err := io.CopyBuffer(hasher, r, buf)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(make([]byte, 0, hasher.Size()))), nil
}

// GetInputFrom returns Reader content
func GetInputFrom(r io.Reader) ([]byte, error) {
	output, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return output, nil
}

type retryFunc func() error

// Retry retries an operation with exponential backoff
func Retry(operation retryFunc, retryCount, initialDelayMilliseconds int) error {
	return RetryWithConfig(operation, retryCount, initialDelayMilliseconds, 0, 0, exponentialBackoffBase)
}

// RetryWithConfig retries an operation with configurable exponential backoff
// nolint:gocritic // paramTypeCombine: parameters are intentionally separated for clarity
func RetryWithConfig(
	operation retryFunc, retryCount, initialDelayMilliseconds, maxDelayMilliseconds int,
	backoffMultiplier, baseMultiplier float64,
) error {
	if backoffMultiplier <= 0 {
		backoffMultiplier = baseMultiplier
	}

	err := operation()
	for i := 0; err != nil && i < retryCount; i++ {
		// Calculate exponential backoff with jitter
		delay := int(math.Pow(backoffMultiplier, float64(i))) * initialDelayMilliseconds

		// Apply max delay limit if specified
		if maxDelayMilliseconds > 0 && delay > maxDelayMilliseconds {
			delay = maxDelayMilliseconds
		}

		sleepDuration := time.Millisecond * time.Duration(delay)
		logrus.Warnf("Retrying operation after %s due to %v (attempt %d/%d)", sleepDuration, err, i+1, retryCount+1)
		time.Sleep(sleepDuration)
		err = operation()
	}

	return err
}

// RetryWithResult retries an operation with a return value and exponential backoff
func RetryWithResult[T any](
	operation func() (T, error),
	retryCount, initialDelayMilliseconds int,
) (result T, err error) {
	return RetryWithResultConfig(operation, retryCount, initialDelayMilliseconds, 0, 0, exponentialBackoffBase)
}

// RetryWithResultConfig retries an operation with a return value and configurable exponential backoff
func RetryWithResultConfig[T any](
	operation func() (T, error),
	retryCount, initialDelayMilliseconds, maxDelayMilliseconds int,
	backoffMultiplier, baseMultiplier float64,
) (result T, err error) {
	if backoffMultiplier <= 0 {
		backoffMultiplier = baseMultiplier
	}

	result, err = operation()
	if err == nil {
		return result, nil
	}

	for i := 0; i < retryCount; i++ {
		// Calculate exponential backoff with jitter
		delay := int(math.Pow(backoffMultiplier, float64(i))) * initialDelayMilliseconds

		// Apply max delay limit if specified
		if maxDelayMilliseconds > 0 && delay > maxDelayMilliseconds {
			delay = maxDelayMilliseconds
		}

		sleepDuration := time.Millisecond * time.Duration(delay)
		logrus.Warnf("Retrying operation after %s due to %v (attempt %d/%d)", sleepDuration, err, i+1, retryCount+1)
		time.Sleep(sleepDuration)

		result, err = operation()
		if err == nil {
			return result, nil
		}
	}

	// Create a more descriptive error message for registry issues
	if strings.Contains(err.Error(), "503 Service Unavailable") ||
		strings.Contains(err.Error(), "unexpected status code 503") {
		return result, fmt.Errorf("registry temporarily unavailable after %d attempts, last error: %w. "+
			"This might be resolved by Runner's registry mirrors", retryCount, err)
	}

	return result, fmt.Errorf("unable to complete operation after %d attempts, last error: %w", retryCount, err)
}

// Lgetxattr retrieves extended attribute values for a file path.
// It handles buffer sizing automatically and returns the attribute value as bytes.
func Lgetxattr(path, attr string) ([]byte, error) {
	// Start with a 128 length byte array
	dest := make([]byte, initialXattrBufferSize)
	sz, errno := unix.Lgetxattr(path, attr, dest)

	for errors.Is(errno, unix.ERANGE) {
		// Buffer too small, use zero-sized buffer to get the actual size
		sz, errno = unix.Lgetxattr(path, attr, []byte{})
		if errno != nil {
			return nil, errno
		}
		dest = make([]byte, sz)
		sz, errno = unix.Lgetxattr(path, attr, dest)
	}

	switch {
	case errors.Is(errno, unix.ENODATA):
		return nil, nil
	case errno != nil:
		return nil, errno
	}

	return dest[:sz], nil
}
