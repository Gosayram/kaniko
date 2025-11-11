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

package cache

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/config"
)

// mmapReader provides memory-mapped file reading for faster access
// Experimental feature for local file cache optimization
//
//nolint:unused // Experimental feature, may be used in future
type mmapReader struct {
	data   []byte
	file   *os.File
	closed bool
}

// ReadAt implements io.ReaderAt for mmap
//
//nolint:unused // Experimental feature, may be used in future
func (mr *mmapReader) ReadAt(p []byte, off int64) (n int, err error) {
	if mr.closed {
		return 0, io.EOF
	}
	if off < 0 || off >= int64(len(mr.data)) {
		return 0, io.EOF
	}
	n = copy(p, mr.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// Close unmaps the memory and closes the file
//
//nolint:unused // Experimental feature, may be used in future
func (mr *mmapReader) Close() error {
	if mr.closed {
		return nil
	}
	mr.closed = true
	if mr.data != nil {
		// Unmap memory (platform-specific)
		if err := syscall.Munmap(mr.data); err != nil {
			logrus.Warnf("Failed to unmap memory: %v", err)
		}
	}
	if mr.file != nil {
		return mr.file.Close()
	}
	return nil
}

// openMMap opens a file using memory mapping (experimental)
// Note: Currently not used directly, but kept for future optimization
//
//nolint:unused // Experimental feature, may be used in future
func openMMap(filePath string) (io.ReaderAt, io.Closer, error) {
	// Validate file path to prevent directory traversal
	cleanPath := filepath.Clean(filePath)
	if strings.Contains(cleanPath, "..") {
		return nil, nil, fmt.Errorf("invalid file path: %s", filePath)
	}
	file, err := os.Open(cleanPath)
	if err != nil {
		return nil, nil, err
	}

	// Get file size
	fi, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}

	size := fi.Size()
	if size == 0 {
		_ = file.Close()
		return &bytes.Reader{}, file, nil
	}

	// Memory map the file
	data, err := syscall.Mmap(int(file.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		_ = file.Close()
		return nil, nil, fmt.Errorf("failed to mmap file: %w", err)
	}

	reader := &mmapReader{
		data: data,
		file: file,
	}

	return reader, reader, nil
}

// isCompressed checks if a file is compressed based on extension
//
//nolint:unused // Experimental feature, may be used in future
func isCompressed(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	lowerPath := strings.ToLower(filePath)
	return ext == ".gz" || ext == ".zstd" ||
		strings.HasSuffix(lowerPath, ".gz") ||
		strings.HasSuffix(lowerPath, ".zstd")
}

// getCompressedPath returns the compressed file path
//
//nolint:unused // Used by loadImageFromCompressedFile
func getCompressedPath(filePath string, compression config.Compression) string {
	switch compression {
	case config.GZip:
		return filePath + ".gz"
	case config.ZStd:
		return filePath + ".zstd"
	default:
		return filePath
	}
}

// readCompressedFile reads and decompresses a file
//
//nolint:unused // Used by loadImageFromCompressedFile
func readCompressedFile(filePath string, compression config.Compression) (io.Reader, error) {
	compressedPath := getCompressedPath(filePath, compression)
	// Validate file path to prevent directory traversal
	cleanPath := filepath.Clean(compressedPath)
	if strings.Contains(cleanPath, "..") {
		return nil, fmt.Errorf("invalid file path: %s", compressedPath)
	}

	file, err := os.Open(cleanPath)
	if err != nil {
		return nil, err
	}

	switch compression {
	case config.GZip:
		return gzip.NewReader(file)
	case config.ZStd:
		// Zstd decompression would require github.com/klauspost/compress/zstd
		// For now, return error if zstd is requested but not available
		_ = file.Close()
		return nil, fmt.Errorf("zstd decompression not yet implemented, use gzip or disable compression")
	default:
		return file, nil
	}
}

// readerAtOpener converts io.ReaderAt to tarball.Opener
//
//nolint:unused // Experimental feature, may be used in future
func readerAtOpener(readerAt io.ReaderAt, size int64) tarball.Opener {
	return func() (io.ReadCloser, error) {
		return io.NopCloser(io.NewSectionReader(readerAt, 0, size)), nil
	}
}

// loadImageFromCompressedFile loads an image from a compressed file
//
//nolint:unused // Used by cachedImageFromPathOptimized
func loadImageFromCompressedFile(p string, compression config.Compression) (v1.Image, error) {
	compressedPath := getCompressedPath(p, compression)
	if _, statErr := os.Stat(compressedPath); statErr != nil {
		return nil, nil // File doesn't exist, not an error
	}

	// Compressed file exists, read and decompress
	decompressedReader, decompressErr := readCompressedFile(p, compression)
	if decompressErr != nil {
		return nil, fmt.Errorf("failed to decompress file: %w", decompressErr)
	}

	// Read all decompressed data into memory
	decompressedData, readErr := io.ReadAll(decompressedReader)
	if readErr != nil {
		return nil, fmt.Errorf("failed to read decompressed data: %w", readErr)
	}

	// Create temporary file for decompressed data
	tmpFile, tmpErr := os.CreateTemp("", "kaniko-decompressed-*.tar")
	if tmpErr != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", tmpErr)
	}
	defer os.Remove(tmpFile.Name()) // Clean up temp file

	if _, writeErr := tmpFile.Write(decompressedData); writeErr != nil {
		_ = tmpFile.Close()
		return nil, fmt.Errorf("failed to write decompressed data: %w", writeErr)
	}
	_ = tmpFile.Close()

	// Load image from temporary file
	img, err := tarball.ImageFromPath(tmpFile.Name(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load image from decompressed file: %w", err)
	}
	return img, nil
}

// loadImageFromRegularFile loads an image from a regular file path
//
//nolint:unused // Used by cachedImageFromPathOptimized
func loadImageFromRegularFile(p string, useMMap bool) (v1.Image, error) {
	img, err := tarball.ImageFromPath(p, nil)
	if err != nil && useMMap {
		logrus.Debugf("Failed to load image with mmap option, falling back to regular read: %v", err)
		// Fallback to regular file
		img, err = tarball.ImageFromPath(p, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load image from path: %w", err)
	}
	return img, nil
}

// loadManifestIfExists loads manifest from path if it exists
//
//nolint:unused // Used by cachedImageFromPathOptimized
func loadManifestIfExists(p string) *v1.Manifest {
	mfstPath := p + ".json"
	if _, err := os.Stat(mfstPath); err != nil {
		return nil
	}
	mfst, err := mfstFromPath(mfstPath)
	if err != nil {
		logrus.Debugf("Error parsing manifest from file: %s", mfstPath)
		return nil
	}
	logrus.Infof("Found manifest at %s", mfstPath)
	return mfst
}

// cachedImageFromPathOptimized loads an image from path with optional mmap and compression support
// Experimental feature for local file cache optimization
//
//nolint:unused // Experimental feature, may be used in future
func cachedImageFromPathOptimized(p string, opts *config.CacheOptions) (v1.Image, error) {
	var img v1.Image
	var err error

	// Check if file is compressed
	if opts != nil && opts.LocalCacheCompress {
		compression := opts.LocalCacheCompression
		if compression == "" {
			compression = config.ZStd // Default
		}
		img, err = loadImageFromCompressedFile(p, compression)
		if err != nil {
			return nil, err
		}
	}

	// If not compressed or compression failed, try regular file or mmap
	if img == nil {
		useMMap := opts != nil && opts.LocalCacheUseMMap
		img, err = loadImageFromRegularFile(p, useMMap)
		if err != nil {
			return nil, err
		}
	}

	// Load manifest if exists
	mfst := loadManifestIfExists(p)

	return &cachedImage{
		digest: filepath.Base(p),
		Image:  img,
		mfst:   mfst,
	}, nil
}

// Platform-specific mmap implementation
// Note: This is a simplified implementation. For production use, consider using
// a library like github.com/edsrzf/mmap-go for cross-platform support
