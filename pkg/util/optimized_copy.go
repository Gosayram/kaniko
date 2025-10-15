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

package util

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// Constants for optimized copy
const (
	OptimizedMaxFileSize    = 500 * 1024 * 1024 // 500MB
	OptimizedMaxMemoryUsage = 100 * 1024 * 1024 // 100MB
	OptimizedBufferSize     = 64 * 1024         // 64KB
	OptimizedDirPerm        = 0o750
)

// OptimizedFileCopy provides memory-efficient file copying with resource limits
type OptimizedFileCopy struct {
	MaxFileSize      int64       // Maximum file size to copy
	MaxMemoryUsage   int64       // Maximum memory usage during copy
	BufferSize       int         // Buffer size for copying
	ProgressCallback func(int64) // Progress callback function
	startTime        time.Time
	bytesCopied      int64
	mutex            sync.Mutex
}

// NewOptimizedFileCopy creates a new optimized file copy instance
func NewOptimizedFileCopy() *OptimizedFileCopy {
	return &OptimizedFileCopy{
		MaxFileSize:    OptimizedMaxFileSize,    // 500MB default
		MaxMemoryUsage: OptimizedMaxMemoryUsage, // 100MB default
		BufferSize:     OptimizedBufferSize,     // 64KB default
		startTime:      time.Now(),
	}
}

// CopyFileWithOptimization copies a file using optimized memory management
func (ofc *OptimizedFileCopy) CopyFileWithOptimization(src, dst string) error {
	// Check source file exists and get size
	srcInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("failed to stat source file %s: %w", src, err)
	}

	// Check file size limit
	if srcInfo.Size() > ofc.MaxFileSize {
		return fmt.Errorf("file %s too large: %d bytes (max: %d)", src, srcInfo.Size(), ofc.MaxFileSize)
	}

	// Check memory usage before starting
	if memErr := ofc.checkMemoryUsage(); memErr != nil {
		return memErr
	}

	// Open source file
	srcFile, err := os.Open(filepath.Clean(src))
	if err != nil {
		return fmt.Errorf("failed to open source file %s: %w", src, err)
	}
	defer srcFile.Close()

	// Create destination directory if needed
	dstDir := filepath.Dir(dst)
	if mkdirErr := os.MkdirAll(dstDir, OptimizedDirPerm); mkdirErr != nil {
		return fmt.Errorf("failed to create destination directory %s: %w", dstDir, mkdirErr)
	}

	// Create destination file
	dstFile, err := os.Create(filepath.Clean(dst))
	if err != nil {
		return fmt.Errorf("failed to create destination file %s: %w", dst, err)
	}
	defer dstFile.Close()

	// Copy file using buffer pool
	bytesCopied, err := ofc.copyWithBufferPool(dstFile, srcFile)
	if err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	// Update progress
	ofc.mutex.Lock()
	ofc.bytesCopied += bytesCopied
	ofc.mutex.Unlock()

	// Call progress callback if provided
	if ofc.ProgressCallback != nil {
		ofc.ProgressCallback(bytesCopied)
	}

	// Preserve file permissions
	if err := os.Chmod(dst, srcInfo.Mode()); err != nil {
		return fmt.Errorf("failed to set file permissions: %w", err)
	}

	// Preserve file timestamps
	if err := os.Chtimes(dst, srcInfo.ModTime(), srcInfo.ModTime()); err != nil {
		return fmt.Errorf("failed to set file timestamps: %w", err)
	}

	return nil
}

// copyWithBufferPool copies data using a buffer from the pool
func (ofc *OptimizedFileCopy) copyWithBufferPool(dst io.Writer, src io.Reader) (int64, error) {
	// Get buffer from pool based on file size
	bufferSize := ofc.BufferSize
	if bufferSize > int(ofc.MaxFileSize) {
		bufferSize = int(ofc.MaxFileSize)
	}

	buf := GetBuffer(bufferSize)
	defer PutBuffer(buf)

	var totalWritten int64
	for {
		// Check memory usage periodically
		if totalWritten%int64(bufferSize) == 0 {
			if err := ofc.checkMemoryUsage(); err != nil {
				return totalWritten, err
			}
		}

		nr, er := src.Read(*buf)
		if nr > 0 {
			nw, ew := dst.Write((*buf)[:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = io.ErrShortWrite
				}
			}
			totalWritten += int64(nw)
			if ew != nil {
				return totalWritten, ew
			}
			if nr != nw {
				return totalWritten, io.ErrShortWrite
			}
		}
		if er != nil {
			if er != io.EOF {
				return totalWritten, er
			}
			break
		}
	}

	return totalWritten, nil
}

// checkMemoryUsage checks if memory usage is within limits
func (ofc *OptimizedFileCopy) checkMemoryUsage() error {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	if ofc.MaxMemoryUsage > 0 && m.Alloc > uint64(ofc.MaxMemoryUsage) {
		return fmt.Errorf("memory usage exceeded: %d bytes (max: %d)", m.Alloc, ofc.MaxMemoryUsage)
	}

	return nil
}

// GetCopyStatistics returns copy statistics
func (ofc *OptimizedFileCopy) GetCopyStatistics() map[string]interface{} {
	ofc.mutex.Lock()
	defer ofc.mutex.Unlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return map[string]interface{}{
		"bytes_copied":  ofc.bytesCopied,
		"duration":      time.Since(ofc.startTime),
		"memory_alloc":  m.Alloc,
		"memory_sys":    m.Sys,
		"gc_cycles":     m.NumGC,
		"buffer_size":   ofc.BufferSize,
		"max_file_size": ofc.MaxFileSize,
		"max_memory":    ofc.MaxMemoryUsage,
	}
}

// CopyFileOrSymlinkOptimized is an optimized version of CopyFileOrSymlink
func CopyFileOrSymlinkOptimized(src, dst, _ string) error {
	// Check if source is a symlink
	srcInfo, err := os.Lstat(src)
	if err != nil {
		return fmt.Errorf("failed to stat source %s: %w", src, err)
	}

	if srcInfo.Mode()&os.ModeSymlink != 0 {
		// Handle symlink
		target, err := os.Readlink(src)
		if err != nil {
			return fmt.Errorf("failed to read symlink %s: %w", src, err)
		}

		// Create destination directory
		dstDir := filepath.Dir(dst)
		if err := os.MkdirAll(dstDir, OptimizedDirPerm); err != nil {
			return fmt.Errorf("failed to create destination directory: %w", err)
		}

		// Create symlink
		if err := os.Symlink(target, dst); err != nil {
			return fmt.Errorf("failed to create symlink: %w", err)
		}

		return nil
	}

	// Handle regular file
	ofc := NewOptimizedFileCopy()
	return ofc.CopyFileWithOptimization(src, dst)
}
