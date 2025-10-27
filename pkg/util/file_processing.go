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

package util

import (
	"os"
)

// Common file operation patterns
// These functions provide common patterns used across different file operations
// while allowing for context-specific customization.

// ProcessFileWithCallback is a common pattern for processing files
// with a callback function. This can be used by both GetFSInfoMap and WalkFS
// with different callback implementations.
type ProcessFileWithCallback func(path string, info os.FileInfo) (bool, error)

// FileProcessorOptions contains options for file processing operations
type FileProcessorOptions struct {
	// IncludeHiddenFiles determines whether to process hidden files
	IncludeHiddenFiles bool
	// MaxDepth limits the maximum depth of directory traversal
	MaxDepth int
	// FollowSymlinks determines whether to follow symbolic links
	FollowSymlinks bool
	// BufferSize specifies the buffer size for file operations
	BufferSize int
}

// DefaultFileProcessorOptions returns default options for file processing
func DefaultFileProcessorOptions() FileProcessorOptions {
	return FileProcessorOptions{
		IncludeHiddenFiles: false,
		MaxDepth:           MaxSearchDepth,
		FollowSymlinks:     false,
		BufferSize:         DefaultBufferSize,
	}
}

// FileOperationResult represents the result of a file operation
type FileOperationResult struct {
	Success        bool
	Error          error
	FilesProcessed int
	FilesChanged   int
}

// Common file processing patterns
// These functions provide common patterns for different types of file processing

// FileProcessorType represents different types of file processing operations
type FileProcessorType int

const (
	// FileProcessorTypeStat processes files for stat information
	FileProcessorTypeStat FileProcessorType = iota
	// FileProcessorTypeDelete processes files for deletion
	FileProcessorTypeDelete
	// FileProcessorTypeCopy processes files for copying
	FileProcessorTypeCopy
	// FileProcessorTypeOwnership processes files for ownership changes
	FileProcessorTypeOwnership
)

// GetProcessorIgnoreHandling returns appropriate ignore handling for different processor types
func GetProcessorIgnoreHandling(processorType FileProcessorType) CommonIgnoreHandling {
	switch processorType {
	case FileProcessorTypeDelete:
		return CommonIgnoreHandling{
			UseCleanedPath: false,
			LogIgnored:     true,
			LogMessage:     "Not deleting %s, as it's ignored",
		}
	case FileProcessorTypeOwnership:
		return CommonIgnoreHandling{
			UseCleanedPath: false,
			LogIgnored:     true,
			LogMessage:     "Not copying ownership for %s, as it's ignored",
		}
	case FileProcessorTypeStat:
		return CommonIgnoreHandling{
			UseCleanedPath: true,
			LogIgnored:     false,
			LogMessage:     "",
		}
	default:
		return DefaultIgnoreHandling()
	}
}
