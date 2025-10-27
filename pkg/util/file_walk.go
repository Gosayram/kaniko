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
	"path/filepath"

	"github.com/karrick/godirwalk"
	"github.com/sirupsen/logrus"
)

// Common file system walking patterns
// These functions provide common patterns used by both GetFSInfoMap and WalkFS
// while maintaining their specific behavior requirements.

// CommonIgnoreCheckResult represents the result of checking if a path should be ignored
type CommonIgnoreCheckResult struct {
	ShouldIgnore  bool
	ShouldSkipDir bool
}

// CheckPathAgainstIgnoreList is a common function that checks if a path should be ignored
// This consolidates the similar logic used in both GetFSInfoMap and WalkFS
func CheckPathAgainstIgnoreList(path string, useCleanedPath bool) CommonIgnoreCheckResult {
	var shouldIgnore bool

	if useCleanedPath {
		shouldIgnore = CheckCleanedPathAgainstIgnoreList(path)
	} else {
		shouldIgnore = IsInIgnoreList(path)
	}

	if shouldIgnore {
		if IsDestDir(path) {
			return CommonIgnoreCheckResult{
				ShouldIgnore:  true,
				ShouldSkipDir: true,
			}
		}
		return CommonIgnoreCheckResult{
			ShouldIgnore:  true,
			ShouldSkipDir: false,
		}
	}

	return CommonIgnoreCheckResult{
		ShouldIgnore:  false,
		ShouldSkipDir: false,
	}
}

// CommonFileProcessingCallback provides a common callback pattern for file processing
// This can be used by both GetFSInfoMap and WalkFS with different implementations
type CommonFileProcessingCallback func(path string, ent *godirwalk.Dirent) error

// CreateCommonCallback creates a common callback function that handles ignore list checking
// and delegates the actual file processing to a provided function
func CreateCommonCallback(
	ignoreResult CommonIgnoreCheckResult,
	processFile func(path string, ent *godirwalk.Dirent) error,
) CommonFileProcessingCallback {
	return func(path string, ent *godirwalk.Dirent) error {
		_ = ent // unused parameter

		if ignoreResult.ShouldIgnore {
			if ignoreResult.ShouldSkipDir {
				logrus.Tracef("Skipping paths under %s, as it is an ignored directory", path)
				return filepath.SkipDir
			}
			return nil
		}

		return processFile(path, ent)
	}
}

// Common godirwalk patterns and utilities
// These functions provide common patterns used across different file system operations

// CommonWalkOptions provides common options for godirwalk.Walk operations
type CommonWalkOptions struct {
	Unsorted bool
	Callback CommonFileProcessingCallback
}

// DefaultWalkOptions returns default options for godirwalk.Walk
func DefaultWalkOptions() CommonWalkOptions {
	return CommonWalkOptions{
		Unsorted: true,
		Callback: nil, // Will be set by caller
	}
}

// CreateWalkOptions creates godirwalk.Options from CommonWalkOptions
func CreateWalkOptions(opts CommonWalkOptions) *godirwalk.Options {
	return &godirwalk.Options{
		Callback: godirwalk.WalkFunc(opts.Callback),
		Unsorted: opts.Unsorted,
	}
}

// CommonIgnoreHandling provides common patterns for handling ignored files
type CommonIgnoreHandling struct {
	UseCleanedPath bool
	LogIgnored     bool
	LogMessage     string
}

// DefaultIgnoreHandling returns default ignore handling configuration
func DefaultIgnoreHandling() CommonIgnoreHandling {
	return CommonIgnoreHandling{
		UseCleanedPath: false,
		LogIgnored:     true,
		LogMessage:     "Not processing %s, as it's ignored",
	}
}

// CreateIgnoreCallback creates a callback that handles ignore list checking
// with configurable behavior
func CreateIgnoreCallback(
	handling CommonIgnoreHandling,
	processFile func(path string, ent *godirwalk.Dirent) error,
) CommonFileProcessingCallback {
	return func(path string, ent *godirwalk.Dirent) error {
		_ = ent // unused parameter

		// Check if path should be ignored
		ignoreResult := CheckPathAgainstIgnoreList(path, handling.UseCleanedPath)

		if ignoreResult.ShouldIgnore {
			if ignoreResult.ShouldSkipDir {
				logrus.Tracef("Skipping paths under '%s', as it is an ignored directory", path)
				return filepath.SkipDir
			}

			if handling.LogIgnored {
				logrus.Debugf(handling.LogMessage, path)
			}
			return nil
		}

		return processFile(path, ent)
	}
}
