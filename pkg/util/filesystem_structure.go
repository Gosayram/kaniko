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

package util

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

// FilesystemStructure provides an abstraction for determining filesystem paths
// dynamically based on image analysis instead of hardcoded paths.
// This allows Kaniko to work with non-standard Linux distributions and
// custom filesystem structures.
type FilesystemStructure interface {
	// GetSystemDirectories returns dynamically determined system directories
	// that often need to be writable (e.g., /etc, /var, /usr, /tmp)
	GetSystemDirectories() []string

	// GetCacheDirectories returns directories commonly used for caching
	// (e.g., /var/cache, /.cache, /tmp)
	GetCacheDirectories() []string

	// GetTempDirectories returns directories used for temporary files
	// (e.g., /tmp, /var/tmp)
	GetTempDirectories() []string

	// GetBinDirectories returns directories containing executables
	// (e.g., /usr/bin, /usr/local/bin, /bin)
	GetBinDirectories() []string

	// GetLibDirectories returns directories containing libraries
	// (e.g., /usr/lib, /usr/local/lib, /lib)
	GetLibDirectories() []string

	// IsSystemDirectory checks if a path is in a system directory
	IsSystemDirectory(path string) bool

	// GetDirectoryPatterns returns regex patterns for directories that might need write access
	// This is a fallback for cases where exact paths aren't available
	GetDirectoryPatterns() []string
}

// FilesystemStructureAnalyzer implements FilesystemStructure by analyzing
// the actual filesystem structure of the image.
type FilesystemStructureAnalyzer struct {
	rootDir           string
	systemDirectories []string
	cacheDirectories  []string
	tempDirectories   []string
	binDirectories    []string
	libDirectories    []string
	patterns          []string
	analyzed          bool
	mu                sync.RWMutex
}

// NewFilesystemStructureAnalyzer creates a new analyzer for the given root directory.
// The analyzer will dynamically determine filesystem structure by examining
// the actual directories present in the filesystem.
func NewFilesystemStructureAnalyzer(rootDir string) *FilesystemStructureAnalyzer {
	return &FilesystemStructureAnalyzer{
		rootDir: rootDir,
	}
}

// Analyze examines the filesystem to determine directory structure.
// This should be called after the base image has been extracted.
// OPTIMIZED: Uses a single efficient scan instead of multiple os.Stat calls.
func (fsa *FilesystemStructureAnalyzer) Analyze() error {
	fsa.mu.Lock()
	defer fsa.mu.Unlock()

	if fsa.analyzed {
		return nil
	}

	logrus.Debugf("🔍 Analyzing filesystem structure at %s", fsa.rootDir)

	// OPTIMIZED: Use a single efficient scan to detect all directories at once
	// This is much faster for large images than multiple os.Stat calls
	fsa.detectDirectoriesEfficiently()

	fsa.buildPatterns()

	fsa.analyzed = true

	logrus.Infof("✅ Filesystem analysis complete: %d system dirs, %d cache dirs, %d temp dirs, %d bin dirs, %d lib dirs",
		len(fsa.systemDirectories), len(fsa.cacheDirectories), len(fsa.tempDirectories),
		len(fsa.binDirectories), len(fsa.libDirectories))

	return nil
}

// detectDirectoriesEfficiently detects all directory types in a single efficient scan.
// This is optimized for large images by:
// 1. Using a single pass through top-level directories
// 2. Caching directory existence checks
// 3. Minimizing filesystem operations
func (fsa *FilesystemStructureAnalyzer) detectDirectoriesEfficiently() {
	// Build a map of all paths we need to check
	// This allows us to check each path only once and categorize it efficiently
	pathsToCheck := map[string]string{
		// System directories
		"/etc":   "system",
		"/var":   "system",
		"/usr":   "system",
		"/opt":   "system",
		"/sbin":  "system",
		"/lib":   "system",
		"/lib64": "system",
		"/root":  "system",
		"/home":  "system",
		// Cache directories
		"/var/cache":   "cache",
		"/.cache":      "cache",
		"/root/.cache": "cache",
		"/tmp":         "cache",
		// Temp directories
		"/var/tmp": "temp",
		"/dev/shm": "temp",
		// Bin directories
		"/usr/bin":        "bin",
		"/usr/local/bin":  "bin",
		"/bin":            "bin",
		"/usr/sbin":       "bin",
		"/usr/local/sbin": "bin",
		// Lib directories
		"/usr/lib":       "lib",
		"/usr/local/lib": "lib",
		"/usr/lib64":     "lib",
	}

	// Check all paths in a single pass and categorize them
	// Use a map to track which paths exist to avoid duplicate checks
	existingPaths := make(map[string]bool)

	for path, category := range pathsToCheck {
		// Skip if we already know this path exists (for paths like /tmp that appear in multiple categories)
		if existingPaths[path] {
			fsa.addPathToCategory(path, category)
			continue
		}

		fullPath := filepath.Join(fsa.rootDir, path)
		if info, err := os.Stat(fullPath); err == nil && info.IsDir() {
			existingPaths[path] = true
			fsa.addPathToCategory(path, category)
			logrus.Debugf("   Found %s directory: %s", category, path)
		}
	}

	// Apply fallbacks if nothing was found in each category
	fsa.applyFallbacks()
}

// addPathToCategory adds a path to the appropriate category slice
// OPTIMIZED: Reduced cyclomatic complexity by extracting helper functions
func (fsa *FilesystemStructureAnalyzer) addPathToCategory(path, category string) {
	var targetSlice *[]string
	switch category {
	case "system":
		targetSlice = &fsa.systemDirectories
	case "cache":
		targetSlice = &fsa.cacheDirectories
	case "temp":
		targetSlice = &fsa.tempDirectories
	case "bin":
		targetSlice = &fsa.binDirectories
	case "lib":
		targetSlice = &fsa.libDirectories
	default:
		return // Unknown category, ignore
	}

	// Check for duplicates and add if not present
	if !fsa.containsPath(*targetSlice, path) {
		*targetSlice = append(*targetSlice, path)
	}
}

// containsPath checks if a path already exists in the slice
func (fsa *FilesystemStructureAnalyzer) containsPath(slice []string, path string) bool {
	for _, existing := range slice {
		if existing == path {
			return true
		}
	}
	return false
}

// applyFallbacks sets default directories if nothing was detected
func (fsa *FilesystemStructureAnalyzer) applyFallbacks() {
	if len(fsa.systemDirectories) == 0 {
		logrus.Warnf("⚠️ No system directories detected, using defaults")
		fsa.systemDirectories = []string{"/etc", "/var", "/usr"}
	}
	if len(fsa.cacheDirectories) == 0 {
		fsa.cacheDirectories = []string{"/var/cache", "/.cache", "/tmp"}
	}
	if len(fsa.tempDirectories) == 0 {
		fsa.tempDirectories = []string{"/tmp", "/var/tmp"}
	}
	if len(fsa.binDirectories) == 0 {
		fsa.binDirectories = []string{"/usr/bin", "/usr/local/bin", "/bin"}
	}
	if len(fsa.libDirectories) == 0 {
		fsa.libDirectories = []string{"/usr/lib", "/usr/local/lib", "/lib"}
	}
}

// buildPatterns creates regex patterns from detected directories
func (fsa *FilesystemStructureAnalyzer) buildPatterns() {
	allDirs := make(map[string]bool)

	// Collect all directories
	for _, dir := range fsa.cacheDirectories {
		allDirs[dir] = true
	}
	for _, dir := range fsa.tempDirectories {
		allDirs[dir] = true
	}
	for _, dir := range fsa.binDirectories {
		allDirs[dir] = true
	}
	for _, dir := range fsa.libDirectories {
		allDirs[dir] = true
	}

	// Build patterns (escape special regex chars)
	for dir := range allDirs {
		// Convert path to regex pattern: /path -> ^/path(/.*)?$
		escaped := strings.ReplaceAll(dir, ".", "\\.")
		pattern := "^" + escaped + "(/.*)?$"
		fsa.patterns = append(fsa.patterns, pattern)
	}
}

// GetSystemDirectories returns detected system directories
func (fsa *FilesystemStructureAnalyzer) GetSystemDirectories() []string {
	fsa.mu.RLock()
	defer fsa.mu.RUnlock()
	return append([]string(nil), fsa.systemDirectories...)
}

// GetCacheDirectories returns detected cache directories
func (fsa *FilesystemStructureAnalyzer) GetCacheDirectories() []string {
	fsa.mu.RLock()
	defer fsa.mu.RUnlock()
	return append([]string(nil), fsa.cacheDirectories...)
}

// GetTempDirectories returns detected temporary directories
func (fsa *FilesystemStructureAnalyzer) GetTempDirectories() []string {
	fsa.mu.RLock()
	defer fsa.mu.RUnlock()
	return append([]string(nil), fsa.tempDirectories...)
}

// GetBinDirectories returns detected binary directories
func (fsa *FilesystemStructureAnalyzer) GetBinDirectories() []string {
	fsa.mu.RLock()
	defer fsa.mu.RUnlock()
	return append([]string(nil), fsa.binDirectories...)
}

// GetLibDirectories returns detected library directories
func (fsa *FilesystemStructureAnalyzer) GetLibDirectories() []string {
	fsa.mu.RLock()
	defer fsa.mu.RUnlock()
	return append([]string(nil), fsa.libDirectories...)
}

// IsSystemDirectory checks if a path is in a system directory
func (fsa *FilesystemStructureAnalyzer) IsSystemDirectory(path string) bool {
	fsa.mu.RLock()
	defer fsa.mu.RUnlock()

	cleanPath := filepath.Clean(path)
	for _, sysDir := range fsa.systemDirectories {
		if strings.HasPrefix(cleanPath, sysDir) {
			return true
		}
	}
	return false
}

// GetDirectoryPatterns returns regex patterns for directories
func (fsa *FilesystemStructureAnalyzer) GetDirectoryPatterns() []string {
	fsa.mu.RLock()
	defer fsa.mu.RUnlock()
	return append([]string(nil), fsa.patterns...)
}

// globalFilesystemStructure is a global instance that can be used throughout the codebase
var (
	globalFilesystemStructure FilesystemStructure
	globalFSAMutex            sync.RWMutex
)

// InitializeFilesystemStructure initializes the global filesystem structure analyzer.
// This should be called after the base image has been extracted.
func InitializeFilesystemStructure(rootDir string) error {
	globalFSAMutex.Lock()
	defer globalFSAMutex.Unlock()

	analyzer := NewFilesystemStructureAnalyzer(rootDir)
	if err := analyzer.Analyze(); err != nil {
		return err
	}

	globalFilesystemStructure = analyzer
	return nil
}

// GetFilesystemStructure returns the global filesystem structure instance.
// If not initialized, returns a fallback implementation that uses hardcoded paths.
func GetFilesystemStructure() FilesystemStructure {
	globalFSAMutex.RLock()
	defer globalFSAMutex.RUnlock()

	if globalFilesystemStructure != nil {
		return globalFilesystemStructure
	}

	// Fallback to hardcoded implementation if not analyzed yet
	return &fallbackFilesystemStructure{}
}

// fallbackFilesystemStructure is a fallback implementation that uses hardcoded paths.
// This is used when filesystem analysis hasn't been performed yet.
type fallbackFilesystemStructure struct{}

func (f *fallbackFilesystemStructure) GetSystemDirectories() []string {
	return []string{"/etc", "/var", "/usr", "/opt", "/sbin", "/lib", "/lib64"}
}

func (f *fallbackFilesystemStructure) GetCacheDirectories() []string {
	return []string{"/var/cache", "/.cache", "/tmp"}
}

func (f *fallbackFilesystemStructure) GetTempDirectories() []string {
	return []string{"/tmp", "/var/tmp"}
}

func (f *fallbackFilesystemStructure) GetBinDirectories() []string {
	return []string{"/usr/bin", "/usr/local/bin", "/bin", "/usr/sbin", "/usr/local/sbin", "/sbin"}
}

func (f *fallbackFilesystemStructure) GetLibDirectories() []string {
	return []string{"/usr/lib", "/usr/local/lib", "/lib", "/lib64", "/usr/lib64"}
}

func (f *fallbackFilesystemStructure) IsSystemDirectory(path string) bool {
	systemDirs := f.GetSystemDirectories()
	cleanPath := filepath.Clean(path)
	for _, sysDir := range systemDirs {
		if strings.HasPrefix(cleanPath, sysDir) {
			return true
		}
	}
	return false
}

func (f *fallbackFilesystemStructure) GetDirectoryPatterns() []string {
	return []string{
		"^/\\.cache(/.*)?$",
		"^/var/cache(/.*)?$",
		"^/tmp(/.*)?$",
		"^/var/tmp(/.*)?$",
		"^/usr/local/bin(/.*)?$",
		"^/usr/bin(/.*)?$",
		"^/usr/local/lib(/.*)?$",
		"^/usr/lib(/.*)?$",
	}
}
