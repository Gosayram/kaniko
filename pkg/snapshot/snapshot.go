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

package snapshot

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/pkg/errors"

	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/filesystem"
	"github.com/Gosayram/kaniko/pkg/timing"
	"github.com/Gosayram/kaniko/pkg/util"

	"github.com/sirupsen/logrus"
)

// For testing
var snapshotPathPrefix = ""

// Snapshotter holds the root directory from which to take snapshots, and a list of snapshots taken
type Snapshotter struct {
	l          *LayeredMap
	directory  string
	ignorelist []util.IgnoreListEntry
	// Incremental snapshotting support
	incremental    *IncrementalSnapshotter
	useIncremental bool
}

// NewSnapshotter creates a new snapshotter rooted at d
func NewSnapshotter(l *LayeredMap, d string) *Snapshotter {
	return &Snapshotter{l: l, directory: d, ignorelist: util.IgnoreList()}
}

// EnableIncrementalSnapshots enables incremental snapshotting for better performance
func (s *Snapshotter) EnableIncrementalSnapshots() {
	s.useIncremental = true
	s.incremental = NewIncrementalSnapshotter(s)
	logrus.Info("Incremental snapshots enabled")
}

// ConfigureIncrementalSnapshots configures incremental snapshotter with options
func (s *Snapshotter) ConfigureIncrementalSnapshots(
	maxExpectedChanges int,
	integrityCheck, fullScanBackup bool,
	fullScanInterval time.Duration,
	scanCountThreshold int,
) {
	if s.incremental == nil {
		s.EnableIncrementalSnapshots()
	}

	if maxExpectedChanges > 0 {
		s.incremental.SetMaxExpectedChanges(maxExpectedChanges)
	}
	if fullScanInterval > 0 {
		s.incremental.SetFullScanInterval(fullScanInterval)
	}
	if scanCountThreshold > 0 {
		s.incremental.SetScanCountThreshold(scanCountThreshold)
	}
	s.incremental.SetIntegrityCheck(integrityCheck)
	s.incremental.SetFullScanBackup(fullScanBackup)

	// Enable filesystem watcher automatically if available (per plan - real-time change detection)
	// This provides faster change detection without periodic scanning
	if s.incremental != nil {
		if err := s.incremental.EnableWatcher(); err != nil {
			logrus.Debugf("Filesystem watcher not available: %v (will use hash-based detection)", err)
		} else {
			// Watch the root directory for changes
			if err := s.incremental.WatchPath(s.directory); err != nil {
				logrus.Debugf("Failed to watch root directory: %v (will use hash-based detection)", err)
			}
		}
	}

	logrus.Infof("Incremental snapshots configured: maxChanges=%d, integrity=%v, backup=%v, interval=%v, threshold=%d",
		maxExpectedChanges, integrityCheck, fullScanBackup, fullScanInterval, scanCountThreshold)
}

// DisableIncrementalSnapshots disables incremental snapshotting
func (s *Snapshotter) DisableIncrementalSnapshots() {
	s.useIncremental = false
	s.incremental = nil
	logrus.Info("Incremental snapshots disabled")
}

// Init initializes a new snapshotter
func (s *Snapshotter) Init() error {
	logrus.Info("Initializing snapshotter ...")
	_, _, err := s.scanFullFilesystem()
	return err
}

// Key returns a string based on the current state of the file system
func (s *Snapshotter) Key() (string, error) {
	return s.l.Key()
}

// TakeSnapshot takes a snapshot of the specified files, avoiding directories in the ignorelist, and creates
// a tarball of the changed files. Return contents of the tarball, and whether or not any files were changed
func (s *Snapshotter) TakeSnapshot(files []string, shdCheckDelete, forceBuildMetadata bool) (string, error) {
	// Use incremental snapshots if enabled
	if s.useIncremental && s.incremental != nil {
		// If no specific files provided, use full incremental snapshot
		if len(files) == 0 && !forceBuildMetadata {
			logrus.Debugf("Using incremental snapshot (full scan)")
			return s.takeIncrementalSnapshot(shdCheckDelete)
		}

		// If specific files provided, use incremental detection for those files
		// This uses hash cache to detect which files actually changed
		if len(files) > 0 && !forceBuildMetadata {
			logrus.Debugf("Using incremental snapshot for %d specified files", len(files))
			return s.takeIncrementalSnapshotForFiles(files, shdCheckDelete)
		}
	}

	// Fallback to regular snapshot
	return s.takeRegularSnapshot(files, shdCheckDelete, forceBuildMetadata)
}

// takeIncrementalSnapshot performs an incremental snapshot
func (s *Snapshotter) takeIncrementalSnapshot(_ bool) (string, error) {
	return s.incremental.TakeIncrementalSnapshot()
}

// takeIncrementalSnapshotForFiles performs an incremental snapshot for specific files
// Uses hash cache to detect which files actually changed
func (s *Snapshotter) takeIncrementalSnapshotForFiles(files []string, shdCheckDelete bool) (string, error) {
	if s.incremental == nil {
		return s.takeRegularSnapshot(files, shdCheckDelete, false)
	}

	// Detect changed files using incremental snapshotter's cache
	changedFiles := s.incremental.DetectChangedFiles(files)

	if len(changedFiles) == 0 {
		logrus.Debugf("No files changed among %d specified files, skipping snapshot", len(files))
		return "", nil
	}

	logrus.Debugf("Detected %d changed files out of %d specified", len(changedFiles), len(files))

	// Use regular snapshot for changed files only
	return s.takeRegularSnapshot(changedFiles, shdCheckDelete, false)
}

// verifyFilesExist checks if files exist before adding to layered map
func verifyFilesExist(filesToAdd []string) {
	for _, file := range filesToAdd {
		if _, statErr := os.Lstat(file); statErr != nil {
			if os.IsNotExist(statErr) {
				logrus.Warnf("File %s does not exist on filesystem when trying to add to layered map!", file)
				logrus.Warnf("This file will be skipped and NOT included in the snapshot!")
			} else {
				logrus.Warnf("Failed to stat file %s: %v", file, statErr)
			}
		}
	}
}

// addFilesToLayeredMap adds files to the current layer in the layered map
func (s *Snapshotter) addFilesToLayeredMap(filesToAdd []string) error {
	for _, file := range filesToAdd {
		if addErr := s.l.Add(file); addErr != nil {
			logrus.Errorf("Failed to add file %s to layered map: %v", file, addErr)
			return fmt.Errorf("unable to add file %s to layered map: %w", file, addErr)
		}
		logrus.Tracef("Added file to layered map: %s", file)
	}
	return nil
}

// getWhiteoutFiles gets files to whiteout for deleted files
func (s *Snapshotter) getWhiteoutFiles(shdCheckDelete bool) ([]string, error) {
	if !shdCheckDelete {
		return nil, nil
	}

	_, deletedFiles := util.WalkFS(s.directory, s.l.GetCurrentPaths(), func(_ string) (bool, error) {
		return true, nil
	})

	logrus.Debugf("Deleting in layer: %v", deletedFiles)
	// Whiteout files in current layer.
	for file := range deletedFiles {
		if deleteErr := s.l.AddDelete(file); deleteErr != nil {
			return nil, fmt.Errorf("unable to whiteout file %s in layered map: %w", file, deleteErr)
		}
	}

	filesToWhiteout := removeObsoleteWhiteouts(deletedFiles)
	sort.Strings(filesToWhiteout)
	return filesToWhiteout, nil
}

// verifyTarFile verifies that tar file was created and has content
func verifyTarFile(tarFile *os.File, expectedFileCount int) {
	fi, statErr := tarFile.Stat()
	if statErr != nil {
		logrus.Warnf("Failed to stat tar file: %v", statErr)
		return
	}

	logrus.Debugf("Tar file created: %s, size: %d bytes", tarFile.Name(), fi.Size())
	if fi.Size() == 0 && expectedFileCount > 0 {
		logrus.Warnf("WARNING: Tar file is empty but %d files were supposed to be written!", expectedFileCount)
	}
}

// takeRegularSnapshot performs a regular snapshot (original implementation)
func (s *Snapshotter) takeRegularSnapshot(files []string, shdCheckDelete, forceBuildMetadata bool) (string, error) {
	f, createErr := os.CreateTemp(config.KanikoDir, "")
	if createErr != nil {
		return "", createErr
	}
	defer f.Close()

	s.l.Snapshot()
	if len(files) == 0 && !forceBuildMetadata {
		logrus.Warnf("No files changed in this command (files list is empty), " +
			"skipping snapshotting. This means NO LAYER will be created!")
		logrus.Warnf("If this is a COPY command, the copied files may not be included in the final image!")
		return "", nil
	}

	filesToAdd, resolveErr := filesystem.ResolvePaths(files, s.ignorelist)
	if resolveErr != nil {
		return "", resolveErr
	}

	logrus.Info("Taking snapshot of files...")
	logrus.Debugf("Files to snapshot: %v (count: %d)", filesToAdd, len(filesToAdd))

	sort.Strings(filesToAdd)

	// Verify files exist before adding to layered map
	verifyFilesExist(filesToAdd)

	logrus.Debugf("Adding to layer: %v", filesToAdd)

	// Add files to current layer.
	if err := s.addFilesToLayeredMap(filesToAdd); err != nil {
		return "", err
	}

	// Get whiteout paths
	filesToWhiteout, whiteoutErr := s.getWhiteoutFiles(shdCheckDelete)
	if whiteoutErr != nil {
		return "", whiteoutErr
	}

	t := util.NewTar(f)
	defer t.Close()

	logrus.Debugf("About to write %d files to tar snapshot", len(filesToAdd))
	if len(filesToAdd) > 0 {
		logrus.Debugf("Files to write to tar: %v", filesToAdd)
	}

	// Removed filesystem sync - simplified approach per plan
	// Files are written directly, no need for explicit sync

	if writeErr := writeToTar(t, filesToAdd, filesToWhiteout); writeErr != nil {
		return "", fmt.Errorf("failed to write files to tar: %w", writeErr)
	}

	// Verify tar file was created and has content
	verifyTarFile(f, len(filesToAdd))

	return f.Name(), nil
}

// TakeSnapshotFS takes a snapshot of the filesystem, avoiding directories in the ignorelist, and creates
// a tarball of the changed files.
func (s *Snapshotter) TakeSnapshotFS() (string, error) {
	f, err := os.CreateTemp(s.getSnapshotPathPrefix(), "")
	if err != nil {
		return "", err
	}
	defer f.Close()
	t := util.NewTar(f)
	defer t.Close()

	filesToAdd, filesToWhiteOut, err := s.scanFullFilesystem()
	if err != nil {
		return "", err
	}

	if err := writeToTar(t, filesToAdd, filesToWhiteOut); err != nil {
		return "", err
	}
	return f.Name(), nil
}

func (s *Snapshotter) getSnapshotPathPrefix() string {
	if snapshotPathPrefix == "" {
		return config.KanikoDir
	}
	return snapshotPathPrefix
}

func (s *Snapshotter) scanFullFilesystem() (filesToAdd, filesToWhiteout []string, err error) {
	logrus.Info("Taking snapshot of full filesystem...")

	// Removed filesystem sync - simplified approach per plan
	// Files are read directly, no need for explicit sync
	// The filesystem and OS handle buffering appropriately

	s.l.Snapshot()

	logrus.Debugf("Current image filesystem: %v", s.l.currentImage)

	// Use SafeSnapshotOptimizer for better hidden file support
	// MaxExpectedChanges: threshold for integrity checking
	// - Small projects (< 100 files): 500-1000
	// - Medium projects (100-1000 files): 2000-5000
	// - Large projects (1000+ files): 5000-10000
	// - Enterprise projects (10000+ files): 10000-50000
	const defaultMaxExpectedChanges = 5000 // Increased for better large project support
	optimizer := NewSafeSnapshotOptimizer(s, &config.KanikoOptions{
		EnableParallelExec: true,
		IntegrityCheck:     true,
		MaxExpectedChanges: defaultMaxExpectedChanges,
	})

	changedPaths, deletedPaths, err := optimizer.OptimizedWalkFS(s.directory, s.l.GetCurrentPaths())
	if err != nil {
		// Simplified: no fallback - if optimizer fails, return error
		return nil, nil, errors.Wrap(err, "optimized filesystem walk failed")
	}
	timer := timing.Start("Resolving Paths")

	filesToAdd = []string{}
	resolvedFiles, err := filesystem.ResolvePaths(changedPaths, s.ignorelist)
	if err != nil {
		return nil, nil, err
	}
	for _, path := range resolvedFiles {
		if util.CheckIgnoreList(path) {
			logrus.Debugf("Not adding %s to layer, as it's ignored", path)
			continue
		}
		filesToAdd = append(filesToAdd, path)
	}

	logrus.Debugf("Adding to layer: %v", filesToAdd)
	logrus.Debugf("Deleting in layer: %v", deletedPaths)

	// Add files to the layered map
	for _, file := range filesToAdd {
		if err := s.l.Add(file); err != nil {
			return nil, nil, fmt.Errorf("unable to add file %s to layered map: %w", file, err)
		}
	}
	for file := range deletedPaths {
		if err := s.l.AddDelete(file); err != nil {
			return nil, nil, fmt.Errorf("unable to whiteout file %s in layered map: %w", file, err)
		}
	}

	filesToWhiteout = removeObsoleteWhiteouts(deletedPaths)
	timing.DefaultRun.Stop(timer)

	sort.Strings(filesToAdd)
	sort.Strings(filesToWhiteout)

	return filesToAdd, filesToWhiteout, nil
}

// removeObsoleteWhiteouts filters deleted files according to their parents delete status.
func removeObsoleteWhiteouts(deletedFiles map[string]struct{}) (filesToWhiteout []string) {
	for path := range deletedFiles {
		// Only add the whiteout if the directory for the file still exists.
		dir := filepath.Dir(path)
		if _, ok := deletedFiles[dir]; !ok {
			logrus.Tracef("Adding whiteout for %s", path)
			filesToWhiteout = append(filesToWhiteout, path)
		}
	}

	return filesToWhiteout
}

func writeToTar(t util.Tar, files, whiteouts []string) error {
	timer := timing.Start("Writing tar file")
	defer timing.DefaultRun.Stop(timer)

	// Now create the tar.
	addedPaths := make(map[string]bool)

	for _, path := range whiteouts {
		skipWhiteout, err := parentPathIncludesNonDirectory(path)
		if err != nil {
			return err
		}
		if skipWhiteout {
			continue
		}

		if err := addParentDirectories(t, addedPaths, path); err != nil {
			return err
		}
		if err := t.Whiteout(path); err != nil {
			return err
		}
	}

	for _, path := range files {
		// Verify file exists before adding to tar
		if _, statErr := os.Lstat(path); statErr != nil {
			if os.IsNotExist(statErr) {
				logrus.Warnf("CRITICAL: File %s does not exist when trying to write to tar! "+
					"This file will NOT be in the layer!", path)
				logrus.Warnf("This may cause files to be missing in subsequent stages or final image!")
				continue
			}
			logrus.Warnf("Failed to stat file %s: %v, skipping", path, statErr)
			continue
		}

		if err := addParentDirectories(t, addedPaths, path); err != nil {
			logrus.Warnf("Failed to add parent directories for %s: %v", path, err)
			return err
		}
		if _, pathAdded := addedPaths[path]; pathAdded {
			logrus.Debugf("Path %s already added to tar, skipping", path)
			continue
		}
		logrus.Debugf("Adding file to tar: %s", path)
		if err := t.AddFileToTar(path); err != nil {
			logrus.Errorf("CRITICAL: Failed to add file %s to tar: %v - this file will NOT be in the layer!", path, err)
			return fmt.Errorf("failed to add file %s to tar: %w", path, err)
		}
		addedPaths[path] = true
		logrus.Debugf("Successfully added file to tar: %s", path)
	}
	logrus.Debugf("Total files written to tar: %d", len(addedPaths))
	return nil
}

// Returns true if a parent of the given path has been replaced with anything other than a directory
func parentPathIncludesNonDirectory(path string) (bool, error) {
	for _, parentPath := range util.ParentDirectories(path) {
		lstat, err := os.Lstat(parentPath)
		if err != nil {
			return false, err
		}

		if !lstat.IsDir() {
			return true, nil
		}
	}
	return false, nil
}

func addParentDirectories(t util.Tar, addedPaths map[string]bool, path string) error {
	for _, parentPath := range util.ParentDirectories(path) {
		if _, pathAdded := addedPaths[parentPath]; pathAdded {
			continue
		}
		if err := t.AddFileToTar(parentPath); err != nil {
			return err
		}
		addedPaths[parentPath] = true
	}
	return nil
}

// filesWithLinks returns the symlink and the target path if its exists.
func filesWithLinks(path string) ([]string, error) {
	link, err := util.GetSymLink(path)
	if errors.Is(err, util.ErrNotSymLink) {
		return []string{path}, nil
	} else if err != nil {
		return nil, err
	}
	// Add symlink if it exists in the FS
	if !filepath.IsAbs(link) {
		link = filepath.Join(filepath.Dir(path), link)
	}
	if _, err := os.Stat(link); err != nil {
		return []string{path}, nil //nolint:nilerr // it's acceptable to ignore file not found errors for symlink targets
	}
	return []string{path, link}, nil
}
