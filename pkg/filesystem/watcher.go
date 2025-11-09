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

package filesystem

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
)

const (
	// defaultChangesChannelSize is the default buffer size for the changes channel
	defaultChangesChannelSize = 100
)

// Watcher tracks filesystem changes in real-time using inotify/kqueue
// This is an optional optimization for faster change detection
// Note: Works on Linux (inotify), BSD/macOS (kqueue), and Windows (ReadDirectoryChangesW)
type Watcher struct {
	watchedPaths map[string]bool
	changes      chan string
	watcher      *fsnotify.Watcher
	mutex        sync.RWMutex
	enabled      bool
}

// NewFileSystemWatcher creates a new filesystem watcher
// Returns nil if watcher cannot be created (e.g., on unsupported systems)
func NewFileSystemWatcher() (*Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		// Watcher creation failed - return nil but don't error
		// This allows graceful degradation to polling-based detection
		logrus.Debugf("FileSystemWatcher not available: %v (will use polling)", err)
		return nil, nil
	}

	return &Watcher{
		watchedPaths: make(map[string]bool),
		changes:      make(chan string, defaultChangesChannelSize),
		watcher:      watcher,
		enabled:      true,
	}, nil
}

// Watch adds a path to watch for changes
func (w *Watcher) Watch(path string) error {
	if w == nil || !w.enabled {
		return nil // Watcher not available or disabled
	}

	w.mutex.Lock()
	defer w.mutex.Unlock()

	if w.watchedPaths[path] {
		return nil // Already watching
	}

	// Resolve absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	// Add directory to watch (fsnotify watches directories, not individual files)
	dir := absPath
	if info, err := os.Stat(absPath); err == nil && !info.IsDir() {
		dir = filepath.Dir(absPath)
	}

	if err := w.watcher.Add(dir); err != nil {
		logrus.Debugf("Failed to watch path %s: %v", dir, err)
		return err
	}

	w.watchedPaths[path] = true
	logrus.Debugf("Now watching path: %s (dir: %s)", path, dir)
	return nil
}

// Start begins watching for filesystem events
func (w *Watcher) Start() {
	if w == nil || !w.enabled {
		return
	}

	go func() {
		for {
			select {
			case event, ok := <-w.watcher.Events:
				if !ok {
					return
				}
				// Only track write and create events for now
				if event.Op&fsnotify.Write == fsnotify.Write ||
					event.Op&fsnotify.Create == fsnotify.Create ||
					event.Op&fsnotify.Remove == fsnotify.Remove {
					select {
					case w.changes <- event.Name:
					default:
						// Channel full - log but don't block
						logrus.Debugf("FileSystemWatcher: channel full, dropped event for %s", event.Name)
					}
				}
			case err, ok := <-w.watcher.Errors:
				if !ok {
					return
				}
				logrus.Debugf("FileSystemWatcher error: %v", err)
			}
		}
	}()
}

// GetChanges returns a channel of changed file paths
func (w *Watcher) GetChanges() <-chan string {
	if w == nil || !w.enabled {
		// Return closed channel if watcher not available
		ch := make(chan string)
		close(ch)
		return ch
	}
	return w.changes
}

// Stop stops watching and closes the watcher
func (w *Watcher) Stop() {
	if w == nil || !w.enabled {
		return
	}

	if w.watcher != nil {
		if err := w.watcher.Close(); err != nil {
			logrus.Debugf("Error closing FileSystemWatcher: %v", err)
		}
	}
	w.enabled = false
}

// IsFilesystemWatchingAvailable checks if filesystem watching is available on this platform
func IsFilesystemWatchingAvailable() bool {
	// fsnotify works on Linux, BSD, macOS, and Windows
	// But we might want to disable it on some platforms for performance reasons
	return runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "windows"
}

// GetWatchedPaths returns a list of currently watched paths
func (w *Watcher) GetWatchedPaths() []string {
	if w == nil || !w.enabled {
		return nil
	}

	w.mutex.RLock()
	defer w.mutex.RUnlock()

	paths := make([]string, 0, len(w.watchedPaths))
	for path := range w.watchedPaths {
		paths = append(paths, path)
	}
	return paths
}
