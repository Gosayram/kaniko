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
	"os"
	"path/filepath"
	"time"
)

// FileSystemInterface defines the interface for file system operations.
// This interface abstracts file system operations to allow for easy mocking in tests
// and provides a consistent API for file operations across the application.
type FileSystemInterface interface {
	// File operations
	Open(name string) (*os.File, error)
	Create(name string) (*os.File, error)
	OpenFile(name string, flag int, perm os.FileMode) (*os.File, error)
	ReadFile(name string) ([]byte, error)
	WriteFile(name string, data []byte, perm os.FileMode) error
	Remove(name string) error
	RemoveAll(path string) error

	// Directory operations
	Mkdir(name string, perm os.FileMode) error
	MkdirAll(path string, perm os.FileMode) error
	ReadDir(name string) ([]os.DirEntry, error)
	Stat(name string) (os.FileInfo, error)
	Lstat(name string) (os.FileInfo, error)

	// Symlink operations
	Readlink(name string) (string, error)
	Symlink(oldname, newname string) error

	// Path operations
	Walk(root string, fn filepath.WalkFunc) error
	Glob(pattern string) ([]string, error)

	// Utility operations
	Chmod(name string, mode os.FileMode) error
	Chown(name string, uid, gid int) error
	Chtimes(name string, atime, mtime time.Time) error
}

// RealFileSystem implements FileSystemInterface using real file system operations.
// This is the default implementation that delegates to the standard library's os package.
type RealFileSystem struct{}

// NewRealFileSystem creates a new real file system instance.
// This function returns a FileSystemInterface that uses the actual file system.
func NewRealFileSystem() FileSystemInterface {
	return &RealFileSystem{}
}

// Open opens a file for reading
func (fs *RealFileSystem) Open(name string) (*os.File, error) {
	return os.Open(name)
}

// Create creates a file for writing
func (fs *RealFileSystem) Create(name string) (*os.File, error) {
	return os.Create(name)
}

// OpenFile opens a file with specified flags and permissions
func (fs *RealFileSystem) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(name, flag, perm)
}

// ReadFile reads the entire file content
func (fs *RealFileSystem) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

// WriteFile writes data to a file
func (fs *RealFileSystem) WriteFile(name string, data []byte, perm os.FileMode) error {
	return os.WriteFile(name, data, perm)
}

// Remove removes a file or empty directory
func (fs *RealFileSystem) Remove(name string) error {
	return os.Remove(name)
}

// RemoveAll removes a file or directory and all its contents
func (fs *RealFileSystem) RemoveAll(path string) error {
	return os.RemoveAll(path)
}

// Mkdir creates a directory
func (fs *RealFileSystem) Mkdir(name string, perm os.FileMode) error {
	return os.Mkdir(name, perm)
}

// MkdirAll creates a directory and all parent directories
func (fs *RealFileSystem) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

// ReadDir reads a directory
func (fs *RealFileSystem) ReadDir(name string) ([]os.DirEntry, error) {
	return os.ReadDir(name)
}

// Stat returns file information
func (fs *RealFileSystem) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

// Lstat returns file information without following symlinks
func (fs *RealFileSystem) Lstat(name string) (os.FileInfo, error) {
	return os.Lstat(name)
}

// Readlink reads the target of a symlink
func (fs *RealFileSystem) Readlink(name string) (string, error) {
	return os.Readlink(name)
}

// Symlink creates a symlink
func (fs *RealFileSystem) Symlink(oldname, newname string) error {
	return os.Symlink(oldname, newname)
}

// Walk walks a directory tree
func (fs *RealFileSystem) Walk(root string, fn filepath.WalkFunc) error {
	return filepath.Walk(root, fn)
}

// Glob matches files by pattern
func (fs *RealFileSystem) Glob(pattern string) ([]string, error) {
	return filepath.Glob(pattern)
}

// Chmod changes file permissions
func (fs *RealFileSystem) Chmod(name string, mode os.FileMode) error {
	return os.Chmod(name, mode)
}

// Chown changes file ownership
func (fs *RealFileSystem) Chown(name string, uid, gid int) error {
	return os.Chown(name, uid, gid)
}

// Chtimes changes file access and modification times
func (fs *RealFileSystem) Chtimes(name string, atime, mtime time.Time) error {
	return os.Chtimes(name, atime, mtime)
}

// MockFileSystem implements FileSystemInterface for testing.
// This mock provides an in-memory file system that can be used in tests
// to avoid dependencies on the actual file system.
type MockFileSystem struct {
	// File contents
	Files map[string][]byte
	// Directory contents
	Directories map[string][]string
	// File permissions
	Permissions map[string]os.FileMode
	// File ownership
	Ownership map[string]struct{ UID, GID int }
	// Symlinks
	Symlinks map[string]string
	// Errors to return for specific operations
	Errors map[string]error
	// File info
	FileInfos map[string]os.FileInfo
}

// NewMockFileSystem creates a new mock file system.
// This function initializes a MockFileSystem with empty maps for files, directories,
// permissions, ownership, symlinks, errors, and file info.
func NewMockFileSystem() *MockFileSystem {
	return &MockFileSystem{
		Files:       make(map[string][]byte),
		Directories: make(map[string][]string),
		Permissions: make(map[string]os.FileMode),
		Ownership:   make(map[string]struct{ UID, GID int }),
		Symlinks:    make(map[string]string),
		Errors:      make(map[string]error),
		FileInfos:   make(map[string]os.FileInfo),
	}
}

// SetError sets an error to return for a specific operation
func (mfs *MockFileSystem) SetError(operation, path string, err error) {
	key := operation + ":" + path
	mfs.Errors[key] = err
}

// SetFile sets file content in the mock
func (mfs *MockFileSystem) SetFile(path string, content []byte) {
	mfs.Files[path] = content
}

// SetDirectory sets directory contents in the mock
func (mfs *MockFileSystem) SetDirectory(path string, entries []string) {
	mfs.Directories[path] = entries
}

// SetSymlink sets a symlink target in the mock
func (mfs *MockFileSystem) SetSymlink(link, target string) {
	mfs.Symlinks[link] = target
}

// Open opens a file for reading (mock implementation)
func (mfs *MockFileSystem) Open(name string) (*os.File, error) {
	if err, exists := mfs.Errors["open:"+name]; exists {
		return nil, err
	}
	if content, exists := mfs.Files[name]; exists {
		// Create a temporary file with the content
		tmpFile, err := os.CreateTemp("", "mock-file-")
		if err != nil {
			return nil, err
		}
		_, err = tmpFile.Write(content)
		if err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			return nil, err
		}
		tmpFile.Seek(0, 0)
		return tmpFile, nil
	}
	return nil, os.ErrNotExist
}

// Create creates a file for writing (mock implementation)
func (mfs *MockFileSystem) Create(name string) (*os.File, error) {
	if err, exists := mfs.Errors["create:"+name]; exists {
		return nil, err
	}
	// In a real mock, you might want to track this differently
	tmpFile, err := os.CreateTemp("", "mock-create-")
	if err != nil {
		return nil, err
	}
	return tmpFile, nil
}

// OpenFile opens a file with specified flags and permissions (mock implementation)
func (mfs *MockFileSystem) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	if err, exists := mfs.Errors["openfile:"+name]; exists {
		return nil, err
	}
	// Simplified mock implementation
	return mfs.Open(name)
}

// ReadFile reads the entire file content (mock implementation)
func (mfs *MockFileSystem) ReadFile(name string) ([]byte, error) {
	if err, exists := mfs.Errors["readfile:"+name]; exists {
		return nil, err
	}
	if content, exists := mfs.Files[name]; exists {
		return content, nil
	}
	return nil, os.ErrNotExist
}

// WriteFile writes data to a file (mock implementation)
func (mfs *MockFileSystem) WriteFile(name string, data []byte, perm os.FileMode) error {
	if err, exists := mfs.Errors["writefile:"+name]; exists {
		return err
	}
	mfs.Files[name] = data
	mfs.Permissions[name] = perm
	return nil
}

// Remove removes a file or empty directory (mock implementation)
func (mfs *MockFileSystem) Remove(name string) error {
	if err, exists := mfs.Errors["remove:"+name]; exists {
		return err
	}
	delete(mfs.Files, name)
	delete(mfs.Directories, name)
	delete(mfs.Symlinks, name)
	return nil
}

// RemoveAll removes a file or directory and all its contents (mock implementation)
func (mfs *MockFileSystem) RemoveAll(path string) error {
	if err, exists := mfs.Errors["removeall:"+path]; exists {
		return err
	}
	// Remove all files, directories, and symlinks
	for key := range mfs.Files {
		delete(mfs.Files, key)
	}
	for key := range mfs.Directories {
		delete(mfs.Directories, key)
	}
	for key := range mfs.Symlinks {
		delete(mfs.Symlinks, key)
	}
	return nil
}

// Mkdir creates a directory (mock implementation)
func (mfs *MockFileSystem) Mkdir(name string, perm os.FileMode) error {
	if err, exists := mfs.Errors["mkdir:"+name]; exists {
		return err
	}
	mfs.Directories[name] = []string{}
	mfs.Permissions[name] = perm
	return nil
}

// MkdirAll creates a directory and all parent directories (mock implementation)
func (mfs *MockFileSystem) MkdirAll(path string, perm os.FileMode) error {
	if err, exists := mfs.Errors["mkdirall:"+path]; exists {
		return err
	}
	mfs.Directories[path] = []string{}
	mfs.Permissions[path] = perm
	return nil
}

// ReadDir reads a directory (mock implementation)
func (mfs *MockFileSystem) ReadDir(name string) ([]os.DirEntry, error) {
	if err, exists := mfs.Errors["readdir:"+name]; exists {
		return nil, err
	}
	if entries, exists := mfs.Directories[name]; exists {
		// Convert string entries to DirEntry mock
		dirEntries := make([]os.DirEntry, len(entries))
		for i, entry := range entries {
			dirEntries[i] = &mockDirEntry{name: entry}
		}
		return dirEntries, nil
	}
	return nil, os.ErrNotExist
}

// Stat returns file information (mock implementation)
func (mfs *MockFileSystem) Stat(name string) (os.FileInfo, error) {
	if err, exists := mfs.Errors["stat:"+name]; exists {
		return nil, err
	}
	if info, exists := mfs.FileInfos[name]; exists {
		return info, nil
	}
	// Check if file exists in our mock
	if _, exists := mfs.Files[name]; exists {
		return &mockFileInfo{name: filepath.Base(name)}, nil
	}
	if _, exists := mfs.Directories[name]; exists {
		return &mockFileInfo{name: filepath.Base(name)}, nil
	}
	if _, exists := mfs.Symlinks[name]; exists {
		return &mockFileInfo{name: filepath.Base(name)}, nil
	}
	return nil, os.ErrNotExist
}

// Lstat returns file information without following symlinks (mock implementation)
func (mfs *MockFileSystem) Lstat(name string) (os.FileInfo, error) {
	return mfs.Stat(name)
}

// Readlink reads the target of a symlink (mock implementation)
func (mfs *MockFileSystem) Readlink(name string) (string, error) {
	if err, exists := mfs.Errors["readlink:"+name]; exists {
		return "", err
	}
	if target, exists := mfs.Symlinks[name]; exists {
		return target, nil
	}
	return "", os.ErrNotExist
}

// Symlink creates a symlink (mock implementation)
func (mfs *MockFileSystem) Symlink(oldname, newname string) error {
	if err, exists := mfs.Errors["symlink:"+newname]; exists {
		return err
	}
	mfs.Symlinks[newname] = oldname
	return nil
}

// Walk walks a directory tree (mock implementation)
func (mfs *MockFileSystem) Walk(root string, fn filepath.WalkFunc) error {
	if err, exists := mfs.Errors["walk:"+root]; exists {
		return err
	}
	// Simplified mock implementation
	return nil
}

// Glob matches files by pattern (mock implementation)
func (mfs *MockFileSystem) Glob(pattern string) ([]string, error) {
	if err, exists := mfs.Errors["glob:"+pattern]; exists {
		return nil, err
	}
	// Simplified mock implementation
	return []string{}, nil
}

// Chmod changes file permissions (mock implementation)
func (mfs *MockFileSystem) Chmod(name string, mode os.FileMode) error {
	if err, exists := mfs.Errors["chmod:"+name]; exists {
		return err
	}
	mfs.Permissions[name] = mode
	return nil
}

// Chown changes file ownership (mock implementation)
func (mfs *MockFileSystem) Chown(name string, uid, gid int) error {
	if err, exists := mfs.Errors["chown:"+name]; exists {
		return err
	}
	mfs.Ownership[name] = struct{ UID, GID int }{uid, gid}
	return nil
}

// Chtimes changes file access and modification times (mock implementation)
func (mfs *MockFileSystem) Chtimes(name string, atime, mtime time.Time) error {
	if err, exists := mfs.Errors["chtimes:"+name]; exists {
		return err
	}
	return nil
}

// mockDirEntry implements os.DirEntry for testing
type mockDirEntry struct {
	name string
}

func (mde *mockDirEntry) Name() string {
	return mde.name
}

func (mde *mockDirEntry) IsDir() bool {
	return false // Simplified
}

func (mde *mockDirEntry) Type() os.FileMode {
	return 0
}

func (mde *mockDirEntry) Info() (os.FileInfo, error) {
	return &mockFileInfo{name: mde.name}, nil
}

// mockFileInfo implements os.FileInfo for testing
type mockFileInfo struct {
	name string
}

func (mfi *mockFileInfo) Name() string {
	return mfi.name
}

func (mfi *mockFileInfo) Size() int64 {
	return 0
}

func (mfi *mockFileInfo) Mode() os.FileMode {
	return 0644
}

func (mfi *mockFileInfo) ModTime() time.Time {
	return time.Now()
}

func (mfi *mockFileInfo) IsDir() bool {
	return false
}

func (mfi *mockFileInfo) Sys() interface{} {
	return nil
}
