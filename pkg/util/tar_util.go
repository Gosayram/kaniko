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
	"archive/tar"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/system"
	"github.com/moby/go-archive/compression"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/config"
)

// Tar knows how to write files to a tar file.
type Tar struct {
	hardlinks map[uint64]string
	w         *tar.Writer
}

// NewTar will create an instance of Tar that can write files to the writer at f.
func NewTar(f io.Writer) Tar {
	w := tar.NewWriter(f)
	return Tar{
		w:         w,
		hardlinks: map[uint64]string{},
	}
}

// CreateTarballOfDirectory creates a tarball from the contents of the specified directory.
func CreateTarballOfDirectory(pathToDir string, f io.Writer) error {
	if !filepath.IsAbs(pathToDir) {
		return errors.New("pathToDir is not absolute")
	}
	tarWriter := NewTar(f)
	defer tarWriter.Close()

	walkFn := func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !filepath.IsAbs(path) {
			return fmt.Errorf("path %v is not absolute, cant read file", path)
		}
		return tarWriter.AddFileToTar(path)
	}

	return filepath.WalkDir(pathToDir, walkFn)
}

// Close will close any open streams used by Tar.
func (t *Tar) Close() {
	if err := t.w.Close(); err != nil {
		logrus.Debugf("Error closing tar writer: %v", err)
	}
}

// AddFileToTar adds the file at path p to the tar
func (t *Tar) AddFileToTar(p string) error {
	i, err := os.Lstat(p)
	if err != nil {
		return fmt.Errorf("failed to get file info for %s: %w", p, err)
	}

	// Handle sockets - ignore them
	if i.Mode()&os.ModeSocket != 0 {
		logrus.Infof("Ignoring socket %s, not adding to tar", i.Name())
		return nil
	}

	// Get link destination for symlinks
	linkDst, err := t.getLinkDestination(p, i)
	if err != nil {
		return err
	}

	// Create tar header
	hdr, err := t.createTarHeader(p, i, linkDst)
	if err != nil {
		return err
	}

	// Write header to tar
	if err := t.w.WriteHeader(hdr); err != nil {
		return err
	}

	// Write file content for regular files that aren't hardlinks
	if hdr.Typeflag == tar.TypeReg {
		return t.writeFileContent(p)
	}

	return nil
}

func (t *Tar) getLinkDestination(p string, i os.FileInfo) (string, error) {
	if i.Mode()&os.ModeSymlink != 0 {
		// Allow absolute paths; only block if link goes outside root when used
		return os.Readlink(p)
	}
	return "", nil
}

func (t *Tar) createTarHeader(p string, i os.FileInfo, linkDst string) (*tar.Header, error) {
	hdr, err := tar.FileInfoHeader(i, linkDst)
	if err != nil {
		return nil, err
	}

	// Read security xattrs
	if err := readSecurityXattrToTarHeader(p, hdr); err != nil {
		return nil, err
	}

	// Set header name
	t.setHeaderName(p, hdr)

	// Set header format and clear user/group names
	hdr.Uname = ""
	hdr.Gname = ""
	hdr.Format = tar.FormatPAX

	// Handle hardlinks
	t.handleHardlinks(p, i, hdr)

	return hdr, nil
}

func (t *Tar) setHeaderName(p string, hdr *tar.Header) {
	if p == config.RootDir {
		// allow entry for / to preserve permission changes etc. (currently ignored anyway by Docker runtime)
		hdr.Name = "/"
	} else {
		// Docker uses no leading / in the tarball
		hdr.Name = strings.TrimPrefix(p, config.RootDir)
		hdr.Name = strings.TrimLeft(hdr.Name, "/")
	}
	if hdr.Typeflag == tar.TypeDir && !strings.HasSuffix(hdr.Name, "/") {
		hdr.Name += "/"
	}
}

func (t *Tar) handleHardlinks(p string, i os.FileInfo, hdr *tar.Header) {
	hardlink, linkDst := t.checkHardlink(p, i)
	if hardlink {
		hdr.Linkname = linkDst
		hdr.Typeflag = tar.TypeLink
		hdr.Size = 0
	}
}

func (t *Tar) writeFileContent(p string) error {
	r, err := os.Open(p) // #nosec G304 -- path comes from controlled walk and Lstat above
	if err != nil {
		return err
	}
	defer r.Close()
	if _, err := io.Copy(t.w, r); err != nil {
		return err
	}
	return nil
}

const (
	securityCapabilityXattr = "security.capability"
)

// writeSecurityXattrToTarFile writes security.capability
// xattrs from a tar header to filesystem
func writeSecurityXattrToTarFile(path string, hdr *tar.Header) error {
	if hdr.PAXRecords == nil {
		return nil
	}
	if capability, ok := hdr.PAXRecords[securityCapabilityXattr]; ok {
		err := system.Lsetxattr(path, securityCapabilityXattr, []byte(capability), 0)
		if err != nil && !errors.Is(err, syscall.EOPNOTSUPP) && !errors.Is(err, system.ErrNotSupportedPlatform) {
			return errors.Wrapf(err, "failed to write %q attribute to %q", securityCapabilityXattr, path)
		}
	}
	return nil
}

// readSecurityXattrToTarHeader reads security.capability
// xattrs from filesystem to a tar header
func readSecurityXattrToTarHeader(path string, hdr *tar.Header) error {
	if hdr.PAXRecords == nil {
		hdr.PAXRecords = make(map[string]string)
	}
	capability, err := system.Lgetxattr(path, securityCapabilityXattr)
	if err != nil && !errors.Is(err, syscall.EOPNOTSUPP) && !errors.Is(err, system.ErrNotSupportedPlatform) {
		return errors.Wrapf(err, "failed to read %q attribute from %q", securityCapabilityXattr, path)
	}
	if capability != nil {
		hdr.PAXRecords[securityCapabilityXattr] = string(capability)
	}
	return nil
}

// Whiteout creates a whiteout file in the tar archive for the specified path.
func (t *Tar) Whiteout(p string) error {
	dir := filepath.Dir(p)
	name := archive.WhiteoutPrefix + filepath.Base(p)

	th := &tar.Header{
		// Docker uses no leading / in the tarball
		Name: strings.TrimLeft(filepath.Join(dir, name), "/"),
		Size: 0,
	}
	if err := t.w.WriteHeader(th); err != nil {
		return err
	}

	return nil
}

// checkHardlink checks if the path is a hardlink and returns the result.
// Returns:
// - bool: true if path is hardlink
// - string: the link destination
func (t *Tar) checkHardlink(p string, i os.FileInfo) (isHardlink bool, linkDestination string) {
	hardlink := false
	linkDst := ""
	stat := getSyscallStatT(i)
	if stat != nil {
		nlinks := stat.Nlink
		if nlinks > 1 {
			inode := stat.Ino
			if original, exists := t.hardlinks[inode]; exists && original != p {
				hardlink = true
				logrus.Debugf("%s inode exists in hardlinks map, linking to %s", p, original)
				linkDst = original
			} else {
				t.hardlinks[inode] = p
			}
		}
	}
	return hardlink, linkDst
}

func getSyscallStatT(i os.FileInfo) *syscall.Stat_t {
	if sys := i.Sys(); sys != nil {
		if stat, ok := sys.(*syscall.Stat_t); ok {
			return stat
		}
	}
	return nil
}

// UnpackLocalTarArchive unpacks the tar archive at path to the directory dest
// Returns the files extracted from the tar archive
func UnpackLocalTarArchive(path, dest string) ([]string, error) {
	// First, we need to check if the path is a local tar archive
	if compressed, compressionLevel := fileIsCompressedTar(path); compressed {
		// Validate the file path to prevent directory traversal
		cleanPath := filepath.Clean(path)
		if strings.Contains(cleanPath, "..") || strings.HasPrefix(cleanPath, "/") {
			return nil, fmt.Errorf("invalid file path: potential directory traversal detected")
		}
		file, err := os.Open(cleanPath)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		switch compressionLevel {
		case int(archive.Gzip):
			gzr, err := gzip.NewReader(file)
			if err != nil {
				return nil, err
			}
			defer gzr.Close()
			return UnTar(gzr, dest)
		case int(archive.Bzip2):
			bzr := bzip2.NewReader(file)
			return UnTar(bzr, dest)
		}
	}
	if fileIsUncompressedTar(path) {
		// Validate the file path to prevent directory traversal
		cleanPath := filepath.Clean(path)
		if strings.Contains(cleanPath, "..") || strings.HasPrefix(cleanPath, "/") {
			return nil, fmt.Errorf("invalid file path: potential directory traversal detected")
		}
		file, err := os.Open(cleanPath)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		return UnTar(file, dest)
	}
	return nil, errors.New("path does not lead to local tar archive")
}

// IsFileLocalTarArchive returns true if the file is a local tar archive
func IsFileLocalTarArchive(src string) bool {
	compressed, _ := fileIsCompressedTar(src)
	uncompressed := fileIsUncompressedTar(src)
	return compressed || uncompressed
}

func fileIsCompressedTar(src string) (isCompressed bool, compressionType int) {
	r, err := os.Open(src) // #nosec G304 -- validated/cleaned earlier in UnpackLocalTarArchive
	if err != nil {
		return false, -1
	}
	defer r.Close()
	buf, err := io.ReadAll(r)
	if err != nil {
		return false, -1
	}
	compressionLevel := compression.Detect(buf)
	return (compressionLevel > 0), int(compressionLevel)
}

func fileIsUncompressedTar(src string) bool {
	r, err := os.Open(src) // #nosec G304 -- validated/cleaned earlier in UnpackLocalTarArchive
	if err != nil {
		return false
	}
	defer r.Close()
	fi, err := os.Lstat(src)
	if err != nil {
		return false
	}
	if fi.Size() == 0 {
		return false
	}
	tr := tar.NewReader(r)
	if tr == nil {
		return false
	}
	_, err = tr.Next()
	return err == nil
}

// UnpackCompressedTar unpacks the compressed tar at path to dir
func UnpackCompressedTar(path, dir string) error {
	// Validate the file path to prevent directory traversal
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") || strings.HasPrefix(cleanPath, "/") {
		return fmt.Errorf("invalid file path: potential directory traversal detected")
	}
	file, err := os.Open(cleanPath)
	if err != nil {
		return err
	}
	defer file.Close()
	gzr, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzr.Close()
	_, err = UnTar(gzr, dir)
	return err
}
